# anytls.zig

[![CI](https://github.com/lalinsky/anytls.zig/actions/workflows/ci.yml/badge.svg)](https://github.com/lalinsky/anytls.zig/actions/workflows/ci.yml)
[![Zig](https://img.shields.io/badge/zig-0.16.0-orange.svg)](https://ziglang.org/download/)

TLS client/server for Zig with a backend selected at build time:

- `openssl` — system libssl (OpenSSL 3), driven sans-I/O through a custom BIO
- `tls_zig` — pure Zig [ianic/tls.zig] (not yet ported to the current API)

All transport I/O goes through a caller-provided [`std.Io.Reader`]/[`std.Io.Writer`]
pair, so any `std.Io` implementation works, including green-thread schedulers
like [zio] where a task may resume on a different OS thread.

> Work in progress. Requires Zig 0.16.

[ianic/tls.zig]: https://github.com/ianic/tls.zig
[zio]: https://github.com/lalinsky/zio
[`std.Io.Reader`]: https://ziglang.org/documentation/0.16.0/std/#std.Io.Reader
[`std.Io.Writer`]: https://ziglang.org/documentation/0.16.0/std/#std.Io.Writer

## Installation

1) Add anytls as a dependency in your `build.zig.zon`:

```bash
zig fetch --save "git+https://github.com/lalinsky/anytls.zig"
```

2) In your `build.zig`, add the `anytls` module to your program:

```zig
const anytls = b.dependency("anytls", .{
    .target = target,
    .optimize = optimize,
    .backend = .openssl,
});
exe.root_module.addImport("anytls", anytls.module("anytls"));
```

The `openssl` backend links the system `libssl`/`libcrypto`, so the OpenSSL
headers need to be installed (`libssl-dev` on Debian/Ubuntu).

## Usage

A context holds the configuration: certificates, keys and the trust store. It
is created once, is immutable afterwards, may be shared by any number of
connections on any thread, and must outlive every connection created from it.

```zig
const anytls = @import("anytls");

var diag: anytls.ConfigDiagnostics = .{};
var ctx = anytls.ClientContext.init(gpa, io, .{
    .ca = .system, // or .{ .file = path }, .{ .dir = path }, .{ .pem = bytes }
    .alpn = &.{ "h2", "http/1.1" },
}, &diag) catch |err| {
    std.log.err("TLS config: {t}: {s}", .{ err, diag.message() });
    return err;
};
defer ctx.deinit();
```

A connection runs over an established transport. The transport buffers must
be at least `anytls.input_buffer_len`/`anytls.output_buffer_len` bytes. The
connection must not move after `initClient`/`initServer`:

```zig
var in_buf: [anytls.input_buffer_len]u8 = undefined;
var out_buf: [anytls.output_buffer_len]u8 = undefined;
var tcp_reader = tcp.reader(io, &in_buf);
var tcp_writer = tcp.writer(io, &out_buf);

var conn: anytls.Connection = undefined;
try conn.initClient(&ctx, io, &tcp_reader.interface, &tcp_writer.interface, .{
    .server_name = "example.com", // SNI and verification; an IP literal verifies the IP SAN
});
defer conn.deinit();
try conn.handshake();

var rbuf: [16 * 1024]u8 = undefined;
var wbuf: [16 * 1024]u8 = undefined;
var reader = conn.reader(&rbuf); // std.Io.Reader for cleartext
var writer = conn.writer(&wbuf); // std.Io.Writer for cleartext

try writer.interface.writeAll("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n");
try writer.interface.flush(); // encrypts and flushes the transport
const line = try reader.interface.takeDelimiterInclusive('\n');

try conn.close(); // close_notify; does not close the transport
```

A server is the same with a `ServerContext`:

```zig
var ctx = try anytls.ServerContext.init(gpa, io, .{
    .certificate = .{ .chain = .{ .file = "cert.pem" }, .key = .{ .file = "key.pem" } },
    .client_auth = .{ .ca = .{ .file = "clients.pem" }, .mode = .require }, // optional mTLS
}, &diag);

var conn: anytls.Connection = undefined;
try conn.initServer(&ctx, io, &tcp_reader.interface, &tcp_writer.interface);
```

### Concurrency

One task may use the reader while another uses the writer, after the
handshake. Two readers or two writers at once are not supported, and
`close()` belongs to the writer side.

## Error handling

TLS failures are a small error set, `anytls.TlsError`; the details are in
`conn.diagnostics()`:

| Error | Meaning | Details |
|---|---|---|
| `ConnectionTruncated` | transport ended inside a record, or during the handshake | |
| `AlertReceived` | the peer aborted | `alert_received` (e.g. `.certificate_required`) |
| `CertificateRejected` | we rejected the peer's certificate | `certificate.reason` (`.untrusted`, `.name_mismatch`, `.expired`, ...), `certificate.depth` |
| `Incompatible` | no common version, cipher, group or ALPN protocol | |
| `ProtocolViolation` | the peer broke the protocol | `not_tls` if it is not speaking TLS at all |
| `Internal` | failure on our side | |

`diagnostics().detail` has the backend's message for logs, and the
`Diagnostics` value formats as a one-line summary with `{f}`.

**Transport failures are never converted into TLS errors.** The reader
returns `error.ReadFailed` with `reader.err` holding the TLS cause, or null
when the transport reader failed, whose own `err` then has the cause
(`error.Canceled`, `error.ConnectionResetByPeer`, ...). The writer works the
same way with the transport writer. The reader never writes to the transport
and the writer never reads from it, so the cause is always on the matching
side:

```zig
const n = reader.interface.readSliceShort(&buf) catch |err| switch (err) {
    error.EndOfStream => return, // close_notify, or EOF at a record boundary
    error.ReadFailed => return reader.err orelse tcp_reader.err.?,
};
```

`handshake()` returns the `TlsError` directly, or `error.ReadFailed`/
`error.WriteFailed` for a transport failure:

```zig
conn.handshake() catch |err| switch (err) {
    error.ReadFailed => return tcp_reader.err.?, // e.g. Canceled by a timeout
    error.WriteFailed => return tcp_writer.err.?,
    else => {
        std.log.warn("TLS handshake failed: {t}: {f}", .{ err, conn.diagnostics().* });
        return err;
    },
};
```

End of stream follows Go's `crypto/tls`. A close_notify, or a transport EOF
at a record boundary, is `error.EndOfStream`; many servers close without
close_notify. A transport EOF inside a record is `ConnectionTruncated`.

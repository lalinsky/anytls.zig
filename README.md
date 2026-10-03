# anytls.zig

[![CI](https://github.com/lalinsky/anytls.zig/actions/workflows/ci.yml/badge.svg)](https://github.com/lalinsky/anytls.zig/actions/workflows/ci.yml)
[![Zig](https://img.shields.io/badge/zig-0.16.0-orange.svg)](https://ziglang.org/download/)

TLS client/server for Zig with a backend selected at build time:

- `openssl` — system libssl (OpenSSL 3), driven sans-I/O through a custom BIO
- `tls_zig` — pure Zig [ianic/tls.zig], with no system dependency but fewer
  features (see below)

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

### Backend differences

Both backends implement the same API. `anytls.features` describes what the
selected one supports, so code can adapt at compile time.

> **The `tls_zig` backend inherits two security bugs from tls.zig and Zig's
> std, so do not use it where certificate verification matters:**
>
> - **Certificate chains are verified without CA constraints.** std only
>   checks issuer names, signatures and validity dates, not that an issuer is
>   a CA, key usage, extended key usage, path length or name constraints. Any
>   certificate a trusted CA issued (an ordinary server certificate) can sign
>   a certificate for any other name, and it is accepted. This also affects
>   client certificates (mTLS).
> - **A post-handshake message split across records is delivered to the
>   reader as application data.** A peer that sends a large session ticket
>   in several records corrupts the cleartext stream.

The `tls_zig` backend is also weaker in these ways:

- its server speaks TLS 1.3 only, and supports only the x25519, P-256 and
  P-384 groups, without HelloRetryRequest;
- it cannot verify an IP address as `server_name` (`initClient` returns
  `error.Unsupported` unless verification is off);
- its client does not send an alert when its handshake fails, so the server
  only sees the connection end; its server answers an untrusted client
  certificate with `internal_error`;
- the alert for a failed read is sent only by `close()`;
- after the transport writer fails, reads fail too;
- a handshake that failed on a transport error cannot be retried;
- certificate problems carry no chain depth, and unknown alert codes are
  reported without the code;
- ALPN protocol names are limited to 32 bytes on the client;
- private keys must be PKCS#8 or SEC1 (`EC PRIVATE KEY`) PEM, not PKCS#1
  (`RSA PRIVATE KEY`), and a context checks only ECDSA keys against their
  certificate;
- CA certificates with the same subject are deduplicated, and SHA-1
  certificate signatures are accepted;
- every record is flushed to the transport as it is written;
- RSA handshakes are about 10× slower than with OpenSSL, and Debug builds are
  much slower still.

### Concurrency

One task may use the reader while another uses the writer, after the
handshake. Two readers or two writers at once are not supported, and
`close()` belongs to the writer side.

The two sides are not independent, because TLS isn't: a read may have to
send something (the reply to a peer's KeyUpdate request, or the alert
reporting a failure), and then waits for an in-progress write to finish
first. A write may need the rest of a post-handshake message from the peer
before libssl lets it continue, and then waits for an in-progress read, or
reads from the transport itself if there is none.

## Error handling

Every operation (`handshake`, `read`, `write`, `flush`, `close`) fails with
`anytls.StreamError`, which says *where* the failure is:

| Error | Where to look |
|---|---|
| `TransportReadFailed` | the transport **reader** failed; its own `err` has the cause (`error.Canceled`, `error.ConnectionResetByPeer`, ...) |
| `TransportWriteFailed` | the transport **writer** failed; its own `err` has the cause. Sticky: the connection can no longer send |
| any `TlsError` | a TLS failure; details in `conn.diagnostics()`. Sticky: every later operation returns it again |

Because of the coupling described above, **either transport error can come
out of any operation**: a read can fail with `TransportWriteFailed` (it was
sending a KeyUpdate reply), and a write can fail with `TransportReadFailed`.
Always look at the transport side the error names, not the side of the
operation that failed.

Through the `std.Io` interfaces, the reader returns `error.ReadFailed` and
the writer `error.WriteFailed`, and their `err` field holds the
`StreamError`. A clean end of stream is `error.EndOfStream` from the reader
and is never an error in `err`.

```zig
fn cause(err: anytls.StreamError, tcp_reader: *Io.net.Stream.Reader, tcp_writer: *Io.net.Stream.Writer) anyerror {
    return switch (err) {
        error.TransportReadFailed => tcp_reader.err.?,
        error.TransportWriteFailed => tcp_writer.err.?,
        else => err, // TLS failure; see conn.diagnostics()
    };
}

const line = reader.interface.takeDelimiterInclusive('\n') catch |err| switch (err) {
    error.EndOfStream => return, // close_notify, or EOF at a record boundary
    error.ReadFailed => return cause(reader.err.?, &tcp_reader, &tcp_writer),
    else => |e| return e,
};

conn.handshake() catch |err| {
    std.log.warn("TLS handshake failed: {t}: {f}", .{ err, conn.diagnostics().* });
    return cause(err, &tcp_reader, &tcp_writer);
};
```

The TLS failures are a small set; `conn.diagnostics()` has the details:

| `TlsError` | Meaning | Details |
|---|---|---|
| `ConnectionTruncated` | transport ended inside a record, or during the handshake | |
| `AlertReceived` | the peer aborted | `alert_received` (e.g. `.certificate_required`) |
| `CertificateRejected` | we rejected the peer's certificate | `certificate.reason` (`.untrusted`, `.name_mismatch`, `.expired`, ...), `certificate.depth` |
| `Incompatible` | no common version, cipher, group or ALPN protocol | |
| `ProtocolViolation` | the peer broke the protocol | `not_tls` if it is not speaking TLS at all |
| `Internal` | failure on our side | |

`diagnostics().detail` has the backend's message for logs, and the
`Diagnostics` value formats as a one-line summary with `{f}`.

End of stream follows Go's `crypto/tls`. A close_notify, or a transport EOF
at a record boundary, is `error.EndOfStream`; many servers close without
close_notify. A transport EOF inside a record is `ConnectionTruncated`.

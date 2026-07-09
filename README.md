# anytls.zig

[![CI](https://github.com/lalinsky/anytls.zig/actions/workflows/ci.yml/badge.svg)](https://github.com/lalinsky/anytls.zig/actions/workflows/ci.yml)
[![Zig](https://img.shields.io/badge/zig-0.16.0-orange.svg)](https://ziglang.org/download/)

TLS client/server for Zig with a backend selected at build time:

- `openssl` — system libssl (OpenSSL 3), driven sans-I/O over memory BIOs
- `tls_zig` — pure Zig [ianic/tls.zig]

Both backends sit behind the same API and do all transport I/O through a
caller-provided [`std.Io.Reader`]/[`std.Io.Writer`] pair, so any `std.Io`
implementation works, including green-thread schedulers like [zio] where a
task may resume on a different OS thread.

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
    .backend = .openssl, // or .tls_zig
});
exe.root_module.addImport("anytls", anytls.module("anytls"));
```

The `openssl` backend links the system `libssl`/`libcrypto`, so the OpenSSL
headers need to be installed (`libssl-dev` on Debian/Ubuntu).

## Usage

`anytls.client` upgrades an established connection to TLS. The transport
buffers must be at least `anytls.input_buffer_len`/`anytls.output_buffer_len`
bytes, enough for one full TLS record in each direction:

```zig
const anytls = @import("anytls");

var in_buf: [anytls.input_buffer_len]u8 = undefined;
var out_buf: [anytls.output_buffer_len]u8 = undefined;
var tcp_reader = tcp.reader(io, &in_buf);
var tcp_writer = tcp.writer(io, &out_buf);

var conn = try anytls.client(io, &tcp_reader.interface, &tcp_writer.interface, .{
    .host = "example.com",
    .allocator = allocator,
});
defer conn.deinit();

try conn.writeAll("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n");

var buf: [4096]u8 = undefined;
while (true) {
    const n = try conn.read(&buf);
    if (n == 0) break; // peer sent close_notify
    // use buf[0..n]
}
```

The server side is the same, with a certificate instead of a host name:

```zig
var conn = try anytls.server(io, &tcp_reader.interface, &tcp_writer.interface, .{
    .auth = .{ .cert_pem = cert_pem, .key_pem = key_pem },
    .allocator = allocator,
});
```

A connection can also be wrapped in `std.Io.Reader`/`std.Io.Writer`
interfaces:

```zig
var rd_buf: [4096]u8 = undefined;
var wr_buf: [4096]u8 = undefined;
var reader = conn.reader(&rd_buf);
var writer = conn.writer(&wr_buf);

try writer.interface.print("hello {d}\n", .{42});
try writer.interface.flush();
const line = try reader.interface.takeDelimiterInclusive('\n');
```

## Error handling

`read`/`writeAll`/`close` return only `error.ReadFailed`/`error.WriteFailed`.
The reason is available from `conn.failure()` (one of `anytls.Failure`:
`TlsFailure`, `TlsTruncated`, `TransportReadFailed`, `TransportWriteFailed`)
and `conn.errorMessage()` gives a best-effort detail string. When using the
reader/writer interfaces, the same value is stored in `reader.err`/`writer.err`.

A transport that ends without close_notify is reported as `error.ReadFailed`
with `failure() == error.TlsTruncated`, not as a clean end of stream.

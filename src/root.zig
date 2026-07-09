//! anytls — TLS client/server over any `std.Io` transport.
//!
//! The TLS implementation is selected at build time (`-Dbackend`):
//! * `openssl` — system libssl (OpenSSL 3), driven sans-I/O over memory BIOs.
//! * `tls_zig` — pure Zig ianic/tls.zig.
//!
//! Both backends do all transport I/O through the caller-provided
//! `*Io.Reader`/`*Io.Writer`, so any `Io` implementation works, including
//! green-thread schedulers without OS-thread affinity.
const std = @import("std");
const Io = std.Io;
const common = @import("common.zig");
const build_options = @import("build_options");

pub const backend = build_options.backend;
pub const Backend = @TypeOf(backend);

const impl = switch (backend) {
    .openssl => @import("openssl.zig"),
    .tls_zig => @import("tlszig.zig"),
};

pub const config = common.config;
pub const Failure = common.Failure;
pub const InitError = common.InitError;
pub const HandshakeError = common.HandshakeError;
pub const ClientError = InitError || HandshakeError;
pub const ServerError = InitError || HandshakeError;

/// Required transport buffer sizes, identical on both backends: the reader
/// buffer must hold one full TLS ciphertext record, the writer buffer one
/// full encrypted record.
pub const input_buffer_len = 16645;
pub const output_buffer_len = 16469;

/// Upgrades a transport reader/writer pair to a TLS connection by performing
/// the client side of the handshake.
///
/// `io` supplies randomness and wall-clock time where the backend needs them
/// (tls_zig); the openssl backend uses its own RNG and clock and ignores it.
pub fn client(io: Io, input: *Io.Reader, output: *Io.Writer, opt: config.Client) ClientError!Connection {
    std.debug.assert(input.buffer.len >= input_buffer_len);
    std.debug.assert(output.buffer.len >= output_buffer_len);
    try common.validate(opt.host, opt.alpn_protocols);
    return .{ .impl = try impl.client(io, input, output, opt) };
}

/// Upgrades a transport reader/writer pair to a TLS connection by performing
/// the server side of the handshake.
///
/// Note: the tls_zig backend serves TLS 1.3 only; openssl serves 1.2 and 1.3.
pub fn server(io: Io, input: *Io.Reader, output: *Io.Writer, opt: config.Server) ServerError!Connection {
    std.debug.assert(input.buffer.len >= input_buffer_len);
    std.debug.assert(output.buffer.len >= output_buffer_len);
    try common.validate("", opt.alpn_protocols);
    return .{ .impl = try impl.server(io, input, output, opt) };
}

/// An established TLS connection. One connection must be driven by one task
/// at a time; concurrent read and write from different tasks is not
/// supported by either backend.
pub const Connection = struct {
    /// Backend connection; its type depends on `backend`. Backend-specific
    /// functionality is available here behind `comptime` checks.
    impl: impl.Connection,

    /// Reads decrypted data into `buffer`. Returns the number of bytes read;
    /// 0 means the peer closed the connection cleanly (close_notify
    /// received). A transport end of stream without close_notify is
    /// reported as `error.ReadFailed` with `failure() == error.TlsTruncated`.
    pub fn read(conn: *Connection, buffer: []u8) error{ReadFailed}!usize {
        return conn.impl.read(buffer);
    }

    /// Encrypts and sends `bytes`, flushing the transport.
    pub fn writeAll(conn: *Connection, bytes: []const u8) error{WriteFailed}!void {
        return conn.impl.writeAll(bytes);
    }

    /// Best-effort: sends close_notify and flushes the transport. Does not
    /// wait for the peer's close_notify; whether one is sent after the peer
    /// already closed is backend-dependent. After `close` the connection may
    /// only be deinitialized. Does not close the underlying transport.
    pub fn close(conn: *Connection) error{WriteFailed}!void {
        return conn.impl.close();
    }

    /// Frees backend resources. Does not close the underlying transport.
    pub fn deinit(conn: *Connection) void {
        conn.impl.deinit();
        conn.* = undefined;
    }

    /// ALPN protocol negotiated during the handshake, null if none.
    /// Valid until `deinit`.
    pub fn alpnProtocol(conn: *const Connection) ?[]const u8 {
        return conn.impl.alpn_protocol;
    }

    /// Why the most recent read/write/close failed; null if none has.
    pub fn failure(conn: *const Connection) ?Failure {
        return conn.impl.err;
    }

    /// Best-effort human-readable detail for the most recent failure:
    /// the OpenSSL error string, or the underlying tls.zig error name.
    pub fn errorMessage(conn: *const Connection) []const u8 {
        return conn.impl.errorMessage();
    }

    pub fn reader(conn: *Connection, buffer: []u8) Reader {
        return .init(conn, buffer);
    }

    pub fn writer(conn: *Connection, buffer: []u8) Writer {
        return .init(conn, buffer);
    }

    // The adapters sit directly on Connection.read/writeAll — never on a
    // backend adapter — so there is exactly one cleartext-side Io.Reader/
    // Io.Writer in the stack regardless of backend.

    pub const Reader = struct {
        conn: *Connection,
        interface: Io.Reader,
        /// Set when the interface returns error.ReadFailed; details in
        /// `conn.errorMessage()`.
        err: ?Failure = null,

        pub fn init(conn: *Connection, buffer: []u8) Reader {
            return .{
                .conn = conn,
                .interface = .{
                    .vtable = &.{ .stream = Reader.stream },
                    .buffer = buffer,
                    .seek = 0,
                    .end = 0,
                },
            };
        }

        fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
            const r: *Reader = @alignCast(@fieldParentPtr("interface", io_r));
            const dest = limit.slice(try w.writableSliceGreedy(1));
            const n = r.conn.read(dest) catch |err| {
                r.err = r.conn.failure() orelse error.TlsFailure;
                return err;
            };
            if (n == 0) return error.EndOfStream;
            w.advance(n);
            return n;
        }
    };

    pub const Writer = struct {
        conn: *Connection,
        interface: Io.Writer,
        /// Set when the interface returns error.WriteFailed; details in
        /// `conn.errorMessage()`.
        err: ?Failure = null,

        pub fn init(conn: *Connection, buffer: []u8) Writer {
            return .{
                .conn = conn,
                .interface = .{
                    .vtable = &.{ .drain = Writer.drain },
                    .buffer = buffer,
                },
            };
        }

        fn drain(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
            const w: *Writer = @alignCast(@fieldParentPtr("interface", io_w));
            var total: usize = 0;
            const buffered = io_w.buffered();
            if (buffered.len != 0) {
                try w.writeAll(buffered);
                total += buffered.len;
            }
            for (data[0 .. data.len - 1]) |slice| {
                if (slice.len == 0) continue;
                try w.writeAll(slice);
                total += slice.len;
            }
            const pattern = data[data.len - 1];
            if (pattern.len != 0) for (0..splat) |_| {
                try w.writeAll(pattern);
                total += pattern.len;
            };
            return io_w.consume(total);
        }

        fn writeAll(w: *Writer, bytes: []const u8) Io.Writer.Error!void {
            w.conn.writeAll(bytes) catch |err| {
                w.err = w.conn.failure() orelse error.TlsFailure;
                return err;
            };
        }
    };
};

test {
    _ = @import("test.zig");
}

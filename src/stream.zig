//! `std.Io.Reader`/`std.Io.Writer` adapters over a backend connection.
//!
//! A backend connection provides:
//! * `read(conn, dest) error{ ReadFailed, EndOfStream }!usize` — decrypts at
//!   least one byte into `dest` (which is non-empty), or fails;
//! * `write(conn, bytes) error{WriteFailed}!void` — encrypts all of `bytes`
//!   into the transport writer without flushing it;
//! * `flush(conn) error{WriteFailed}!void` — sends anything queued and
//!   flushes the transport writer;
//! * `failure(conn) ?TlsError` — the TLS-layer cause of the last failure,
//!   null if it was the transport.
const std = @import("std");
const Io = std.Io;
const api = @import("api.zig");

pub fn Reader(comptime Connection: type) type {
    return struct {
        conn: *Connection,
        interface: Io.Reader,
        /// TLS-layer cause after the interface returned `error.ReadFailed`.
        /// Null means the transport reader failed; its own `err` has the
        /// cause.
        err: ?api.TlsError = null,

        const Self = @This();

        pub fn init(conn: *Connection, buffer: []u8) Self {
            return .{
                .conn = conn,
                .interface = .{
                    .vtable = &.{ .stream = stream },
                    .buffer = buffer,
                    .seek = 0,
                    .end = 0,
                },
            };
        }

        fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
            const r: *Self = @alignCast(@fieldParentPtr("interface", io_r));
            const dest = limit.slice(try w.writableSliceGreedy(1));
            if (dest.len == 0) return 0;
            const n = r.conn.read(dest) catch |err| switch (err) {
                error.EndOfStream => return error.EndOfStream,
                error.ReadFailed => {
                    r.err = r.conn.failure();
                    return error.ReadFailed;
                },
            };
            w.advance(n);
            return n;
        }
    };
}

pub fn Writer(comptime Connection: type) type {
    return struct {
        conn: *Connection,
        interface: Io.Writer,
        /// TLS-layer cause after the interface returned `error.WriteFailed`.
        /// Null means the transport writer failed; its own `err` has the
        /// cause.
        err: ?api.TlsError = null,

        const Self = @This();

        pub fn init(conn: *Connection, buffer: []u8) Self {
            return .{
                .conn = conn,
                .interface = .{
                    .vtable = &.{ .drain = drain, .flush = flush },
                    .buffer = buffer,
                },
            };
        }

        fn drain(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
            const w: *Self = @alignCast(@fieldParentPtr("interface", io_w));
            try w.write(io_w.buffered());
            io_w.end = 0;
            var total: usize = 0;
            for (data[0 .. data.len - 1]) |bytes| {
                try w.write(bytes);
                total += bytes.len;
            }
            const pattern = data[data.len - 1];
            for (0..splat) |_| {
                try w.write(pattern);
                total += pattern.len;
            }
            return total;
        }

        fn flush(io_w: *Io.Writer) Io.Writer.Error!void {
            const w: *Self = @alignCast(@fieldParentPtr("interface", io_w));
            try w.write(io_w.buffered());
            io_w.end = 0;
            w.conn.flush() catch |err| {
                w.err = w.conn.failure();
                return err;
            };
        }

        fn write(w: *Self, bytes: []const u8) Io.Writer.Error!void {
            if (bytes.len == 0) return;
            w.conn.write(bytes) catch |err| {
                w.err = w.conn.failure();
                return err;
            };
        }
    };
}

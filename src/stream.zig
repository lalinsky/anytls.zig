//! `std.Io.Reader`/`std.Io.Writer` adapters over a backend connection.
//!
//! A backend connection provides:
//! * `read(conn, dest) (StreamError || error{EndOfStream})!usize` —
//!   decrypts at least one byte into `dest` (which is non-empty);
//! * `write(conn, bytes) StreamError!void` — encrypts all of `bytes` into
//!   the transport writer without necessarily flushing it;
//! * `flush(conn) StreamError!void` — sends anything queued and flushes the
//!   transport writer.
const std = @import("std");
const Io = std.Io;
const api = @import("api.zig");

pub fn Reader(comptime Connection: type) type {
    return struct {
        conn: *Connection,
        interface: Io.Reader,
        /// Why the interface returned `error.ReadFailed`; see
        /// `StreamError`. `TransportReadFailed`/`TransportWriteFailed` mean
        /// the cause is in the transport reader's/writer's own `err`.
        err: ?api.StreamError = null,

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
                else => |e| {
                    r.err = e;
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
        /// Why the interface returned `error.WriteFailed`; see
        /// `StreamError`. `TransportReadFailed`/`TransportWriteFailed` mean
        /// the cause is in the transport reader's/writer's own `err`.
        err: ?api.StreamError = null,

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
            try w.writeSplat(pattern, splat);
            return total + pattern.len * splat;
        }

        fn flush(io_w: *Io.Writer) Io.Writer.Error!void {
            const w: *Self = @alignCast(@fieldParentPtr("interface", io_w));
            try w.write(io_w.buffered());
            io_w.end = 0;
            w.conn.flush() catch |err| {
                w.err = err;
                return error.WriteFailed;
            };
        }

        /// Repeats a short pattern into blocks, so a splat (e.g. padding)
        /// becomes a few records instead of one record per repetition.
        fn writeSplat(w: *Self, pattern: []const u8, splat: usize) Io.Writer.Error!void {
            if (pattern.len == 0 or splat == 0) return;
            var block: [4096]u8 = undefined;
            if (splat == 1 or pattern.len > block.len / 2) {
                for (0..splat) |_| try w.write(pattern);
                return;
            }
            const per_block = block.len / pattern.len;
            for (0..per_block) |i| @memcpy(block[i * pattern.len ..][0..pattern.len], pattern);
            var left = splat;
            while (left > 0) {
                const k = @min(per_block, left);
                try w.write(block[0 .. k * pattern.len]);
                left -= k;
            }
        }

        fn write(w: *Self, bytes: []const u8) Io.Writer.Error!void {
            if (bytes.len == 0) return;
            w.conn.write(bytes) catch |err| {
                w.err = err;
                return error.WriteFailed;
            };
        }
    };
}

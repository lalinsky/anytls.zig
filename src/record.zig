//! Tracks TLS record boundaries in the ciphertext a backend consumes, so a
//! transport EOF can be classified the way Go's crypto/tls does: at a record
//! boundary it is a normal end of stream, inside a record it is truncation.
const std = @import("std");

pub const Tracker = struct {
    header: [header_len]u8 = undefined,
    header_got: u8 = 0,
    body_left: u16 = 0,
    /// Set once the first record header has been seen.
    started: bool = false,
    /// The first byte received was not a TLS record content type.
    not_tls: bool = false,

    const header_len = 5;

    /// Accounts for `bytes` handed to the backend, in stream order.
    pub fn feed(t: *Tracker, bytes: []const u8) void {
        var rest = bytes;
        while (rest.len > 0) {
            if (t.body_left > 0) {
                const n: u16 = @intCast(@min(rest.len, t.body_left));
                t.body_left -= n;
                rest = rest[n..];
                continue;
            }
            if (!t.started) {
                t.started = true;
                t.not_tls = !isContentType(rest[0]);
            }
            const n = @min(rest.len, header_len - t.header_got);
            @memcpy(t.header[t.header_got..][0..n], rest[0..n]);
            t.header_got += @intCast(n);
            rest = rest[n..];
            if (t.header_got == header_len) {
                t.header_got = 0;
                t.body_left = std.mem.readInt(u16, t.header[3..5], .big);
            }
        }
    }

    /// True if everything fed so far ends exactly at a record boundary.
    pub fn atBoundary(t: *const Tracker) bool {
        return t.header_got == 0 and t.body_left == 0;
    }

    fn isContentType(b: u8) bool {
        // change_cipher_spec, alert, handshake, application_data
        return b >= 20 and b <= 23;
    }
};

test "boundaries across arbitrary splits" {
    // Two records: 3-byte body and 0-byte body.
    const stream = [_]u8{ 23, 3, 3, 0, 3, 'a', 'b', 'c', 21, 3, 3, 0, 0 };
    for (0..stream.len + 1) |split| {
        var t: Tracker = .{};
        t.feed(stream[0..split]);
        const boundary = split == 0 or split == 8 or split == stream.len;
        try std.testing.expectEqual(boundary, t.atBoundary());
        t.feed(stream[split..]);
        try std.testing.expect(t.atBoundary());
        try std.testing.expect(!t.not_tls);
    }
}

test "plaintext is not TLS" {
    var t: Tracker = .{};
    t.feed("GET / HTTP/1.1\r\n");
    try std.testing.expect(t.not_tls);
}

const std = @import("std");
const Io = std.Io;
const tls = @import("tls");
const common = @import("common.zig");

pub const Error = common.InitError || common.HandshakeError;

pub fn client(io: Io, input: *Io.Reader, output: *Io.Writer, opt: common.config.Client) Error!Connection {
    const gpa = opt.allocator;
    var rng_source: std.Random.IoSource = .{ .io = io };

    var root_ca: tls.config.cert.Bundle = .empty;
    defer root_ca.deinit(gpa);
    switch (opt.root_ca) {
        .system => root_ca = tls.config.cert.fromSystem(gpa, io) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.TlsInitFailure,
        },
        .pem => |pem| root_ca = tls.config.cert.fromSlice(gpa, io, pem) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidCertificate,
        },
        .none => {},
    }

    var auth: ?tls.config.CertKeyPair = null;
    defer if (auth) |*kp| kp.deinit(gpa);
    if (opt.auth) |kp_pem| auth = try certKeyPairFromPem(gpa, io, kp_pem);

    const conn = tls.client(input, output, .{
        .host = opt.host,
        .root_ca = root_ca,
        .insecure_skip_verify = opt.insecure_skip_verify,
        .alpn_protocols = opt.alpn_protocols,
        .auth = if (auth) |*kp| kp else null,
        .rng = rng_source.interface(),
        .now = Io.Clock.real.now(io),
    }) catch |err| return mapHandshakeError(err);
    return .{ .impl = conn };
}

pub fn server(io: Io, input: *Io.Reader, output: *Io.Writer, opt: common.config.Server) Error!Connection {
    const gpa = opt.allocator;
    var rng_source: std.Random.IoSource = .{ .io = io };

    var auth = try certKeyPairFromPem(gpa, io, opt.auth);
    defer auth.deinit(gpa);

    var client_root_ca: tls.config.cert.Bundle = .empty;
    defer client_root_ca.deinit(gpa);
    if (opt.client_auth) |ca| switch (ca.root_ca) {
        .system => client_root_ca = tls.config.cert.fromSystem(gpa, io) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.TlsInitFailure,
        },
        .pem => |pem| client_root_ca = tls.config.cert.fromSlice(gpa, io, pem) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidCertificate,
        },
        .none => {},
    };

    const conn = tls.server(input, output, .{
        .auth = &auth,
        .client_auth = if (opt.client_auth) |ca| .{
            .root_ca = client_root_ca,
            .auth_type = switch (ca.auth_type) {
                .request => .request,
                .require => .require,
            },
        } else null,
        .alpn_protocols = opt.alpn_protocols,
        .rng = rng_source.interface(),
        .now = Io.Clock.real.now(io),
    }) catch |err| return mapHandshakeError(err);
    return .{ .impl = conn };
}

pub const Connection = struct {
    impl: tls.Connection,

    /// The most recent failure: tls.zig's own error, passed through verbatim.
    err: ?anyerror = null,

    pub fn errorMessage(conn: *const Connection) []const u8 {
        return if (conn.err) |e| @errorName(e) else "";
    }

    /// tls.zig holds no resources outside the caller-provided buffers.
    pub fn deinit(conn: *Connection) void {
        conn.* = undefined;
    }

    /// Reads decrypted data into `buffer`. Returns the number of bytes read;
    /// 0 means no application data was available this call, not end of
    /// stream. A clean shutdown (close_notify) is reported as
    /// `error.EndOfStream`; a transport end of stream without close_notify is
    /// reported as `error.ReadFailed` with `err == error.TlsConnectionTruncated`.
    pub fn read(conn: *Connection, buffer: []u8) error{ ReadFailed, EndOfStream }!usize {
        if (buffer.len == 0) return 0;
        const n = conn.impl.read(buffer) catch |err| {
            conn.recordTlsErr(err);
            return error.ReadFailed;
        };
        if (n == 0) {
            // eof() distinguishes a received close_notify from a transport
            // EOF without one (truncation).
            if (conn.impl.eof()) return error.EndOfStream;
            conn.err = error.TlsConnectionTruncated;
            return error.ReadFailed;
        }
        return n;
    }

    /// Encrypts and sends `bytes`; tls.zig flushes the transport per record.
    pub fn writeAll(conn: *Connection, bytes: []const u8) error{WriteFailed}!void {
        conn.impl.writeAll(bytes) catch |err| {
            conn.recordTlsErr(err);
            return error.WriteFailed;
        };
    }

    /// Sends close_notify. Does not wait for the peer's close_notify.
    /// Does not close the underlying transport.
    pub fn close(conn: *Connection) error{WriteFailed}!void {
        conn.impl.close() catch |err| {
            conn.recordTlsErr(err);
            return error.WriteFailed;
        };
    }

    pub fn alpnProtocol(conn: *const Connection) ?[]const u8 {
        return conn.impl.alpn_protocol;
    }

    /// Transport failures are recorded on the caller's reader/writer, so store
    /// only genuine TLS-layer errors here (see root.zig `failure()`).
    fn recordTlsErr(conn: *Connection, err: anyerror) void {
        if (err != error.ReadFailed and err != error.WriteFailed) conn.err = err;
    }
};

fn certKeyPairFromPem(
    gpa: std.mem.Allocator,
    io: Io,
    kp: common.config.CertKeyPair,
) common.InitError!tls.config.CertKeyPair {
    return tls.config.CertKeyPair.fromSlice(gpa, io, kp.cert_pem, kp.key_pem) catch |err| {
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            inline else => |e| {
                if (comptime std.mem.startsWith(u8, @errorName(e), "Certificate"))
                    return error.InvalidCertificate;
                return error.InvalidPrivateKey;
            },
        }
    };
}

fn mapHandshakeError(err: anytype) common.HandshakeError {
    switch (err) {
        error.ReadFailed => return error.ReadFailed,
        error.WriteFailed => return error.WriteFailed,
        error.EndOfStream => return error.TlsHandshakeFailure,
        inline else => |e| {
            if (comptime std.mem.startsWith(u8, @errorName(e), "Certificate"))
                return error.CertificateVerificationFailure;
            return error.TlsHandshakeFailure;
        }
    }
}

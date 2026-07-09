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
    return .{ .impl = conn, .alpn_protocol = conn.alpn_protocol };
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
    return .{ .impl = conn, .alpn_protocol = conn.alpn_protocol };
}

pub const Connection = struct {
    impl: tls.Connection,

    /// Negotiated ALPN protocol. Always null for client connections: see
    /// the note in `client` about the upstream slice lifetime bug.
    alpn_protocol: ?[]const u8 = null,

    /// The most recent failure; underlying error name in `errorMessage`.
    err: ?common.Failure = null,
    err_name: []const u8 = "",

    pub fn errorMessage(conn: *const Connection) []const u8 {
        return conn.err_name;
    }

    /// tls.zig holds no resources outside the caller-provided buffers.
    pub fn deinit(conn: *Connection) void {
        conn.* = undefined;
    }

    /// Reads decrypted data into `buffer`. Returns the number of bytes read;
    /// 0 means the peer closed the connection cleanly (close_notify
    /// received). A transport end of stream without close_notify is reported
    /// as `error.ReadFailed` with `err == error.TlsTruncated`.
    pub fn read(conn: *Connection, buffer: []u8) error{ReadFailed}!usize {
        if (buffer.len == 0) return 0;
        const n = conn.impl.read(buffer) catch |err| {
            conn.setErr(err);
            return error.ReadFailed;
        };
        // tls.zig reports transport EOF as a clean end of stream; only a
        // received close_notify counts as one for us.
        if (n == 0 and !conn.impl.eof()) {
            conn.err = error.TlsTruncated;
            conn.err_name = "EndOfStream";
            return error.ReadFailed;
        }
        return n;
    }

    /// Encrypts and sends `bytes`; tls.zig flushes the transport per record.
    pub fn writeAll(conn: *Connection, bytes: []const u8) error{WriteFailed}!void {
        conn.impl.writeAll(bytes) catch |err| {
            conn.setErr(err);
            return error.WriteFailed;
        };
    }

    /// Sends close_notify. Does not wait for the peer's close_notify.
    /// Does not close the underlying transport.
    pub fn close(conn: *Connection) error{WriteFailed}!void {
        conn.impl.close() catch |err| {
            conn.setErr(err);
            return error.WriteFailed;
        };
    }

    fn setErr(conn: *Connection, err: anytype) void {
        // == instead of switch: switch prongs must be members of the call
        // site's inferred error set, which varies across tls.zig versions.
        conn.err = if (err == error.ReadFailed)
            error.TransportReadFailed
        else if (err == error.WriteFailed)
            error.TransportWriteFailed
        else
            error.TlsFailure;
        conn.err_name = @errorName(err);
    }
};

fn certKeyPairFromPem(
    gpa: std.mem.Allocator,
    io: Io,
    kp: common.config.CertKeyPair,
) common.InitError!tls.config.CertKeyPair {
    return tls.config.CertKeyPair.fromSlice(gpa, io, kp.cert_pem, kp.key_pem) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        // Key parse errors surface from PrivateKey.parsePem before the
        // certificate bundle is touched; anything else is the bundle.
        const name = @errorName(err);
        if (std.mem.indexOf(u8, name, "Certificate") != null) return error.InvalidCertificate;
        return error.InvalidPrivateKey;
    };
}

fn mapHandshakeError(err: anytype) common.HandshakeError {
    switch (err) {
        error.ReadFailed => return error.ReadFailed,
        error.WriteFailed => return error.WriteFailed,
        error.EndOfStream => return error.TlsHandshakeFailure,
        else => {},
    }
    // Chain and host name verification errors come from std.crypto and all
    // start with "Certificate".
    if (std.mem.startsWith(u8, @errorName(err), "Certificate"))
        return error.CertificateVerificationFailure;
    return error.TlsHandshakeFailure;
}

//! One TLS connection driven by tls.zig's blocking `Connection` over the
//! caller's transport.
//!
//! Compared with the OpenSSL backend this one is weaker: the server speaks
//! TLS 1.3 only, IP addresses cannot be verified, handshake alerts are not
//! sent by the client, certificate problems carry no chain depth, unknown
//! alert codes are lost, fragmented post-handshake messages are rejected,
//! and every record is flushed to the transport as it is written.
//!
//! Must not move after `initClient`/`initServer`: the random number source
//! tls.zig keeps a pointer to lives here.
const Connection = @This();

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;
const tls = @import("tls");
const api = @import("../api.zig");
const source = @import("../source.zig");
const stream = @import("../stream.zig");
const context = @import("context.zig");

const TlsError = api.TlsError;
const StreamError = api.StreamError;
/// tls.zig's alert type; reachable only through a field type.
const TlsAlert = @typeInfo(@FieldType(tls.Connection, "pending_alert")).optional.child;

side: union(enum) {
    client: *context.ClientContext,
    server: *context.ServerContext,
},
io: Io,
input: *Io.Reader,
output: *Io.Writer,
rng: std.Random.IoSource,
server_name_buf: [api.max_server_name_len]u8 = undefined,
server_name_len: usize = 0,
inner: tls.Connection = undefined,

/// Guards `failed` and `diag`, which both directions update.
mutex: Io.Mutex = .init,
handshake_done: bool = false,
close_sent: bool = false,
/// Sticky TLS-layer failure.
failed: ?TlsError = null,
/// The transport writer failed; nothing more can be sent. Set by the writer,
/// read atomically by the reader.
write_failed: bool = false,
diag: api.Diagnostics = .{},

/// Minimum transport buffer sizes, as for the OpenSSL backend.
pub const input_buffer_len = tls.input_buffer_len;
pub const output_buffer_len = tls.output_buffer_len;

pub const Reader = stream.Reader(Connection);
pub const Writer = stream.Writer(Connection);

pub fn initClient(
    conn: *Connection,
    ctx: *context.ClientContext,
    io: Io,
    input: *Io.Reader,
    output: *Io.Writer,
    opt: api.ClientConnectionOptions,
) api.ConnectionInitError!void {
    const name = opt.server_name;
    if (name.len == 0 and ctx.verify) return error.MissingServerName;
    if (name.len > api.max_server_name_len or std.mem.indexOfScalar(u8, name, 0) != null)
        return error.InvalidServerName;
    // std's certificate name check only matches DNS names.
    const is_ip = if (Io.net.IpAddress.parse(name, 0)) |_| true else |_| false;
    if (is_ip and ctx.verify) return error.Unsupported;

    conn.init(.{ .client = ctx }, io, input, output);
    // IP literals are not sent as SNI (RFC 6066 section 3).
    if (!is_ip) {
        @memcpy(conn.server_name_buf[0..name.len], name);
        conn.server_name_len = name.len;
    }
    ctx.live.inc();
}

pub fn initServer(
    conn: *Connection,
    ctx: *context.ServerContext,
    io: Io,
    input: *Io.Reader,
    output: *Io.Writer,
) api.ConnectionInitError!void {
    conn.init(.{ .server = ctx }, io, input, output);
    ctx.live.inc();
}

fn init(conn: *Connection, side: @FieldType(Connection, "side"), io: Io, input: *Io.Reader, output: *Io.Writer) void {
    assert(input.buffer.len >= input_buffer_len);
    assert(output.buffer.len >= output_buffer_len);
    conn.* = .{
        .side = side,
        .io = io,
        .input = input,
        .output = output,
        .rng = .{ .io = io },
    };
}

/// Does not close the transport.
pub fn deinit(conn: *Connection) void {
    switch (conn.side) {
        inline else => |ctx| ctx.live.dec(),
    }
    conn.* = undefined;
}

pub fn handshake(conn: *Connection) StreamError!void {
    assert(!conn.handshake_done);
    if (conn.failed) |err| return err;
    const now = Io.Clock.real.now(conn.io);
    conn.inner = switch (conn.side) {
        .client => |ctx| tls.client(conn.input, conn.output, .{
            .rng = conn.rng.interface(),
            .now = now,
            .host = conn.server_name_buf[0..conn.server_name_len],
            .root_ca = ctx.root_ca,
            .insecure_skip_verify = !ctx.verify,
            .alpn_protocols = ctx.alpn.names,
            .auth = if (ctx.auth) |*kp| kp else null,
        }) catch |err| return conn.handshakeFailed(err),
        .server => |ctx| blk: {
            // tls.zig reads records before it can tell; look at the first
            // byte ourselves to recognize a peer that is not speaking TLS.
            const first = conn.input.peek(1) catch |err| switch (err) {
                error.EndOfStream => return conn.setFailed(error.ConnectionTruncated, "connection closed during handshake"),
                error.ReadFailed => return error.TransportReadFailed,
            };
            if (first[0] < 20 or first[0] > 23) {
                conn.diag.not_tls = true;
                return conn.setFailed(error.ProtocolViolation, "peer is not speaking TLS");
            }
            break :blk tls.server(conn.input, conn.output, .{
                .rng = conn.rng.interface(),
                .now = now,
                .auth = &ctx.auth,
                .client_auth = if (ctx.client_auth) |ca| .{
                    .root_ca = ca.root_ca,
                    .auth_type = switch (ca.mode) {
                        .request => .request,
                        .require => .require,
                    },
                } else null,
                .alpn_protocols = ctx.alpn.names,
            }) catch |err| return conn.handshakeFailed(err);
        },
    };
    conn.handshake_done = true;
}

fn handshakeFailed(conn: *Connection, err: anyerror) StreamError {
    // Only the server sends an alert when its handshake fails.
    if (conn.side == .server) conn.diag.alert_sent = alertOf(TlsAlert.forLocalError(err));
    if (err == error.EndOfStream) return conn.setFailed(error.ConnectionTruncated, "connection closed during handshake");
    return conn.mapError(err);
}

/// Decrypts into `dest` (non-empty). Returns at least one byte, or
/// `error.EndOfStream` after close_notify or a transport EOF at a record
/// boundary.
pub fn read(conn: *Connection, dest: []u8) (StreamError || error{EndOfStream})!usize {
    assert(conn.handshake_done);
    assert(dest.len > 0);
    while (true) {
        const n = conn.inner.read(dest) catch |err| {
            if (conn.inner.pending_alert) |alert| conn.recordAlertSent(alertOf(alert));
            return conn.mapError(err);
        };
        if (n > 0) return n;
        // Zero is also an empty application data record.
        if (conn.inner.eof()) return error.EndOfStream;
    }
}

/// Encrypts all of `bytes`; tls.zig flushes the transport after every
/// record.
pub fn write(conn: *Connection, bytes: []const u8) StreamError!void {
    assert(conn.handshake_done);
    assert(!conn.close_sent); // writing after close() is a usage error
    if (conn.write_failed) return error.TransportWriteFailed;
    conn.inner.writeAll(bytes) catch |err| return conn.mapError(err);
}

pub fn flush(conn: *Connection) StreamError!void {
    if (conn.write_failed) return error.TransportWriteFailed;
    conn.output.flush() catch return conn.mapError(error.WriteFailed);
}

/// Sends close_notify, or the alert for a failed read, and flushes the
/// transport. Idempotent. Belongs to the writer side.
pub fn close(conn: *Connection) StreamError!void {
    if (conn.write_failed) return error.TransportWriteFailed;
    if (conn.handshake_done and !conn.close_sent) {
        conn.close_sent = true;
        conn.inner.close() catch |err| return conn.mapError(err);
    }
    try conn.flush();
}

pub fn failure(conn: *const Connection) ?TlsError {
    return conn.failed;
}

pub fn diagnostics(conn: *const Connection) *const api.Diagnostics {
    return &conn.diag;
}

pub fn reader(conn: *Connection, buffer: []u8) Reader {
    return .init(conn, buffer);
}

pub fn writer(conn: *Connection, buffer: []u8) Writer {
    return .init(conn, buffer);
}

pub fn alpnProtocol(conn: *const Connection) ?[]const u8 {
    return conn.inner.alpn_protocol;
}

pub const ProtocolVersion = enum { tls_1_2, tls_1_3 };

pub fn protocolVersion(conn: *const Connection) ProtocolVersion {
    // TLS 1.3 suites are 0x13xx.
    return if (@intFromEnum(std.meta.activeTag(conn.inner.cipher)) >> 8 == 0x13) .tls_1_3 else .tls_1_2;
}

/// IANA name of the negotiated cipher suite, e.g. "TLS_AES_128_GCM_SHA256".
pub fn cipherSuite(conn: *const Connection) []const u8 {
    const suite = std.meta.activeTag(conn.inner.cipher);
    inline for (@typeInfo(@TypeOf(suite)).@"enum".fields) |field| {
        if (@intFromEnum(suite) == field.value) return "TLS_" ++ field.name;
    }
    return "";
}

// Errors

fn setFailed(conn: *Connection, err: TlsError, detail: []const u8) TlsError {
    conn.mutex.lockUncancelable(conn.io);
    defer conn.mutex.unlock(conn.io);
    if (conn.failed) |first| return first;
    conn.failed = err;
    conn.diag.detail = detail;
    return err;
}

fn recordAlertSent(conn: *Connection, alert: ?api.Alert) void {
    conn.mutex.lockUncancelable(conn.io);
    defer conn.mutex.unlock(conn.io);
    if (conn.diag.alert_sent == null) conn.diag.alert_sent = alert;
}

/// Maps a tls.zig or std error onto `StreamError`, recording TLS failures
/// as sticky.
fn mapError(conn: *Connection, err: anyerror) StreamError {
    switch (err) {
        error.ReadFailed => return error.TransportReadFailed,
        error.WriteFailed => {
            @atomicStore(bool, &conn.write_failed, true, .release);
            return error.TransportWriteFailed;
        },
        // tls.zig fails the whole connection when either direction fails.
        // If that was the transport writer, say so instead of blaming TLS.
        error.TlsConnectionFailed => if (@atomicLoad(bool, &conn.write_failed, .acquire)) {
            if (conn.failed == null) return error.TransportWriteFailed;
        },
        else => {},
    }

    conn.mutex.lockUncancelable(conn.io);
    defer conn.mutex.unlock(conn.io);
    // The other direction failed first; report its cause.
    if (conn.failed) |first| return first;

    conn.diag.detail = @errorName(err);
    const tls_err: TlsError = blk: {
        if (receivedAlert(err)) |alert| {
            conn.diag.alert_received = alert;
            break :blk error.AlertReceived;
        }
        if (err == error.TlsAlertUnknown) break :blk error.AlertReceived;
        if (err == error.TlsAlertCloseNotify) break :blk error.ConnectionTruncated;
        if (certificateReason(err)) |reason| {
            conn.diag.certificate = .{ .reason = reason };
            break :blk error.CertificateRejected;
        }
        break :blk switch (err) {
            error.TlsConnectionTruncated, error.EndOfStream => error.ConnectionTruncated,
            error.TlsNoApplicationProtocol,
            error.TlsNoSupportedCiphers,
            error.TlsProtocolVersion,
            error.TlsHandshakeFailure,
            error.TlsInsufficientSecurity,
            error.TlsServerHelloRetryRequest,
            error.TlsUnknownSignatureScheme,
            error.TlsMissingExtension,
            error.TlsUnsupportedFragmentedHandshakeMessage,
            => error.Incompatible,
            error.TlsInternalError,
            error.TlsCipherNoSpaceLeft,
            error.BufferUndersize,
            error.InputBufferUndersize,
            error.OutputBufferUndersize,
            error.OutOfMemory,
            => error.Internal,
            else => error.ProtocolViolation,
        };
    };
    conn.failed = tls_err;
    return tls_err;
}

fn alertOf(alert: ?TlsAlert) ?api.Alert {
    const a = alert orelse return null;
    return @enumFromInt(@intFromEnum(a));
}

/// The alert a `TlsAlert*` error stands for.
fn receivedAlert(err: anyerror) ?api.Alert {
    inline for (comptime std.enums.values(TlsAlert)) |alert| {
        if (alert.toError()) |_| {} else |alert_err| {
            if (err == alert_err and alert_err != error.TlsAlertUnknown) return alertOf(alert);
        }
    }
    return null;
}

fn certificateReason(err: anyerror) ?api.CertificateProblem.Reason {
    return switch (err) {
        error.CertificateHostMismatch => .name_mismatch,
        error.CertificateExpired, error.TlsCertificateExpired => .expired,
        error.CertificateNotYetValid => .not_yet_valid,
        error.CertificateIssuerNotFound, error.CertificateIssuerMismatch, error.TlsUnknownCa => .untrusted,
        error.CertificateSignatureInvalid, error.CertificateSignatureInvalidLength, error.SignatureVerificationFailed => .bad_signature,
        error.TlsCertificateRevoked => .revoked,
        error.TlsCertificateRequired => .missing,
        error.CertificateFieldHasInvalidLength,
        error.CertificateFieldHasWrongDataType,
        error.CertificatePublicKeyInvalid,
        error.CertificateTimeInvalid,
        => .malformed,
        error.CertificateSignatureAlgorithmUnsupported,
        error.CertificateSignatureAlgorithmMismatch,
        error.CertificateSignatureUnsupportedBitCount,
        error.CertificateSignatureNamedCurveUnsupported,
        error.CertificatePublicKeyUnsupported,
        error.TlsBadCertificate,
        error.TlsUnsupportedCertificate,
        error.TlsCertificateUnknown,
        => .other,
        else => null,
    };
}

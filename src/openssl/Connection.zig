//! One TLS connection driven by libssl, sans-I/O: libssl only ever sees
//! slices of the caller's transport buffers, through a custom BIO, and all
//! transport I/O happens here, outside libssl.
//!
//! Must not move after `initClient`/`initServer`: libssl holds pointers to
//! it (app data, BIO data).
const Connection = @This();

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;
const c = @import("c");
const api = @import("../api.zig");
const record = @import("../record.zig");
const stream = @import("../stream.zig");
const context = @import("context.zig");

const TlsError = api.TlsError;

shared: *context.Shared,
io: Io,
ssl: *c.SSL,
input: *Io.Reader,
output: *Io.Writer,

/// Serializes libssl calls between the reader and the writer task. Never
/// held across transport I/O.
mutex: Io.Mutex = .init,
handshake_done: bool = false,
/// close_notify received, or EOF at a record boundary.
read_closed: bool = false,
close_sent: bool = false,
/// Sticky TLS-layer failure.
failed: ?TlsError = null,

/// Record boundaries of the ciphertext consumed so far.
tracker: record.Tracker = .{},

/// BIO windows, set around each libssl call.
bio_in: []const u8 = &.{},
bio_in_used: usize = 0,
bio_out: []u8 = &.{},
bio_out_used: usize = 0,

/// Output produced while reading (KeyUpdate replies, alerts). The reader
/// never touches the transport writer; the writer side sends this first.
pending: [pending_capacity]u8 = undefined,
pending_len: usize = 0,

/// First certificate verification error reported by the verify callback.
verify_error: ?VerifyError = null,
diag: api.Diagnostics = .{},
detail_buf: [256]u8 = undefined,

const VerifyError = struct { code: c_int, depth: c_int };

const pending_capacity = 1024;
/// Largest cleartext passed to one SSL_write: one record.
const max_fragment = 16384;
/// Worst-case expansion of one record (header, IV, MAC/tag, padding) plus a
/// KeyUpdate record that may precede it.
const max_record_overhead = 256;

/// Minimum transport buffer sizes: the reader must hold a full ciphertext
/// record, the writer a full record plus overhead.
pub const input_buffer_len = 16384 + 2048 + 5;
pub const output_buffer_len = max_fragment + max_record_overhead;

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
    if (name.len == 0 and ctx.shared.verify_name) return error.MissingServerName;
    if (name.len > api.max_server_name_len or std.mem.indexOfScalar(u8, name, 0) != null)
        return error.InvalidServerName;

    try conn.init(&ctx.shared, io, input, output);
    errdefer conn.deinit();

    if (name.len > 0) {
        var name_z: [api.max_server_name_len + 1]u8 = undefined;
        @memcpy(name_z[0..name.len], name);
        name_z[name.len] = 0;
        const name_ptr: [*:0]const u8 = name_z[0..name.len :0];

        const is_ip = if (Io.net.IpAddress.parse(name, 0)) |_| true else |_| false;
        if (is_ip) {
            // IP literals are not sent as SNI (RFC 6066 section 3).
            if (ctx.shared.verify_name and c.X509_VERIFY_PARAM_set1_ip_asc(c.SSL_get0_param(conn.ssl), name_ptr) != 1)
                return error.InvalidServerName;
        } else {
            if (c.SSL_set_tlsext_host_name(conn.ssl, name_ptr) != 1) return error.InvalidServerName;
            if (ctx.shared.verify_name and c.SSL_set1_host(conn.ssl, name_ptr) != 1) return error.InvalidServerName;
        }
    }
    c.SSL_set_connect_state(conn.ssl);
}

pub fn initServer(
    conn: *Connection,
    ctx: *context.ServerContext,
    io: Io,
    input: *Io.Reader,
    output: *Io.Writer,
) api.ConnectionInitError!void {
    try conn.init(&ctx.shared, io, input, output);
    c.SSL_set_accept_state(conn.ssl);
}

fn init(conn: *Connection, shared: *context.Shared, io: Io, input: *Io.Reader, output: *Io.Writer) error{OutOfMemory}!void {
    assert(input.buffer.len >= input_buffer_len);
    assert(output.buffer.len >= output_buffer_len);

    const ssl = c.SSL_new(shared.ssl_ctx) orelse return error.OutOfMemory;
    errdefer c.SSL_free(ssl);
    const rbio = c.BIO_new(shared.bio_method) orelse return error.OutOfMemory;
    const wbio = c.BIO_new(shared.bio_method) orelse {
        _ = c.BIO_free(rbio);
        return error.OutOfMemory;
    };
    c.SSL_set_bio(ssl, rbio, wbio); // ssl owns both BIOs now
    c.BIO_set_data(rbio, conn);
    c.BIO_set_data(wbio, conn);
    _ = c.SSL_set_ex_data(ssl, 0, conn);

    conn.* = .{
        .shared = shared,
        .io = io,
        .ssl = ssl,
        .input = input,
        .output = output,
    };
    if (std.debug.runtime_safety) _ = shared.live.fetchAdd(1, .monotonic);
}

/// Frees libssl state. Does not close the transport.
pub fn deinit(conn: *Connection) void {
    c.SSL_free(conn.ssl);
    if (std.debug.runtime_safety) _ = conn.shared.live.fetchSub(1, .monotonic);
    conn.* = undefined;
}

/// Performs the handshake. Must complete before the reader or writer is
/// used, and runs on one task.
///
/// `error.ReadFailed`/`error.WriteFailed` mean the transport failed; the
/// cause is on the transport reader/writer. Anything else is a TLS failure
/// with details in `diagnostics()`.
pub fn handshake(conn: *Connection) api.HandshakeError!void {
    assert(!conn.handshake_done);
    if (conn.failed) |err| return err;
    while (true) {
        const r = conn.call(conn.input.buffered(), conn.output.unusedCapacitySlice(), .handshake, &.{});
        conn.input.toss(r.consumed);
        conn.output.advance(r.produced);
        switch (r.code) {
            c.SSL_ERROR_NONE => {
                conn.handshake_done = true;
                try conn.output.flush();
                return;
            },
            c.SSL_ERROR_WANT_READ => {
                try conn.output.flush();
                conn.input.fillMore() catch |err| switch (err) {
                    error.EndOfStream => return conn.fail(error.ConnectionTruncated),
                    error.ReadFailed => return error.ReadFailed,
                };
            },
            c.SSL_ERROR_WANT_WRITE => try conn.output.flush(),
            else => {
                conn.classifyFailure();
                // Best effort: deliver the alert libssl wrote.
                conn.output.flush() catch {};
                return conn.failed.?;
            },
        }
    }
}

/// Decrypts into `dest` (non-empty). See `stream.zig` for the contract.
pub fn read(conn: *Connection, dest: []u8) error{ ReadFailed, EndOfStream }!usize {
    assert(conn.handshake_done);
    while (true) {
        conn.mutex.lockUncancelable(conn.io);
        if (conn.failed != null) {
            conn.mutex.unlock(conn.io);
            return error.ReadFailed;
        }
        if (conn.read_closed) {
            conn.mutex.unlock(conn.io);
            return error.EndOfStream;
        }
        var n: usize = 0;
        const r = conn.call(conn.input.buffered(), conn.pending[conn.pending_len..], .read, dest);
        conn.input.toss(r.consumed);
        conn.pending_len += r.produced;
        switch (r.code) {
            c.SSL_ERROR_NONE => n = r.bytes,
            c.SSL_ERROR_ZERO_RETURN => conn.read_closed = true,
            c.SSL_ERROR_WANT_READ => {},
            c.SSL_ERROR_WANT_WRITE => {
                // The pending queue is full: the peer keeps provoking
                // replies (e.g. KeyUpdate requests) faster than we write.
                conn.setDetail("too much post-handshake output pending");
                conn.failed = error.ProtocolViolation;
            },
            else => conn.classifyFailure(),
        }
        const failed = conn.failed != null;
        const closed = conn.read_closed;
        conn.mutex.unlock(conn.io);

        if (n > 0) return n;
        if (failed) return error.ReadFailed;
        if (closed) return error.EndOfStream;

        // libssl consumed everything buffered and wants more.
        conn.input.fillMore() catch |err| switch (err) {
            error.ReadFailed => return error.ReadFailed,
            error.EndOfStream => {
                conn.mutex.lockUncancelable(conn.io);
                defer conn.mutex.unlock(conn.io);
                // Go's rule: EOF at a record boundary ends the stream,
                // inside a record it is truncation.
                if (conn.tracker.atBoundary()) {
                    conn.read_closed = true;
                    return error.EndOfStream;
                }
                conn.failed = error.ConnectionTruncated;
                return error.ReadFailed;
            },
        };
    }
}

/// Encrypts all of `bytes` into the transport writer, flushing the
/// transport only when its buffer is full.
pub fn write(conn: *Connection, bytes: []const u8) error{WriteFailed}!void {
    assert(conn.handshake_done);
    var off: usize = 0;
    while (off < bytes.len) {
        const chunk = bytes[off..][0..@min(bytes.len - off, max_fragment)];
        conn.mutex.lockUncancelable(conn.io);
        if (conn.failed != null) {
            conn.mutex.unlock(conn.io);
            return error.WriteFailed;
        }
        if (!conn.movePendingLocked() or conn.output.unusedCapacityLen() < chunk.len + max_record_overhead) {
            conn.mutex.unlock(conn.io);
            try conn.output.flush();
            continue;
        }
        const r = conn.call(&.{}, conn.output.unusedCapacitySlice(), .write, @constCast(chunk));
        conn.output.advance(r.produced);
        switch (r.code) {
            c.SSL_ERROR_NONE => off += r.bytes,
            // Not expected with the space reserved above; retry after
            // making room.
            c.SSL_ERROR_WANT_WRITE => {},
            else => conn.classifyFailure(),
        }
        const failed = conn.failed != null;
        conn.mutex.unlock(conn.io);
        if (failed) return error.WriteFailed;
        if (r.code == c.SSL_ERROR_WANT_WRITE) try conn.output.flush();
    }
}

/// Sends output queued by the reader and flushes the transport writer.
pub fn flush(conn: *Connection) error{WriteFailed}!void {
    while (true) {
        conn.mutex.lockUncancelable(conn.io);
        const moved = conn.movePendingLocked();
        conn.mutex.unlock(conn.io);
        try conn.output.flush();
        if (moved) return;
    }
}

/// Sends close_notify (or a pending fatal alert) and flushes the transport.
/// Idempotent. Belongs to the writer side. Does not wait for the peer's
/// close_notify and does not close the transport.
pub fn close(conn: *Connection) error{WriteFailed}!void {
    while (true) {
        conn.mutex.lockUncancelable(conn.io);
        if (!conn.movePendingLocked() or conn.output.unusedCapacityLen() < max_record_overhead) {
            conn.mutex.unlock(conn.io);
            try conn.output.flush();
            continue;
        }
        if (conn.handshake_done and conn.failed == null and !conn.close_sent) {
            conn.close_sent = true;
            const r = conn.call(&.{}, conn.output.unusedCapacitySlice(), .shutdown, &.{});
            conn.output.advance(r.produced);
        }
        conn.mutex.unlock(conn.io);
        return conn.output.flush();
    }
}

/// Moves the pending queue into the transport writer's buffer. Returns false
/// if it does not fit; the caller must flush the transport and retry.
fn movePendingLocked(conn: *Connection) bool {
    if (conn.pending_len == 0) return true;
    const dest = conn.output.unusedCapacitySlice();
    if (dest.len < conn.pending_len) return false;
    @memcpy(dest[0..conn.pending_len], conn.pending[0..conn.pending_len]);
    conn.output.advance(conn.pending_len);
    conn.pending_len = 0;
    return true;
}

/// The TLS-layer cause of the last failure; null if it was the transport.
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

/// ALPN protocol negotiated in the handshake, null if none. Valid until
/// `deinit`.
pub fn alpnProtocol(conn: *const Connection) ?[]const u8 {
    var data: [*c]const u8 = null;
    var len: c_uint = 0;
    c.SSL_get0_alpn_selected(conn.ssl, &data, &len);
    return if (len > 0) data[0..len] else null;
}

pub const ProtocolVersion = enum { tls_1_2, tls_1_3 };

pub fn protocolVersion(conn: *const Connection) ProtocolVersion {
    return if (c.SSL_version(conn.ssl) == c.TLS1_3_VERSION) .tls_1_3 else .tls_1_2;
}

/// IANA name of the negotiated cipher suite, e.g. "TLS_AES_128_GCM_SHA256".
pub fn cipherSuite(conn: *const Connection) []const u8 {
    const cipher = c.SSL_get_current_cipher(conn.ssl) orelse return "";
    return std.mem.span(c.SSL_CIPHER_standard_name(cipher));
}

// libssl calls

const Op = enum { handshake, read, write, shutdown };

const CallResult = struct {
    /// SSL_ERROR_* code, SSL_ERROR_NONE on success.
    code: c_int,
    /// Cleartext bytes read or written.
    bytes: usize,
    /// Ciphertext consumed from the input window.
    consumed: usize,
    /// Ciphertext produced into the output window.
    produced: usize,
};

/// Runs one libssl operation against the given ciphertext windows. The
/// error queue is thread-local, so it is cleared before and inspected right
/// after the call, with no suspension point in between; `classifyFailure`
/// must be called before the next suspension if the call failed.
fn call(conn: *Connection, in: []const u8, out: []u8, op: Op, buf: []u8) CallResult {
    conn.bio_in = in;
    conn.bio_in_used = 0;
    conn.bio_out = out;
    conn.bio_out_used = 0;
    c.ERR_clear_error();
    var n: usize = 0;
    const rc: c_int = switch (op) {
        .handshake => c.SSL_do_handshake(conn.ssl),
        .read => c.SSL_read_ex(conn.ssl, buf.ptr, buf.len, &n),
        .write => c.SSL_write_ex(conn.ssl, buf.ptr, buf.len, &n),
        .shutdown => c.SSL_shutdown(conn.ssl),
    };
    const code = if (rc > 0 or (op == .shutdown and rc == 0)) c.SSL_ERROR_NONE else c.SSL_get_error(conn.ssl, rc);
    const result: CallResult = .{
        .code = code,
        .bytes = n,
        .consumed = conn.bio_in_used,
        .produced = conn.bio_out_used,
    };
    conn.bio_in = &.{};
    conn.bio_out = &.{};
    return result;
}

fn fail(conn: *Connection, err: TlsError) TlsError {
    conn.failed = err;
    return err;
}

/// Turns the state left by a failed libssl call (error queue, verify and
/// info callbacks, record tracker) into a `TlsError` in `conn.failed`, and
/// clears the error queue.
fn classifyFailure(conn: *Connection) void {
    defer c.ERR_clear_error();

    // The outermost SSL-library reason explains the failure; the last queue
    // entry is the best message.
    var ssl_reason: ?c_int = null;
    var last: c_ulong = 0;
    while (true) {
        const e = c.ERR_get_error();
        if (e == 0) break;
        last = e;
        if (c.ERR_GET_LIB(e) == c.ERR_LIB_SSL) ssl_reason = c.ERR_GET_REASON(e);
    }
    if (last != 0) {
        c.ERR_error_string_n(last, &conn.detail_buf, conn.detail_buf.len);
        conn.diag.detail = std.mem.sliceTo(&conn.detail_buf, 0);
    } else {
        conn.diag.detail = "";
    }
    conn.diag.not_tls = conn.tracker.not_tls;

    const err: TlsError = blk: {
        if (conn.diag.alert_received != null) break :blk error.AlertReceived;
        if (ssl_reason) |reason| {
            if (reason >= c.SSL_AD_REASON_OFFSET and reason < c.SSL_AD_REASON_OFFSET + 256) {
                conn.diag.alert_received = @enumFromInt(reason - c.SSL_AD_REASON_OFFSET);
                break :blk error.AlertReceived;
            }
        }
        if (conn.verify_error) |ve| {
            conn.diag.certificate = .{
                .reason = certificateReason(ve.code),
                .depth = std.math.cast(u8, ve.depth),
            };
            const msg = std.mem.span(c.X509_verify_cert_error_string(ve.code));
            conn.diag.detail = msg;
            break :blk error.CertificateRejected;
        }
        if (conn.diag.not_tls) break :blk error.ProtocolViolation;
        const reason = ssl_reason orelse break :blk error.Internal;
        if (reason == c.SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE) {
            conn.diag.certificate = .{ .reason = .missing };
            break :blk error.CertificateRejected;
        }
        if (reason == c.SSL_R_CERTIFICATE_VERIFY_FAILED) {
            conn.diag.certificate = .{ .reason = .other };
            break :blk error.CertificateRejected;
        }
        if (isIncompatible(reason)) break :blk error.Incompatible;
        if (isInternal(reason)) break :blk error.Internal;
        break :blk error.ProtocolViolation;
    };
    conn.failed = err;
}

fn setDetail(conn: *Connection, msg: []const u8) void {
    conn.diag.detail = msg;
}

fn isIncompatible(reason: c_int) bool {
    const names = .{
        "SSL_R_NO_SHARED_CIPHER",
        "SSL_R_NO_CIPHERS_AVAILABLE",
        "SSL_R_UNSUPPORTED_PROTOCOL",
        "SSL_R_NO_PROTOCOLS_AVAILABLE",
        "SSL_R_VERSION_TOO_LOW",
        "SSL_R_VERSION_TOO_HIGH",
        "SSL_R_NO_SUITABLE_KEY_SHARE",
        "SSL_R_NO_SHARED_GROUPS",
        "SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS",
        "SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM",
        "SSL_R_NO_APPLICATION_PROTOCOL",
    };
    inline for (names) |name| {
        if (@hasDecl(c, name) and reason == @field(c, name)) return true;
    }
    return false;
}

fn isInternal(reason: c_int) bool {
    const names = .{
        "SSL_R_INTERNAL_ERROR",
    };
    inline for (names) |name| {
        if (@hasDecl(c, name) and reason == @field(c, name)) return true;
    }
    return false;
}

fn certificateReason(code: c_int) api.CertificateProblem.Reason {
    const map = .{
        .{ "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT", .untrusted },
        .{ "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY", .untrusted },
        .{ "X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE", .untrusted },
        .{ "X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT", .untrusted },
        .{ "X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN", .untrusted },
        .{ "X509_V_ERR_CERT_UNTRUSTED", .untrusted },
        .{ "X509_V_ERR_CERT_REJECTED", .untrusted },
        .{ "X509_V_ERR_HOSTNAME_MISMATCH", .name_mismatch },
        .{ "X509_V_ERR_IP_ADDRESS_MISMATCH", .name_mismatch },
        .{ "X509_V_ERR_EMAIL_MISMATCH", .name_mismatch },
        .{ "X509_V_ERR_CERT_HAS_EXPIRED", .expired },
        .{ "X509_V_ERR_CERT_NOT_YET_VALID", .not_yet_valid },
        .{ "X509_V_ERR_CERT_REVOKED", .revoked },
        .{ "X509_V_ERR_CERT_SIGNATURE_FAILURE", .bad_signature },
        .{ "X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE", .bad_signature },
        .{ "X509_V_ERR_INVALID_CA", .invalid_usage },
        .{ "X509_V_ERR_INVALID_PURPOSE", .invalid_usage },
        .{ "X509_V_ERR_KEYUSAGE_NO_CERTSIGN", .invalid_usage },
        .{ "X509_V_ERR_PATH_LENGTH_EXCEEDED", .invalid_usage },
        .{ "X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD", .malformed },
        .{ "X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD", .malformed },
        .{ "X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY", .malformed },
    };
    inline for (map) |entry| {
        if (@hasDecl(c, entry[0]) and code == @field(c, entry[0])) return entry[1];
    }
    return .other;
}

// Callbacks. libssl calls these synchronously inside `call`; none of them
// may suspend.

fn fromSsl(ssl: ?*const c.SSL) *Connection {
    return @ptrCast(@alignCast(c.SSL_get_ex_data(ssl, 0).?));
}

pub fn verifyCallback(preverify_ok: c_int, store_ctx: ?*c.X509_STORE_CTX) callconv(.c) c_int {
    if (preverify_ok == 1) return 1;
    const ssl: ?*c.SSL = @ptrCast(c.X509_STORE_CTX_get_ex_data(store_ctx, c.SSL_get_ex_data_X509_STORE_CTX_idx()));
    const conn = fromSsl(ssl);
    if (conn.verify_error == null) conn.verify_error = .{
        .code = c.X509_STORE_CTX_get_error(store_ctx),
        .depth = c.X509_STORE_CTX_get_error_depth(store_ctx),
    };
    return 0;
}

pub fn infoCallback(ssl: ?*const c.SSL, where: c_int, value: c_int) callconv(.c) void {
    if (where & c.SSL_CB_ALERT == 0) return;
    const bits: c_uint = @bitCast(value);
    // Only fatal alerts (level 2) end a connection.
    if (bits >> 8 != 2) return;
    const alert: api.Alert = @enumFromInt(@as(u8, @truncate(bits)));
    const conn = fromSsl(ssl);
    if (where & c.SSL_CB_READ != 0) {
        if (conn.diag.alert_received == null) conn.diag.alert_received = alert;
    } else if (where & c.SSL_CB_WRITE != 0) {
        if (conn.diag.alert_sent == null) conn.diag.alert_sent = alert;
    }
}

// Custom BIO: reads from `bio_in`, writes to `bio_out`. Never does I/O; an
// exhausted window is "retry", which libssl reports as WANT_READ/WANT_WRITE.

pub fn newBioMethod() error{OutOfMemory}!*c.BIO_METHOD {
    const method = c.BIO_meth_new(c.BIO_get_new_index() | c.BIO_TYPE_SOURCE_SINK, "anytls") orelse
        return error.OutOfMemory;
    _ = c.BIO_meth_set_read(method, bioRead);
    _ = c.BIO_meth_set_write(method, bioWrite);
    _ = c.BIO_meth_set_ctrl(method, bioCtrl);
    _ = c.BIO_meth_set_create(method, bioCreate);
    return method;
}

fn bioCreate(bio: ?*c.BIO) callconv(.c) c_int {
    c.BIO_set_init(bio, 1);
    return 1;
}

fn bioRead(bio: ?*c.BIO, buf: [*c]u8, len: c_int) callconv(.c) c_int {
    c.BIO_clear_flags(bio, c.BIO_FLAGS_RWS | c.BIO_FLAGS_SHOULD_RETRY);
    const conn: *Connection = @ptrCast(@alignCast(c.BIO_get_data(bio).?));
    const avail = conn.bio_in[conn.bio_in_used..];
    if (avail.len == 0 or len <= 0) {
        c.BIO_set_flags(bio, c.BIO_FLAGS_READ | c.BIO_FLAGS_SHOULD_RETRY);
        return -1;
    }
    const n = @min(avail.len, @as(usize, @intCast(len)));
    @memcpy(buf[0..n], avail[0..n]);
    conn.bio_in_used += n;
    conn.tracker.feed(avail[0..n]);
    return @intCast(n);
}

fn bioWrite(bio: ?*c.BIO, buf: [*c]const u8, len: c_int) callconv(.c) c_int {
    c.BIO_clear_flags(bio, c.BIO_FLAGS_RWS | c.BIO_FLAGS_SHOULD_RETRY);
    const conn: *Connection = @ptrCast(@alignCast(c.BIO_get_data(bio).?));
    const space = conn.bio_out[conn.bio_out_used..];
    if (space.len == 0 or len <= 0) {
        c.BIO_set_flags(bio, c.BIO_FLAGS_WRITE | c.BIO_FLAGS_SHOULD_RETRY);
        return -1;
    }
    const n = @min(space.len, @as(usize, @intCast(len)));
    @memcpy(space[0..n], buf[0..n]);
    conn.bio_out_used += n;
    return @intCast(n);
}

fn bioCtrl(bio: ?*c.BIO, cmd: c_int, num: c_long, ptr: ?*anyopaque) callconv(.c) c_long {
    _ = .{ bio, num, ptr };
    // libssl treats a failed flush as WANT_WRITE; the transport is flushed
    // by us, so flushing the BIO always succeeds.
    return if (cmd == c.BIO_CTRL_FLUSH) 1 else 0;
}

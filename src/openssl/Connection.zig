//! One TLS connection driven by libssl, sans-I/O: libssl only ever sees
//! slices of the caller's transport buffers, through a custom BIO, and all
//! transport I/O happens here, outside libssl.
//!
//! Must not move after `initClient`/`initServer`: libssl holds pointers to
//! it (app data, BIO data).
//!
//! Concurrency: after the handshake, one task may read while another
//! writes. Three locks, always taken in this order:
//! 1. `read_mutex` — held for a whole read, transport I/O included. The
//!    writer only ever `tryLock`s it.
//! 2. `write_mutex` — held for a whole write/flush/close, transport I/O
//!    included. A reader takes it to send output its read produced.
//! 3. `ssl_mutex` — held around each libssl call and the state it touches;
//!    never across transport I/O.
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
const StreamError = api.StreamError;

shared: *context.Shared,
io: Io,
ssl: *c.SSL,
input: *Io.Reader,
output: *Io.Writer,

read_mutex: Io.Mutex = .init,
write_mutex: Io.Mutex = .init,
ssl_mutex: Io.Mutex = .init,
/// Bumped (under `ssl_mutex`) after every libssl read and when a read ends;
/// a writer waiting for the reader to receive input waits for it to change.
read_progress: u64 = 0,
read_progress_cond: Io.Condition = .init,

handshake_done: bool = false,
/// close_notify received, or EOF at a record boundary.
read_closed: bool = false,
close_sent: bool = false,
/// Sticky TLS-layer failure.
failed: ?TlsError = null,
/// The transport writer failed; nothing more can be sent. Guarded by
/// `write_mutex`.
write_failed: bool = false,

/// Record boundaries of the ciphertext consumed so far.
tracker: record.Tracker = .{},

/// BIO windows, set around each libssl call.
bio_in: []const u8 = &.{},
bio_in_used: usize = 0,
bio_out: []u8 = &.{},
bio_out_used: usize = 0,

/// Output libssl produced during a read (KeyUpdate replies, alerts). The
/// reader moves it into the transport writer under `write_mutex`; if it
/// fills up, libssl reports WANT_WRITE and the reader sends it first.
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
    if (c.SSL_set_ex_data(ssl, 0, conn) != 1) return error.OutOfMemory;
    const rbio = c.BIO_new(shared.bio_method) orelse return error.OutOfMemory;
    const wbio = c.BIO_new(shared.bio_method) orelse {
        _ = c.BIO_free(rbio);
        return error.OutOfMemory;
    };
    c.BIO_set_data(rbio, conn);
    c.BIO_set_data(wbio, conn);
    c.SSL_set_bio(ssl, rbio, wbio); // ssl owns both BIOs now

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
/// used, and runs on one task. See `StreamError` for the errors.
pub fn handshake(conn: *Connection) StreamError!void {
    assert(!conn.handshake_done);
    if (conn.failed) |err| return err;
    if (conn.write_failed) return error.TransportWriteFailed;
    while (true) {
        const r = conn.call(conn.input.buffered(), conn.output.unusedCapacitySlice(), .handshake, &.{});
        conn.input.toss(r.consumed);
        conn.output.advance(r.produced);
        switch (r.code) {
            c.SSL_ERROR_NONE => {
                conn.handshake_done = true;
                return conn.flushTransport();
            },
            c.SSL_ERROR_WANT_READ => {
                try conn.flushTransport();
                conn.input.fillMore() catch |err| switch (err) {
                    error.EndOfStream => return conn.setFailed(error.ConnectionTruncated, "connection closed during handshake"),
                    error.ReadFailed => return error.TransportReadFailed,
                };
            },
            c.SSL_ERROR_WANT_WRITE => try conn.flushTransport(),
            c.SSL_ERROR_ZERO_RETURN => return conn.setFailed(error.ConnectionTruncated, "close_notify during handshake"),
            else => {
                const err = conn.classifyFailure(r.code);
                // Best effort: deliver the alert libssl wrote.
                conn.flushTransport() catch {};
                return err;
            },
        }
    }
}

/// Decrypts into `dest` (non-empty). Returns at least one byte, or
/// `error.EndOfStream` after close_notify or a transport EOF at a record
/// boundary.
pub fn read(conn: *Connection, dest: []u8) (StreamError || error{EndOfStream})!usize {
    assert(conn.handshake_done);
    assert(dest.len > 0);
    conn.read_mutex.lockUncancelable(conn.io);
    defer {
        conn.ssl_mutex.lockUncancelable(conn.io);
        conn.bumpReadProgress();
        conn.ssl_mutex.unlock(conn.io);
        conn.read_mutex.unlock(conn.io);
    }

    while (true) {
        conn.ssl_mutex.lockUncancelable(conn.io);
        if (conn.failed) |err| {
            conn.ssl_mutex.unlock(conn.io);
            return err;
        }
        if (conn.read_closed) {
            conn.ssl_mutex.unlock(conn.io);
            return error.EndOfStream;
        }
        const r = conn.call(conn.input.buffered(), conn.pending[conn.pending_len..], .read, dest);
        conn.input.toss(r.consumed);
        conn.pending_len += r.produced;
        var n: usize = 0;
        switch (r.code) {
            c.SSL_ERROR_NONE => n = r.bytes,
            c.SSL_ERROR_ZERO_RETURN => conn.read_closed = true,
            c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => {},
            else => conn.failed = conn.classifyFailure(r.code),
        }
        conn.bumpReadProgress();
        const failed = conn.failed;
        const closed = conn.read_closed;
        const has_pending = conn.pending_len > 0;
        conn.ssl_mutex.unlock(conn.io);

        // Send what the read produced before going on, as Go does: a
        // KeyUpdate reply, or the alert reporting a failure.
        if (has_pending) {
            conn.sendPending() catch |err| {
                // The TLS failure, if any, is the more useful cause.
                if (failed) |tls_err| return tls_err;
                return err;
            };
        }
        if (n > 0) return n;
        if (failed) |err| return err;
        if (closed) return error.EndOfStream;
        // The pending queue was full; it has been sent, try again.
        if (r.code == c.SSL_ERROR_WANT_WRITE) continue;

        // libssl consumed everything buffered and wants more.
        conn.input.fillMore() catch |err| switch (err) {
            error.ReadFailed => return error.TransportReadFailed,
            error.EndOfStream => {
                conn.ssl_mutex.lockUncancelable(conn.io);
                defer conn.ssl_mutex.unlock(conn.io);
                // Go's rule: EOF at a record boundary ends the stream,
                // inside a record it is truncation.
                if (conn.tracker.atBoundary()) {
                    conn.read_closed = true;
                    return error.EndOfStream;
                }
                return conn.setFailed(error.ConnectionTruncated, "connection closed inside a record");
            },
        };
    }
}

/// Encrypts all of `bytes` into the transport writer, flushing the
/// transport only when its buffer is full.
pub fn write(conn: *Connection, bytes: []const u8) StreamError!void {
    assert(conn.handshake_done);
    conn.write_mutex.lockUncancelable(conn.io);
    defer conn.write_mutex.unlock(conn.io);
    assert(!conn.close_sent); // writing after close() is a usage error
    if (conn.write_failed) return error.TransportWriteFailed;

    var off: usize = 0;
    while (off < bytes.len) {
        const chunk = bytes[off..][0..@min(bytes.len - off, max_fragment)];
        off += try conn.writeOp(.write, @constCast(chunk));
    }
}

/// Sends anything queued and flushes the transport writer.
pub fn flush(conn: *Connection) StreamError!void {
    conn.write_mutex.lockUncancelable(conn.io);
    defer conn.write_mutex.unlock(conn.io);
    if (conn.write_failed) return error.TransportWriteFailed;
    try conn.movePendingAndFlush();
}

/// Sends close_notify and flushes the transport. Idempotent; after it the
/// connection may only read or be deinitialized. Does not wait for the
/// peer's close_notify and does not close the transport. After a TLS
/// failure it only flushes what is queued (the alert).
pub fn close(conn: *Connection) StreamError!void {
    conn.write_mutex.lockUncancelable(conn.io);
    defer conn.write_mutex.unlock(conn.io);
    if (conn.write_failed) return error.TransportWriteFailed;
    if (conn.handshake_done and !conn.close_sent) {
        conn.ssl_mutex.lockUncancelable(conn.io);
        const ok = conn.failed == null;
        conn.ssl_mutex.unlock(conn.io);
        if (ok) {
            _ = try conn.writeOp(.shutdown, &.{});
            conn.close_sent = true;
        }
    }
    try conn.movePendingAndFlush();
}

/// Runs SSL_write or SSL_shutdown until it succeeds, returning the number
/// of cleartext bytes written. Caller holds `write_mutex`.
fn writeOp(conn: *Connection, op: Op, buf: []u8) StreamError!usize {
    // Set when libssl needs input to continue (a post-handshake message
    // arrived only partly) and no read is in progress: the writer then feeds
    // it input itself.
    var holds_read = false;
    defer if (holds_read) conn.read_mutex.unlock(conn.io);

    while (true) {
        conn.ssl_mutex.lockUncancelable(conn.io);
        if (conn.failed) |err| {
            conn.ssl_mutex.unlock(conn.io);
            return err;
        }
        if (!conn.movePendingLocked() or conn.output.unusedCapacityLen() < buf.len + max_record_overhead) {
            conn.ssl_mutex.unlock(conn.io);
            try conn.flushTransport();
            continue;
        }
        const in: []const u8 = if (holds_read) conn.input.buffered() else &.{};
        // SSL_shutdown fails outright (instead of asking for input) while a
        // post-handshake message is half received; finish that message
        // first, which waits for input like a write does.
        const this_op: Op = if (op == .shutdown and c.SSL_in_init(conn.ssl) != 0) .handshake else op;
        const r = conn.call(in, conn.output.unusedCapacitySlice(), this_op, buf);
        if (holds_read) conn.input.toss(r.consumed);
        conn.output.advance(r.produced);
        const err: ?TlsError = switch (r.code) {
            c.SSL_ERROR_NONE, c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => null,
            else => conn.classifyFailure(r.code),
        };
        const progress = conn.read_progress;
        conn.ssl_mutex.unlock(conn.io);

        if (err) |e| return e;
        switch (r.code) {
            c.SSL_ERROR_NONE => if (this_op == op) return r.bytes,
            c.SSL_ERROR_WANT_WRITE => try conn.flushTransport(),
            c.SSL_ERROR_WANT_READ => {
                if (holds_read) {
                    try conn.flushTransport();
                    conn.input.fillMore() catch |e| switch (e) {
                        error.ReadFailed => return error.TransportReadFailed,
                        error.EndOfStream => {
                            conn.ssl_mutex.lockUncancelable(conn.io);
                            defer conn.ssl_mutex.unlock(conn.io);
                            return conn.setFailed(error.ConnectionTruncated, "connection closed inside a message");
                        },
                    };
                } else if (conn.read_mutex.tryLock()) {
                    holds_read = true;
                } else {
                    // A read is in progress and will feed libssl. Wait for
                    // it without holding `write_mutex`, which the reader may
                    // need to send what its read produced.
                    conn.write_mutex.unlock(conn.io);
                    conn.ssl_mutex.lockUncancelable(conn.io);
                    while (conn.read_progress == progress and conn.failed == null)
                        conn.read_progress_cond.waitUncancelable(conn.io, &conn.ssl_mutex);
                    conn.ssl_mutex.unlock(conn.io);
                    conn.write_mutex.lockUncancelable(conn.io);
                    if (conn.write_failed) return error.TransportWriteFailed;
                }
            },
            else => unreachable,
        }
    }
}

/// Reader side: sends output produced by a read. Takes `write_mutex`.
fn sendPending(conn: *Connection) StreamError!void {
    conn.write_mutex.lockUncancelable(conn.io);
    defer conn.write_mutex.unlock(conn.io);
    if (conn.write_failed) return error.TransportWriteFailed;
    try conn.movePendingAndFlush();
}

/// Moves the pending queue into the transport writer and flushes it.
/// Caller holds `write_mutex`.
fn movePendingAndFlush(conn: *Connection) StreamError!void {
    while (true) {
        conn.ssl_mutex.lockUncancelable(conn.io);
        const moved = conn.movePendingLocked();
        conn.ssl_mutex.unlock(conn.io);
        try conn.flushTransport();
        if (moved) return;
    }
}

/// Moves the pending queue into the transport writer's buffer. Returns false
/// if it does not fit; the caller must flush the transport and retry.
/// Caller holds `write_mutex` and `ssl_mutex`.
fn movePendingLocked(conn: *Connection) bool {
    if (conn.pending_len == 0) return true;
    const dest = conn.output.unusedCapacitySlice();
    if (dest.len < conn.pending_len) return false;
    @memcpy(dest[0..conn.pending_len], conn.pending[0..conn.pending_len]);
    conn.output.advance(conn.pending_len);
    conn.pending_len = 0;
    return true;
}

/// Flushes the transport writer; a failure is sticky. Caller holds
/// `write_mutex` (or is the handshake).
fn flushTransport(conn: *Connection) error{TransportWriteFailed}!void {
    conn.output.flush() catch {
        conn.write_failed = true;
        return error.TransportWriteFailed;
    };
}

fn bumpReadProgress(conn: *Connection) void {
    conn.read_progress +%= 1;
    conn.read_progress_cond.broadcast(conn.io);
}

/// The sticky TLS-layer failure, if any.
pub fn failure(conn: *const Connection) ?TlsError {
    return conn.failed;
}

/// Details of the TLS failure. Valid until `deinit`; read it after an
/// operation has failed.
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
/// error queue is thread-local, so it is cleared before the call; if the
/// call failed, `classifyFailure` must run before the next suspension
/// point.
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
    // SSL_shutdown returns 0 when close_notify was sent but the peer's has
    // not arrived yet; that is success for us.
    const ok = rc > 0 or (op == .shutdown and rc == 0);
    const code = if (ok) c.SSL_ERROR_NONE else c.SSL_get_error(conn.ssl, rc);
    const result: CallResult = .{
        .code = code,
        .bytes = n,
        .consumed = conn.bio_in_used,
        .produced = conn.bio_out_used,
    };
    conn.bio_in = &.{};
    conn.bio_out = &.{};
    // Nothing to inspect on success or WANT_*; don't leave anything behind
    // on this OS thread.
    if (code != c.SSL_ERROR_SSL and code != c.SSL_ERROR_SYSCALL) c.ERR_clear_error();
    return result;
}

/// Records a failure decided by us rather than by libssl. Caller holds
/// `ssl_mutex` (or is the handshake).
fn setFailed(conn: *Connection, err: TlsError, detail: []const u8) TlsError {
    conn.failed = err;
    conn.diag.detail = detail;
    conn.diag.not_tls = conn.tracker.not_tls;
    return err;
}

/// Turns the state left by a failed libssl call (error queue, verify and
/// info callbacks, record tracker) into a sticky `TlsError`, and clears the
/// error queue. Caller holds `ssl_mutex` (or is the handshake).
fn classifyFailure(conn: *Connection, code: c_int) TlsError {
    defer c.ERR_clear_error();

    // The outermost SSL-library reason explains the failure; the last queue
    // entry is the best message. Shared reason codes (internal error,
    // allocation failure) can come from any library.
    var ssl_reason: ?c_int = null;
    var internal = false;
    var last: c_ulong = 0;
    while (true) {
        const e = c.ERR_get_error();
        if (e == 0) break;
        last = e;
        const reason = c.ERR_GET_REASON(e);
        if (c.ERR_GET_LIB(e) == c.ERR_LIB_SSL) ssl_reason = reason;
        if (isInternal(reason)) internal = true;
    }
    if (last != 0) {
        c.ERR_error_string_n(last, &conn.detail_buf, conn.detail_buf.len);
        conn.diag.detail = std.mem.sliceTo(&conn.detail_buf, 0);
    } else {
        conn.diag.detail = if (code == c.SSL_ERROR_SYSCALL) "libssl reported a system error" else "libssl failed without a reason";
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
            conn.diag.detail = std.mem.span(c.X509_verify_cert_error_string(ve.code));
            break :blk error.CertificateRejected;
        }
        if (internal or conn.diag.alert_sent == .internal_error) break :blk error.Internal;
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
        break :blk error.ProtocolViolation;
    };
    conn.failed = err;
    return err;
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
        "SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED",
        "SSL_R_DH_KEY_TOO_SMALL",
    };
    inline for (names) |name| {
        if (@hasDecl(c, name) and reason == @field(c, name)) return true;
    }
    return false;
}

fn isInternal(reason: c_int) bool {
    // OpenSSL 3 raises internal failures with the shared ERR_R_* reasons;
    // SSL_R_INTERNAL_ERROR is BoringSSL's spelling.
    const names = .{
        "ERR_R_INTERNAL_ERROR",
        "ERR_R_MALLOC_FAILURE",
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

// Callbacks. libssl calls these synchronously inside `call`, with
// `ssl_mutex` held; none of them may suspend.

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

var bio_method: std.atomic.Value(?*c.BIO_METHOD) = .init(null);

/// The process-wide BIO method, created on first use and never freed:
/// BIO type indexes are a finite, process-global resource.
pub fn bioMethod() error{OutOfMemory}!*c.BIO_METHOD {
    if (bio_method.load(.acquire)) |m| return m;
    const index = c.BIO_get_new_index();
    if (index == -1) return error.OutOfMemory;
    const m = c.BIO_meth_new(index | c.BIO_TYPE_SOURCE_SINK, "anytls") orelse return error.OutOfMemory;
    if (c.BIO_meth_set_read(m, bioRead) != 1 or
        c.BIO_meth_set_write(m, bioWrite) != 1 or
        c.BIO_meth_set_ctrl(m, bioCtrl) != 1 or
        c.BIO_meth_set_create(m, bioCreate) != 1)
    {
        c.BIO_meth_free(m);
        return error.OutOfMemory;
    }
    if (bio_method.cmpxchgStrong(null, m, .acq_rel, .acquire)) |existing| {
        c.BIO_meth_free(m);
        return existing.?;
    }
    return m;
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

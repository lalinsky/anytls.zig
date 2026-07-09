const std = @import("std");
const Io = std.Io;
const c = @import("c");
const common = @import("common.zig");

pub const Error = common.InitError || common.HandshakeError;

pub fn client(io: Io, input: *Io.Reader, output: *Io.Writer, opt: common.config.Client) Error!Connection {
    _ = io; // OpenSSL uses its own RNG and clock.
    var conn = try initClient(input, output, opt);
    errdefer conn.deinit();
    try conn.handshake();
    return conn;
}

pub fn server(io: Io, input: *Io.Reader, output: *Io.Writer, opt: common.config.Server) Error!Connection {
    _ = io;
    var alpn_wire_buf: [max_alpn_wire_len]u8 = undefined;
    const alpn_wire = try alpnWireFormat(&alpn_wire_buf, opt.alpn_protocols);

    var conn = try initServer(input, output, opt);
    errdefer conn.deinit();

    // The callback fires inside SSL_do_handshake during conn.handshake()
    // below, never after (TLS 1.3, and renegotiation is disabled), so
    // stack-local state is safe here.
    var alpn_ctx: AlpnSelectCtx = .{ .wire = alpn_wire };
    if (alpn_wire.len > 0) c.SSL_CTX_set_alpn_select_cb(conn.ctx, alpnSelect, &alpn_ctx);

    try conn.handshake();
    return conn;
}

pub const Connection = struct {
    ssl: *c.SSL,
    ctx: *c.SSL_CTX,
    rbio: *c.BIO,
    wbio: *c.BIO,
    input: *Io.Reader,
    output: *Io.Writer,

    /// Set once the peer's close_notify has been received.
    read_closed: bool = false,
    /// ALPN protocol negotiated during the handshake, null if none. Points
    /// into SSL-owned memory; valid until `deinit`.
    alpn_protocol: ?[]const u8 = null,

    /// The most recent failure; message in `errorMessage`.
    err: ?common.Failure = null,
    err_buf: [256]u8 = undefined,
    err_len: usize = 0,

    /// Cleartext fed to a single SSL_write call; bounds how much ciphertext
    /// can pile up in the wbio before it is moved to the transport (one TLS
    /// record).
    const max_cleartext_chunk = 16384;

    pub fn errorMessage(conn: *const Connection) []const u8 {
        return conn.err_buf[0..conn.err_len];
    }

    /// Frees libssl resources. Does not close the underlying transport.
    pub fn deinit(conn: *Connection) void {
        c.SSL_free(conn.ssl); // frees both BIOs
        c.SSL_CTX_free(conn.ctx);
        conn.* = undefined;
    }

    /// Drives the TLS handshake to completion. Called by `client`/`server`.
    pub fn handshake(conn: *Connection) common.HandshakeError!void {
        while (true) {
            c.ERR_clear_error();
            const rc = c.SSL_do_handshake(conn.ssl);
            if (rc == 1) {
                conn.moveOutgoing() catch return conn.failTransportWrite(error.WriteFailed);
                conn.output.flush() catch return conn.failTransportWrite(error.WriteFailed);
                conn.captureAlpn();
                return;
            }
            switch (c.SSL_get_error(conn.ssl, rc)) {
                c.SSL_ERROR_WANT_READ => {
                    conn.moveOutgoing() catch return conn.failTransportWrite(error.WriteFailed);
                    conn.fillIncoming() catch |fill_err| switch (fill_err) {
                        error.EndOfStream => {
                            conn.err = error.TlsTruncated;
                            return error.TlsHandshakeFailure;
                        },
                        error.ReadFailed => {
                            conn.err = error.TransportReadFailed;
                            return error.ReadFailed;
                        },
                        error.WriteFailed => return conn.failTransportWrite(error.WriteFailed),
                    };
                },
                c.SSL_ERROR_WANT_WRITE => {
                    conn.moveOutgoing() catch return conn.failTransportWrite(error.WriteFailed);
                },
                else => {
                    const verify_failed = conn.captureVerifyFailure();
                    if (!verify_failed) conn.captureSslError();
                    // Best effort: deliver the fatal alert to the peer.
                    conn.moveOutgoing() catch {};
                    conn.output.flush() catch {};
                    return if (verify_failed)
                        error.CertificateVerificationFailure
                    else
                        error.TlsHandshakeFailure;
                },
            }
        }
    }

    /// Reads decrypted data into `buffer`. Returns the number of bytes read;
    /// 0 means the peer closed the connection cleanly (close_notify
    /// received). A transport end of stream without close_notify is reported
    /// as `error.ReadFailed` with `err == error.TlsTruncated`.
    pub fn read(conn: *Connection, buffer: []u8) error{ReadFailed}!usize {
        if (buffer.len == 0 or conn.read_closed) return 0;
        while (true) {
            c.ERR_clear_error();
            var n: usize = 0;
            const rc = c.SSL_read_ex(conn.ssl, buffer.ptr, buffer.len, &n);
            if (rc == 1) {
                // TLS 1.3 reads can produce output (session tickets,
                // KeyUpdate responses); park it in the transport buffer.
                conn.moveOutgoing() catch return conn.failTransportWrite(error.ReadFailed);
                return n;
            }
            switch (c.SSL_get_error(conn.ssl, rc)) {
                c.SSL_ERROR_ZERO_RETURN => {
                    conn.read_closed = true;
                    return 0;
                },
                c.SSL_ERROR_WANT_READ => {
                    conn.moveOutgoing() catch return conn.failTransportWrite(error.ReadFailed);
                    conn.fillIncoming() catch |fill_err| switch (fill_err) {
                        error.EndOfStream => {
                            conn.err = error.TlsTruncated;
                            return error.ReadFailed;
                        },
                        error.ReadFailed => {
                            conn.err = error.TransportReadFailed;
                            return error.ReadFailed;
                        },
                        error.WriteFailed => return conn.failTransportWrite(error.ReadFailed),
                    };
                },
                c.SSL_ERROR_WANT_WRITE => {
                    conn.moveOutgoing() catch return conn.failTransportWrite(error.ReadFailed);
                },
                else => {
                    conn.captureSslError();
                    return error.ReadFailed;
                },
            }
        }
    }

    /// Encrypts and sends `bytes`, flushing the transport.
    pub fn writeAll(conn: *Connection, bytes: []const u8) error{WriteFailed}!void {
        try conn.encryptAll(bytes);
        conn.output.flush() catch return conn.failTransportWrite(error.WriteFailed);
    }

    /// Sends close_notify and flushes the transport. Does not wait for the
    /// peer's close_notify. Does not close the underlying transport.
    pub fn close(conn: *Connection) error{WriteFailed}!void {
        c.ERR_clear_error();
        _ = c.SSL_shutdown(conn.ssl);
        conn.moveOutgoing() catch return conn.failTransportWrite(error.WriteFailed);
        conn.output.flush() catch return conn.failTransportWrite(error.WriteFailed);
    }

    /// Encrypts `bytes` into the transport writer buffer without flushing
    /// the transport, one TLS record's worth of cleartext at a time.
    fn encryptAll(conn: *Connection, bytes: []const u8) error{WriteFailed}!void {
        var off: usize = 0;
        while (off < bytes.len) {
            const chunk = bytes[off..@min(bytes.len, off + max_cleartext_chunk)];
            c.ERR_clear_error();
            var written: usize = 0;
            const rc = c.SSL_write_ex(conn.ssl, chunk.ptr, chunk.len, &written);
            if (rc == 1) {
                off += written;
                conn.moveOutgoing() catch return conn.failTransportWrite(error.WriteFailed);
                continue;
            }
            switch (c.SSL_get_error(conn.ssl, rc)) {
                c.SSL_ERROR_WANT_READ => {
                    // Post-handshake message (e.g. rekey) must be read first.
                    conn.moveOutgoing() catch return conn.failTransportWrite(error.WriteFailed);
                    conn.fillIncoming() catch |fill_err| {
                        conn.err = switch (fill_err) {
                            error.EndOfStream => error.TlsTruncated,
                            error.ReadFailed => error.TransportReadFailed,
                            error.WriteFailed => error.TransportWriteFailed,
                        };
                        return error.WriteFailed;
                    };
                },
                c.SSL_ERROR_WANT_WRITE => {
                    conn.moveOutgoing() catch return conn.failTransportWrite(error.WriteFailed);
                },
                else => {
                    conn.captureSslError();
                    return error.WriteFailed;
                },
            }
        }
    }

    /// Moves pending ciphertext from the wbio into the transport writer
    /// buffer. Does not flush the transport; flushing happens before
    /// blocking on reads and at operation boundaries so records batch up in
    /// the transport buffer.
    fn moveOutgoing(conn: *Connection) Io.Writer.Error!void {
        while (true) {
            const pending = c.BIO_ctrl_pending(conn.wbio);
            if (pending == 0) return;
            const dest = try conn.output.writableSliceGreedy(1);
            const len: c_int = @intCast(@min(dest.len, pending, std.math.maxInt(c_int)));
            const n = c.BIO_read(conn.wbio, dest.ptr, len);
            if (n <= 0) return;
            conn.output.advance(@intCast(n));
        }
    }

    /// Feeds ciphertext from the transport into the rbio, suspending if
    /// nothing is buffered. Flushes the transport writer first so the peer
    /// can make the progress we are about to wait for.
    fn fillIncoming(conn: *Connection) error{ ReadFailed, WriteFailed, EndOfStream }!void {
        try conn.output.flush();
        if (conn.input.bufferedLen() == 0) try conn.input.fillMore();
        const data = conn.input.buffered();
        const len: c_int = @intCast(@min(data.len, std.math.maxInt(c_int)));
        const n = c.BIO_write(conn.rbio, data.ptr, len);
        if (n > 0) conn.input.toss(@intCast(n));
    }

    /// Captures the OpenSSL error queue into `err_buf`. Must be called
    /// immediately after the failing `SSL_*` call, before any transport I/O:
    /// a suspension may migrate the fiber to another OS thread, and the
    /// error queue is thread-local.
    fn captureSslError(conn: *Connection) void {
        conn.err = error.TlsFailure;
        const e = c.ERR_get_error();
        if (e != 0) {
            c.ERR_error_string_n(e, &conn.err_buf, conn.err_buf.len);
            conn.err_len = std.mem.indexOfScalar(u8, &conn.err_buf, 0) orelse conn.err_buf.len;
        } else {
            conn.err_len = 0;
        }
        c.ERR_clear_error();
    }

    /// If the handshake failed due to peer certificate verification, records
    /// the human-readable verify result and returns true.
    fn captureVerifyFailure(conn: *Connection) bool {
        const vr = c.SSL_get_verify_result(conn.ssl);
        if (vr == c.X509_V_OK) return false;
        conn.err = error.TlsFailure;
        const msg = std.mem.span(c.X509_verify_cert_error_string(vr));
        const n = @min(msg.len, conn.err_buf.len);
        @memcpy(conn.err_buf[0..n], msg[0..n]);
        conn.err_len = n;
        c.ERR_clear_error();
        return true;
    }

    fn failTransportWrite(conn: *Connection, comptime err: anytype) @TypeOf(err) {
        conn.err = error.TransportWriteFailed;
        return err;
    }

    fn captureAlpn(conn: *Connection) void {
        var data: [*c]const u8 = null;
        var len: c_uint = 0;
        c.SSL_get0_alpn_selected(conn.ssl, &data, &len);
        if (len > 0) conn.alpn_protocol = data[0..len];
    }
};

fn initClient(input: *Io.Reader, output: *Io.Writer, opt: common.config.Client) common.InitError!Connection {
    const ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse return error.TlsInitFailure;
    errdefer c.SSL_CTX_free(ctx);
    try commonCtxSetup(ctx);

    switch (opt.root_ca) {
        .system => if (c.SSL_CTX_set_default_verify_paths(ctx) != 1) return error.TlsInitFailure,
        .pem => |pem| try addTrustedCerts(ctx, pem),
        .none => {},
    }
    c.SSL_CTX_set_verify(ctx, if (opt.insecure_skip_verify) c.SSL_VERIFY_NONE else c.SSL_VERIFY_PEER, null);
    if (opt.auth) |kp| try useCertKeyPair(ctx, kp);

    const parts = try newSslWithMemBios(ctx);
    const ssl = parts.ssl;
    errdefer c.SSL_free(ssl);

    if (opt.host.len > 0) {
        // Max DNS name length is 253; OpenSSL copies the string.
        if (opt.host.len > 253) return error.HostTooLong;
        var host_z: [254]u8 = undefined;
        @memcpy(host_z[0..opt.host.len], opt.host);
        host_z[opt.host.len] = 0;
        const host_ptr: [*:0]u8 = host_z[0..opt.host.len :0];
        if (c.SSL_set_tlsext_host_name(ssl, host_ptr) != 1) return error.TlsInitFailure;
        if (!opt.insecure_skip_verify) {
            if (c.SSL_set1_host(ssl, host_ptr) != 1) return error.TlsInitFailure;
        }
    }

    if (opt.alpn_protocols.len > 0) {
        var wire_buf: [max_alpn_wire_len]u8 = undefined;
        const wire = try alpnWireFormat(&wire_buf, opt.alpn_protocols);
        // Note inverted convention: 0 is success.
        if (c.SSL_set_alpn_protos(ssl, wire.ptr, @intCast(wire.len)) != 0) return error.TlsInitFailure;
    }

    c.SSL_set_connect_state(ssl);
    return .{
        .ssl = ssl,
        .ctx = ctx,
        .rbio = parts.rbio,
        .wbio = parts.wbio,
        .input = input,
        .output = output,
    };
}

fn initServer(input: *Io.Reader, output: *Io.Writer, opt: common.config.Server) common.InitError!Connection {
    const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return error.TlsInitFailure;
    errdefer c.SSL_CTX_free(ctx);
    try commonCtxSetup(ctx);
    try useCertKeyPair(ctx, opt.auth);

    if (opt.client_auth) |ca| {
        switch (ca.root_ca) {
            .system => if (c.SSL_CTX_set_default_verify_paths(ctx) != 1) return error.TlsInitFailure,
            .pem => |pem| try addTrustedCerts(ctx, pem),
            .none => {},
        }
        const mode = c.SSL_VERIFY_PEER | switch (ca.auth_type) {
            .require => c.SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
            .request => 0,
        };
        c.SSL_CTX_set_verify(ctx, mode, null);
    }

    const parts = try newSslWithMemBios(ctx);
    c.SSL_set_accept_state(parts.ssl);
    return .{
        .ssl = parts.ssl,
        .ctx = ctx,
        .rbio = parts.rbio,
        .wbio = parts.wbio,
        .input = input,
        .output = output,
    };
}

fn commonCtxSetup(ctx: *c.SSL_CTX) common.InitError!void {
    if (c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_2_VERSION) != 1) return error.TlsInitFailure;
    // Partial writes map SSL_write_ex results onto Io.Writer.drain semantics.
    _ = c.SSL_CTX_set_mode(ctx, c.SSL_MODE_ENABLE_PARTIAL_WRITE | c.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    // No renegotiation: guarantees no handshake callbacks after the
    // handshake, and no surprise WANT_READ storms mid-stream on TLS 1.2.
    // (The translated SSL_OP_BIT macro doesn't compile, so spell the
    // constant out; value verified against openssl/ssl.h.)
    const ssl_op_no_renegotiation: u64 = 1 << 30;
    _ = c.SSL_CTX_set_options(ctx, ssl_op_no_renegotiation);
}

const SslParts = struct {
    ssl: *c.SSL,
    rbio: *c.BIO,
    wbio: *c.BIO,
};

fn newSslWithMemBios(ctx: *c.SSL_CTX) common.InitError!SslParts {
    const ssl = c.SSL_new(ctx) orelse return error.TlsInitFailure;
    errdefer c.SSL_free(ssl);
    const rbio = c.BIO_new(c.BIO_s_mem()) orelse return error.TlsInitFailure;
    const wbio = c.BIO_new(c.BIO_s_mem()) orelse {
        _ = c.BIO_free(rbio);
        return error.TlsInitFailure;
    };
    // An empty rbio must report "retry" (=> SSL_ERROR_WANT_READ), not EOF.
    _ = c.BIO_set_mem_eof_return(rbio, -1);
    _ = c.BIO_set_mem_eof_return(wbio, -1);
    c.SSL_set_bio(ssl, rbio, wbio); // ssl now owns both BIOs
    return .{ .ssl = ssl, .rbio = rbio, .wbio = wbio };
}

/// Parses PEM certificates and adds them as trust anchors.
fn addTrustedCerts(ctx: *c.SSL_CTX, pem: []const u8) common.InitError!void {
    const store = c.SSL_CTX_get_cert_store(ctx) orelse return error.TlsInitFailure;
    const bio = c.BIO_new_mem_buf(pem.ptr, @intCast(pem.len)) orelse return error.TlsInitFailure;
    defer _ = c.BIO_free(bio);
    var count: usize = 0;
    while (c.PEM_read_bio_X509(bio, null, null, null)) |x| {
        defer c.X509_free(x); // the store takes its own reference
        if (c.X509_STORE_add_cert(store, x) != 1) {
            c.ERR_clear_error();
            return error.InvalidCertificate;
        }
        count += 1;
    }
    // The read loop always ends with PEM_R_NO_START_LINE in the queue.
    c.ERR_clear_error();
    if (count == 0) return error.InvalidCertificate;
}

/// Loads a PEM certificate chain (leaf first) and private key into the context.
fn useCertKeyPair(ctx: *c.SSL_CTX, kp: common.config.CertKeyPair) common.InitError!void {
    {
        const bio = c.BIO_new_mem_buf(kp.cert_pem.ptr, @intCast(kp.cert_pem.len)) orelse
            return error.TlsInitFailure;
        defer _ = c.BIO_free(bio);
        const leaf = c.PEM_read_bio_X509(bio, null, null, null) orelse {
            c.ERR_clear_error();
            return error.InvalidCertificate;
        };
        defer c.X509_free(leaf); // SSL_CTX takes its own reference
        if (c.SSL_CTX_use_certificate(ctx, leaf) != 1) {
            c.ERR_clear_error();
            return error.InvalidCertificate;
        }
        while (c.PEM_read_bio_X509(bio, null, null, null)) |inter| {
            // On success ownership moves to the SSL_CTX.
            if (c.SSL_CTX_add_extra_chain_cert(ctx, inter) != 1) {
                c.X509_free(inter);
                c.ERR_clear_error();
                return error.InvalidCertificate;
            }
        }
        c.ERR_clear_error();
    }
    {
        const bio = c.BIO_new_mem_buf(kp.key_pem.ptr, @intCast(kp.key_pem.len)) orelse
            return error.TlsInitFailure;
        defer _ = c.BIO_free(bio);
        const key = c.PEM_read_bio_PrivateKey(bio, null, null, null) orelse {
            c.ERR_clear_error();
            return error.InvalidPrivateKey;
        };
        defer c.EVP_PKEY_free(key); // SSL_CTX takes its own reference
        if (c.SSL_CTX_use_PrivateKey(ctx, key) != 1) {
            c.ERR_clear_error();
            return error.InvalidPrivateKey;
        }
    }
    if (c.SSL_CTX_check_private_key(ctx) != 1) {
        c.ERR_clear_error();
        return error.InvalidPrivateKey;
    }
}

/// ALPN wire format: length-prefixed protocol names, concatenated.
const max_alpn_wire_len = 256;

fn alpnWireFormat(buf: []u8, protocols: []const []const u8) error{AlpnProtocolsTooLong}![]const u8 {
    var i: usize = 0;
    for (protocols) |proto| {
        if (proto.len == 0 or proto.len > 255) return error.AlpnProtocolsTooLong;
        if (i + 1 + proto.len > buf.len) return error.AlpnProtocolsTooLong;
        buf[i] = @intCast(proto.len);
        @memcpy(buf[i + 1 ..][0..proto.len], proto);
        i += 1 + proto.len;
    }
    return buf[0..i];
}

const AlpnSelectCtx = struct {
    wire: []const u8,
};

fn alpnSelect(
    ssl: ?*c.SSL,
    out: [*c][*c]const u8,
    outlen: [*c]u8,
    in: [*c]const u8,
    inlen: c_uint,
    arg: ?*anyopaque,
) callconv(.c) c_int {
    _ = ssl;
    const alpn_ctx: *const AlpnSelectCtx = @ptrCast(@alignCast(arg.?));
    var selected: [*c]u8 = null;
    var selected_len: u8 = 0;
    // Server list first: negotiates in server preference order.
    const rc = c.SSL_select_next_proto(
        &selected,
        &selected_len,
        alpn_ctx.wire.ptr,
        @intCast(alpn_ctx.wire.len),
        in,
        inlen,
    );
    if (rc != c.OPENSSL_NPN_NEGOTIATED) return c.SSL_TLSEXT_ERR_ALERT_FATAL;
    out.* = selected;
    outlen.* = selected_len;
    return c.SSL_TLSEXT_ERR_OK;
}

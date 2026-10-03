//! OpenSSL contexts: one `SSL_CTX` per configuration, shared by every
//! connection created from it.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const c = @import("c");
const api = @import("../api.zig");
const Connection = @import("Connection.zig");

const ConfigError = api.ConfigError;
const ConfigDiagnostics = api.ConfigDiagnostics;

/// State shared by client and server contexts. Connections point at it, so
/// a context must not move or be deinitialized while connections exist.
pub const Shared = struct {
    gpa: Allocator,
    ssl_ctx: *c.SSL_CTX,
    bio_method: *c.BIO_METHOD,
    /// Server ALPN preference list in wire format; the select callback's arg.
    alpn_select: ?*AlpnSelect = null,
    /// Client: verify the server's name.
    verify_name: bool = false,
    /// Live connections, counted in safe builds to catch a context being
    /// deinitialized too early.
    live: if (std.debug.runtime_safety) std.atomic.Value(u32) else void =
        if (std.debug.runtime_safety) .init(0) else {},

    fn init(gpa: Allocator, method: ?*const c.SSL_METHOD) ConfigError!Shared {
        const ssl_ctx = c.SSL_CTX_new(method) orelse return error.OutOfMemory;
        errdefer c.SSL_CTX_free(ssl_ctx);
        const bio_method = try Connection.newBioMethod();
        errdefer c.BIO_meth_free(bio_method);

        if (c.SSL_CTX_set_min_proto_version(ssl_ctx, c.TLS1_2_VERSION) != 1) return error.Unsupported;
        _ = c.SSL_CTX_set_mode(ssl_ctx, c.SSL_MODE_ENABLE_PARTIAL_WRITE | c.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        // SSL_OP_NO_RENEGOTIATION; the translated SSL_OP_BIT macro does not
        // compile, so the value (bit 30) is spelled out.
        _ = c.SSL_CTX_set_options(ssl_ctx, @as(u64, 1) << 30);
        c.SSL_CTX_set_info_callback(ssl_ctx, Connection.infoCallback);

        return .{ .gpa = gpa, .ssl_ctx = ssl_ctx, .bio_method = bio_method };
    }

    fn deinit(s: *Shared) void {
        if (std.debug.runtime_safety) {
            const live = s.live.load(.monotonic);
            if (live != 0) std.log.scoped(.anytls).err("context deinitialized with {d} live connection(s)", .{live});
        }
        c.SSL_CTX_free(s.ssl_ctx);
        c.BIO_meth_free(s.bio_method);
        if (s.alpn_select) |a| s.gpa.destroy(a);
        s.* = undefined;
    }
};

pub const ClientContext = struct {
    shared: Shared,

    pub fn init(gpa: Allocator, io: Io, opt: api.ClientOptions, diag: ?*ConfigDiagnostics) ConfigError!ClientContext {
        var scratch: ConfigDiagnostics = .{};
        const d = diag orelse &scratch;
        d.len = 0;

        var shared = try Shared.init(gpa, c.TLS_client_method());
        errdefer shared.deinit();
        const ctx = shared.ssl_ctx;

        switch (opt.verify) {
            .full => {
                try loadCa(ctx, gpa, io, opt.ca, d);
                c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, Connection.verifyCallback);
                shared.verify_name = true;
            },
            .insecure_no_verify => c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null),
        }
        if (opt.certificate) |cert| try loadCertificate(ctx, gpa, io, cert, d);
        if (opt.alpn.len > 0) {
            var buf: [api.max_alpn_wire_len]u8 = undefined;
            const wire = try api.alpnWireFormat(&buf, opt.alpn);
            // Inverted convention: 0 is success.
            if (c.SSL_CTX_set_alpn_protos(ctx, wire.ptr, @intCast(wire.len)) != 0) return error.OutOfMemory;
        }
        return .{ .shared = shared };
    }

    pub fn deinit(ctx: *ClientContext) void {
        ctx.shared.deinit();
    }
};

pub const ServerContext = struct {
    shared: Shared,

    pub fn init(gpa: Allocator, io: Io, opt: api.ServerOptions, diag: ?*ConfigDiagnostics) ConfigError!ServerContext {
        var scratch: ConfigDiagnostics = .{};
        const d = diag orelse &scratch;
        d.len = 0;

        var shared = try Shared.init(gpa, c.TLS_server_method());
        errdefer shared.deinit();
        const ctx = shared.ssl_ctx;

        try loadCertificate(ctx, gpa, io, opt.certificate, d);

        if (opt.client_auth) |auth| {
            try loadCa(ctx, gpa, io, auth.ca, d);
            const mode = c.SSL_VERIFY_PEER | switch (auth.mode) {
                .require => c.SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                .request => 0,
            };
            c.SSL_CTX_set_verify(ctx, mode, Connection.verifyCallback);
        }

        // Session tickets are on by default. Resumption on a context that
        // verifies client certificates fails without a session id context.
        const sid = "anytls";
        if (c.SSL_CTX_set_session_id_context(ctx, sid, sid.len) != 1) return error.OutOfMemory;

        if (opt.alpn.len > 0) {
            const a = try gpa.create(AlpnSelect);
            a.len = (try api.alpnWireFormat(&a.buf, opt.alpn)).len;
            shared.alpn_select = a;
            c.SSL_CTX_set_alpn_select_cb(ctx, alpnSelect, a);
        }
        return .{ .shared = shared };
    }

    pub fn deinit(ctx: *ServerContext) void {
        ctx.shared.deinit();
    }
};

const AlpnSelect = struct {
    buf: [api.max_alpn_wire_len]u8,
    len: usize,
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
    const a: *const AlpnSelect = @ptrCast(@alignCast(arg.?));
    var selected: [*c]u8 = null;
    var selected_len: u8 = 0;
    // Server list first: negotiates in server preference order.
    const rc = c.SSL_select_next_proto(&selected, &selected_len, &a.buf, @intCast(a.len), in, inlen);
    if (rc != c.OPENSSL_NPN_NEGOTIATED) return c.SSL_TLSEXT_ERR_ALERT_FATAL;
    out.* = selected;
    outlen.* = selected_len;
    return c.SSL_TLSEXT_ERR_OK;
}

// Loading

const max_file_size = 16 * 1024 * 1024;

/// Bytes of a `Source`; owned (and freed by `deinit`) when read from a file.
const Loaded = struct {
    bytes: []const u8,
    owned: bool,

    fn deinit(l: Loaded, gpa: Allocator) void {
        if (l.owned) gpa.free(l.bytes);
    }
};

fn readSource(gpa: Allocator, io: Io, src: api.Source, d: *ConfigDiagnostics) ConfigError!Loaded {
    return switch (src) {
        .pem => |pem| .{ .bytes = pem, .owned = false },
        .file => |path| .{ .bytes = try readFile(gpa, io, Io.Dir.cwd(), path, d), .owned = true },
    };
}

fn readFile(gpa: Allocator, io: Io, dir: Io.Dir, path: []const u8, d: *ConfigDiagnostics) ConfigError![]u8 {
    return dir.readFileAlloc(io, path, gpa, .limited(max_file_size)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Canceled => return error.Canceled,
        else => {
            d.set("{s}: {t}", .{ path, err });
            return error.FileUnreadable;
        },
    };
}

fn loadCertificate(ctx: *c.SSL_CTX, gpa: Allocator, io: Io, src: api.CertificateSource, d: *ConfigDiagnostics) ConfigError!void {
    const chain = try readSource(gpa, io, src.chain, d);
    defer chain.deinit(gpa);
    const key = try readSource(gpa, io, src.key, d);
    defer key.deinit(gpa);

    {
        const bio = try memBio(chain.bytes);
        defer _ = c.BIO_free(bio);
        const leaf = c.PEM_read_bio_X509(bio, null, null, null) orelse
            return sslFailure(d, "certificate", error.InvalidCertificate);
        defer c.X509_free(leaf); // the SSL_CTX takes its own reference
        if (c.SSL_CTX_use_certificate(ctx, leaf) != 1)
            return sslFailure(d, "certificate", error.InvalidCertificate);
        while (c.PEM_read_bio_X509(bio, null, null, null)) |intermediate| {
            // On success ownership moves to the SSL_CTX.
            if (c.SSL_CTX_add_extra_chain_cert(ctx, intermediate) != 1) {
                c.X509_free(intermediate);
                return sslFailure(d, "certificate chain", error.InvalidCertificate);
            }
        }
        if (!endOfPem()) return sslFailure(d, "certificate chain", error.InvalidCertificate);
    }
    {
        const bio = try memBio(key.bytes);
        defer _ = c.BIO_free(bio);
        // A password callback that refuses: the default one prompts on the
        // terminal for encrypted keys.
        const pkey = c.PEM_read_bio_PrivateKey(bio, null, noPassword, null) orelse
            return sslFailure(d, "private key", error.InvalidPrivateKey);
        defer c.EVP_PKEY_free(pkey); // the SSL_CTX takes its own reference
        if (c.SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
            // libssl checks the key against the certificate here already.
            const e = c.ERR_peek_last_error();
            const mismatch = c.ERR_GET_LIB(e) == c.ERR_LIB_X509 and
                (c.ERR_GET_REASON(e) == c.X509_R_KEY_VALUES_MISMATCH or c.ERR_GET_REASON(e) == c.X509_R_KEY_TYPE_MISMATCH);
            return sslFailure(d, "private key", if (mismatch) error.KeyMismatch else error.InvalidPrivateKey);
        }
    }
    if (c.SSL_CTX_check_private_key(ctx) != 1)
        return sslFailure(d, "private key", error.KeyMismatch);
}

fn noPassword(buf: [*c]u8, size: c_int, rwflag: c_int, userdata: ?*anyopaque) callconv(.c) c_int {
    _ = .{ buf, size, rwflag, userdata };
    return 0;
}

fn loadCa(ctx: *c.SSL_CTX, gpa: Allocator, io: Io, src: api.CaSource, d: *ConfigDiagnostics) ConfigError!void {
    const store = c.SSL_CTX_get_cert_store(ctx) orelse return error.OutOfMemory;
    switch (src) {
        .none => {},
        .pem => |pem| if (try addPemCerts(store, pem, d) == 0) return noCaCerts(d, "PEM"),
        .file => |path| {
            const bytes = try readFile(gpa, io, Io.Dir.cwd(), path, d);
            defer gpa.free(bytes);
            if (try addPemCerts(store, bytes, d) == 0) return noCaCerts(d, path);
        },
        .dir => |path| {
            var dir = Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => {
                    d.set("{s}: {t}", .{ path, err });
                    return error.FileUnreadable;
                },
            };
            defer dir.close(io);
            var count: usize = 0;
            var it = dir.iterate();
            while (it.next(io) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => {
                    d.set("{s}: {t}", .{ path, err });
                    return error.FileUnreadable;
                },
            }) |entry| {
                switch (entry.kind) {
                    .file, .sym_link => {},
                    else => continue,
                }
                const bytes = try readFile(gpa, io, dir, entry.name, d);
                defer gpa.free(bytes);
                // Files without certificates (READMEs, CRLs) are skipped.
                count += addPemCerts(store, bytes, d) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => 0,
                };
            }
            if (count == 0) return noCaCerts(d, path);
        },
        .system => try loadSystemCa(store, gpa, io, d),
    }
}

fn noCaCerts(d: *ConfigDiagnostics, what: []const u8) ConfigError {
    d.set("{s}: no CA certificates found", .{what});
    return error.InvalidCaCertificates;
}

/// Adds every PEM certificate in `pem` to `store`; returns how many.
fn addPemCerts(store: *c.X509_STORE, pem: []const u8, d: *ConfigDiagnostics) ConfigError!usize {
    const bio = try memBio(pem);
    defer _ = c.BIO_free(bio);
    var count: usize = 0;
    while (c.PEM_read_bio_X509(bio, null, null, null)) |cert| {
        defer c.X509_free(cert); // the store takes its own reference
        if (c.X509_STORE_add_cert(store, cert) != 1)
            return sslFailure(d, "CA certificate", error.InvalidCaCertificates);
        count += 1;
    }
    if (!endOfPem()) return sslFailure(d, "CA certificate", error.InvalidCaCertificates);
    return count;
}

/// Uses the standard library's per-OS trust store discovery, then hands the
/// DER certificates to OpenSSL.
fn loadSystemCa(store: *c.X509_STORE, gpa: Allocator, io: Io, d: *ConfigDiagnostics) ConfigError!void {
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(gpa);
    bundle.rescan(gpa, io, Io.Clock.real.now(io)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Canceled => return error.Canceled,
        else => {
            d.set("system trust store: {t}", .{err});
            return error.CaUnavailable;
        },
    };
    var count: usize = 0;
    var it = bundle.map.valueIterator();
    while (it.next()) |start| {
        const der = bundle.bytes.items[start.*..];
        var p: [*c]const u8 = der.ptr;
        const cert = c.d2i_X509(null, &p, @intCast(der.len)) orelse continue;
        defer c.X509_free(cert);
        if (c.X509_STORE_add_cert(store, cert) == 1) count += 1;
    }
    c.ERR_clear_error();
    if (count == 0) {
        d.set("system trust store: no certificates found", .{});
        return error.CaUnavailable;
    }
}

fn memBio(bytes: []const u8) error{OutOfMemory}!*c.BIO {
    return c.BIO_new_mem_buf(bytes.ptr, @intCast(bytes.len)) orelse error.OutOfMemory;
}

/// After a PEM read loop ends: true if it ended because there were no more
/// PEM blocks, false if a block failed to parse. Clears the error queue.
fn endOfPem() bool {
    const e = c.ERR_peek_last_error();
    const ok = e == 0 or (c.ERR_GET_LIB(e) == c.ERR_LIB_PEM and c.ERR_GET_REASON(e) == c.PEM_R_NO_START_LINE);
    if (ok) c.ERR_clear_error();
    return ok;
}

/// Records the OpenSSL error queue in `d` and returns `err`.
fn sslFailure(d: *ConfigDiagnostics, what: []const u8, err: ConfigError) ConfigError {
    var buf: [200]u8 = undefined;
    const e = c.ERR_peek_last_error();
    if (e != 0) {
        c.ERR_error_string_n(e, &buf, buf.len);
        d.set("{s}: {s}", .{ what, std.mem.sliceTo(&buf, 0) });
    } else {
        d.set("{s}: invalid", .{what});
    }
    c.ERR_clear_error();
    return err;
}

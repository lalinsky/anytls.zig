//! tls.zig contexts: parsed certificates, keys and trust anchors, shared
//! read-only by every connection created from them.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const tls = @import("tls");
const api = @import("../api.zig");
const source = @import("../source.zig");

const ConfigError = api.ConfigError;
const ConfigDiagnostics = api.ConfigDiagnostics;
const Bundle = tls.config.cert.Bundle;

const max_client_alpn_len = @import("../root.zig").features.max_client_alpn_len;
const CertKeyPair = tls.config.CertKeyPair;

pub const ClientContext = struct {
    gpa: Allocator,
    root_ca: Bundle = .empty,
    verify: bool,
    auth: ?CertKeyPair = null,
    alpn: Alpn = .{},
    live: source.LiveCount = .{},

    pub fn init(gpa: Allocator, io: Io, opt: api.ClientOptions, diag: ?*ConfigDiagnostics) ConfigError!ClientContext {
        var scratch: ConfigDiagnostics = .{};
        const d = diag orelse &scratch;
        d.len = 0;

        var ctx: ClientContext = .{ .gpa = gpa, .verify = opt.verify == .full };
        errdefer ctx.free();
        if (ctx.verify) ctx.root_ca = try loadCa(gpa, io, opt.ca, d);
        if (opt.certificate) |cert| ctx.auth = try loadCertificate(gpa, io, cert, d);
        // tls.zig's client keeps the negotiated protocol in a 32-byte buffer.
        for (opt.alpn) |name| if (name.len > max_client_alpn_len) {
            d.set("ALPN protocol names longer than {d} bytes are not supported", .{max_client_alpn_len});
            return error.Unsupported;
        };
        ctx.alpn = try .init(gpa, opt.alpn);
        return ctx;
    }

    pub fn deinit(ctx: *ClientContext) void {
        ctx.live.check();
        ctx.free();
        ctx.* = undefined;
    }

    fn free(ctx: *ClientContext) void {
        ctx.root_ca.deinit(ctx.gpa);
        if (ctx.auth) |*kp| kp.deinit(ctx.gpa);
        ctx.alpn.deinit(ctx.gpa);
    }
};

pub const ServerContext = struct {
    gpa: Allocator,
    auth: CertKeyPair,
    client_auth: ?ClientAuth = null,
    alpn: Alpn = .{},
    live: source.LiveCount = .{},

    const ClientAuth = struct {
        root_ca: Bundle,
        mode: api.ClientAuth.Mode,
    };

    pub fn init(gpa: Allocator, io: Io, opt: api.ServerOptions, diag: ?*ConfigDiagnostics) ConfigError!ServerContext {
        var scratch: ConfigDiagnostics = .{};
        const d = diag orelse &scratch;
        d.len = 0;

        var auth = try loadCertificate(gpa, io, opt.certificate, d);
        errdefer auth.deinit(gpa);
        var client_auth: ?ClientAuth = null;
        if (opt.client_auth) |ca| client_auth = .{ .root_ca = try loadCa(gpa, io, ca.ca, d), .mode = ca.mode };
        errdefer if (client_auth) |*ca| ca.root_ca.deinit(gpa);
        return .{
            .gpa = gpa,
            .auth = auth,
            .client_auth = client_auth,
            .alpn = try .init(gpa, opt.alpn),
        };
    }

    pub fn deinit(ctx: *ServerContext) void {
        ctx.live.check();
        ctx.auth.deinit(ctx.gpa);
        if (ctx.client_auth) |*ca| ca.root_ca.deinit(ctx.gpa);
        ctx.alpn.deinit(ctx.gpa);
        ctx.* = undefined;
    }
};

/// ALPN protocol names owned by the context: tls.zig hands out the
/// negotiated protocol as a slice into this list.
const Alpn = struct {
    names: []const []const u8 = &.{},
    bytes: []u8 = &.{},

    fn init(gpa: Allocator, protocols: []const []const u8) ConfigError!Alpn {
        var wire: [api.max_alpn_wire_len]u8 = undefined;
        _ = try api.alpnWireFormat(&wire, protocols);
        var total: usize = 0;
        for (protocols) |p| total += p.len;
        const bytes = try gpa.alloc(u8, total);
        errdefer gpa.free(bytes);
        const names = try gpa.alloc([]const u8, protocols.len);
        var off: usize = 0;
        for (protocols, names) |p, *name| {
            @memcpy(bytes[off..][0..p.len], p);
            name.* = bytes[off..][0..p.len];
            off += p.len;
        }
        return .{ .names = names, .bytes = bytes };
    }

    fn deinit(a: *Alpn, gpa: Allocator) void {
        gpa.free(a.names);
        gpa.free(a.bytes);
        a.* = .{};
    }
};

fn loadCertificate(gpa: Allocator, io: Io, src: api.CertificateSource, d: *ConfigDiagnostics) ConfigError!CertKeyPair {
    const chain = try source.read(gpa, io, src.chain, d);
    defer chain.deinit(gpa);
    const key = try source.read(gpa, io, src.key, d);
    defer key.deinit(gpa);

    // The key only: tls.zig's own chain parsing drops expired certificates
    // (so the leaf may silently go missing) and leaks when it fails.
    var kp = CertKeyPair.fromSlice(gpa, io, "", key.bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            d.set("private key: {t}", .{err});
            return error.InvalidPrivateKey;
        },
    };
    errdefer kp.deinit(gpa);
    kp.bundle.deinit(gpa);
    kp.bundle = .empty;
    try loadChain(&kp.bundle, gpa, chain.bytes, d);
    try checkKeyMatches(&kp, d);
    return kp;
}

/// Puts the PEM chain into `bundle` exactly as given, leaf first. tls.zig
/// sends `bundle.bytes` as the chain and uses the map only for the count.
fn loadChain(bundle: *Bundle, gpa: Allocator, pem: []const u8, d: *ConfigDiagnostics) ConfigError!void {
    const Map = @FieldType(Bundle, "map");
    const MapContext = @typeInfo(@TypeOf(Map.putNoClobberContext)).@"fn".params[4].type.?;

    var blocks = PemBlocks{ .pem = pem };
    while (try blocks.next(bundle, gpa, d, "certificate")) |slice| {
        // Keyed by the whole certificate, so every certificate counts once.
        const gop = try bundle.map.getOrPutContext(gpa, slice, MapContext{ .cb = bundle });
        if (gop.found_existing) {
            bundle.bytes.items.len = slice.start; // the same certificate twice
        } else {
            gop.value_ptr.* = slice.start;
        }
    }
    if (bundle.map.count() == 0) {
        d.set("certificate: no certificate found", .{});
        return error.InvalidCertificate;
    }
}

/// Iterates PEM CERTIFICATE blocks, decoding each into `bundle.bytes` and
/// checking it is one DER element.
const PemBlocks = struct {
    pem: []const u8,
    pos: usize = 0,

    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";

    fn next(
        it: *PemBlocks,
        bundle: *Bundle,
        gpa: Allocator,
        d: *ConfigDiagnostics,
        comptime what: []const u8,
    ) ConfigError!?std.crypto.Certificate.der.Element.Slice {
        const err: ConfigError = if (comptime std.mem.eql(u8, what, "certificate")) error.InvalidCertificate else error.InvalidCaCertificates;
        const begin = std.mem.indexOfPos(u8, it.pem, it.pos, begin_marker) orelse return null;
        const start = begin + begin_marker.len;
        const end = std.mem.indexOfPos(u8, it.pem, start, end_marker) orelse {
            d.set(what ++ ": missing end marker", .{});
            return err;
        };
        it.pos = end + end_marker.len;

        const base64 = std.base64.standard.decoderWithIgnore(" \t\r\n");
        const encoded = it.pem[start..end];
        try bundle.bytes.ensureUnusedCapacity(gpa, base64.calcSizeUpperBound(encoded.len));
        const decoded_start: u32 = @intCast(bundle.bytes.items.len);
        const n = base64.decode(bundle.bytes.unusedCapacitySlice(), encoded) catch {
            d.set(what ++ ": invalid base64", .{});
            return err;
        };
        bundle.bytes.items.len += n;
        const elem = std.crypto.Certificate.der.Element.parse(bundle.bytes.items, decoded_start) catch {
            bundle.bytes.items.len = decoded_start;
            d.set(what ++ ": invalid DER", .{});
            return err;
        };
        if (elem.slice.end != bundle.bytes.items.len) {
            bundle.bytes.items.len = decoded_start;
            d.set(what ++ ": invalid DER", .{});
            return err;
        }
        return .{ .start = decoded_start, .end = elem.slice.end };
    }
};

/// tls.zig does not check that the key belongs to the certificate. Compare
/// the public keys where that is cheap (ECDSA); other key types, and leaves
/// std cannot parse, are not checked.
fn checkKeyMatches(kp: *const CertKeyPair, d: *ConfigDiagnostics) ConfigError!void {
    const pair = kp.ecdsa_key_pair orelse return;
    // loadChain put the leaf first.
    const leaf = std.crypto.Certificate.parse(.{ .buffer = kp.bundle.bytes.items, .index = 0 }) catch return;
    const matches = switch (pair) {
        inline else => |key_pair| blk: {
            const public = key_pair.public_key.toUncompressedSec1();
            break :blk std.mem.eql(u8, leaf.pubKey(), &public);
        },
    };
    if (!matches) {
        d.set("private key does not match the certificate", .{});
        return error.KeyMismatch;
    }
}

fn loadCa(gpa: Allocator, io: Io, src: api.CaSource, d: *ConfigDiagnostics) ConfigError!Bundle {
    var bundle: Bundle = .empty;
    errdefer bundle.deinit(gpa);
    const now = Io.Clock.real.now(io).toSeconds();
    switch (src) {
        .none => {},
        .pem => |pem| if (try addPem(&bundle, gpa, now, pem, d) == 0) return source.noCaCerts(d, "PEM"),
        .file => |path| {
            const bytes = try source.readFile(gpa, io, Io.Dir.cwd(), path, d);
            defer gpa.free(bytes);
            if (try addPem(&bundle, gpa, now, bytes, d) == 0) return source.noCaCerts(d, path);
        },
        .dir => |path| {
            const adder: PemAdder = .{ .bundle = &bundle, .gpa = gpa, .now = now, .d = d };
            if (try source.forEachFileInDir(gpa, io, path, d, adder, PemAdder.add) == 0)
                return source.noCaCerts(d, path);
        },
        .system => {
            bundle.rescan(gpa, io, Io.Clock.real.now(io)) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Canceled => return error.Canceled,
                else => {
                    d.set("system trust store: {t}", .{err});
                    return error.CaUnavailable;
                },
            };
            if (bundle.map.count() == 0) {
                d.set("system trust store: no certificates found", .{});
                return error.CaUnavailable;
            }
        },
    }
    return bundle;
}

const PemAdder = struct {
    bundle: *Bundle,
    gpa: Allocator,
    now: i64,
    d: *ConfigDiagnostics,

    fn add(a: PemAdder, bytes: []const u8) ConfigError!usize {
        return addPem(a.bundle, a.gpa, a.now, bytes, a.d);
    }
};

/// Adds the PEM certificates in `pem` to `bundle`; returns how many were
/// kept. Like std's own loading, expired certificates and a second
/// certificate with the same subject are dropped.
fn addPem(bundle: *Bundle, gpa: Allocator, now_sec: i64, pem: []const u8, d: *ConfigDiagnostics) ConfigError!usize {
    const before = bundle.map.count();
    var blocks = PemBlocks{ .pem = pem };
    while (try blocks.next(bundle, gpa, d, "CA certificate")) |slice| {
        bundle.parseCert(gpa, slice.start, now_sec) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                d.set("CA certificate: {t}", .{err});
                return error.InvalidCaCertificates;
            },
        };
    }
    return bundle.map.count() - before;
}

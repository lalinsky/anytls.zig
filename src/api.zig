//! Backend-independent types: options, error sets and diagnostics.
const std = @import("std");
const Io = std.Io;

/// Where to load a certificate chain or private key from.
pub const Source = union(enum) {
    /// Path to a PEM file, read through `std.Io` when the context is created.
    file: []const u8,
    /// PEM bytes.
    pem: []const u8,
};

/// Trust anchors used to verify the peer.
pub const CaSource = union(enum) {
    /// The operating system's trust store.
    system,
    /// Path to a PEM file with one or more certificates.
    file: []const u8,
    /// Path to a directory; every file in it is read and the PEM
    /// certificates found are added.
    dir: []const u8,
    /// PEM bytes with one or more certificates.
    pem: []const u8,
    /// No trust anchors; every peer certificate fails verification.
    none,
};

pub const CertificateSource = struct {
    /// PEM: leaf certificate first, then any intermediates.
    chain: Source,
    /// PEM private key for the leaf certificate.
    key: Source,
};

pub const Verify = enum {
    /// Verify the peer's certificate chain and, on the client, its name.
    full,
    /// Accept any peer certificate. For testing only.
    insecure_no_verify,
};

pub const ClientOptions = struct {
    ca: CaSource = .system,
    verify: Verify = .full,
    /// Client certificate, sent if the server requests one.
    certificate: ?CertificateSource = null,
    /// ALPN protocols to offer, e.g. "h2", "http/1.1".
    alpn: []const []const u8 = &.{},
};

pub const ClientAuth = struct {
    /// Trust anchors for client certificates.
    ca: CaSource,
    mode: Mode = .require,

    pub const Mode = enum {
        /// Ask for a certificate; accept a client that sends none.
        request,
        /// Ask for a certificate; reject a client that sends none.
        require,
    };
};

pub const ServerOptions = struct {
    certificate: CertificateSource,
    /// Request client certificates (mTLS).
    client_auth: ?ClientAuth = null,
    /// ALPN protocols in server preference order. If the client offers ALPN
    /// and there is no overlap, the handshake fails; if the client offers
    /// none, none is negotiated.
    alpn: []const []const u8 = &.{},
};

pub const ClientConnectionOptions = struct {
    /// Host name or IP literal of the server. Host names are sent as SNI and
    /// verified against the certificate; IP literals are verified against
    /// the certificate's IP addresses and not sent as SNI. Required unless
    /// the context uses `.insecure_no_verify`.
    server_name: []const u8,
};

/// Errors from creating a context. Details are in `ConfigDiagnostics`.
pub const ConfigError = error{
    /// Unparseable certificate PEM, or no certificate found.
    InvalidCertificate,
    /// Unparseable, unsupported or encrypted private key.
    InvalidPrivateKey,
    /// The private key does not belong to the leaf certificate.
    KeyMismatch,
    /// The CA source is unparseable or contains no certificate.
    InvalidCaCertificates,
    /// `.system` was requested but no trust store was found.
    CaUnavailable,
    /// A `.file`/`.dir` source could not be read.
    FileUnreadable,
    /// An ALPN protocol name is empty or the list is too long.
    InvalidAlpnProtocols,
    /// The selected backend does not support a requested option.
    Unsupported,
    Canceled,
    OutOfMemory,
};

/// Errors from creating a connection.
pub const ConnectionInitError = error{
    /// Peer verification is on but no server name was given.
    MissingServerName,
    /// The server name is too long or contains a NUL byte.
    InvalidServerName,
    OutOfMemory,
};

/// TLS-layer failures. Transport failures are never reported as one of
/// these; they surface as `error.ReadFailed`/`error.WriteFailed` with the
/// cause on the transport reader/writer.
pub const TlsError = error{
    /// The transport ended in the middle of a record, or during the
    /// handshake.
    ConnectionTruncated,
    /// The peer sent a fatal alert; `Diagnostics.alert_received` says which.
    AlertReceived,
    /// We rejected the peer's certificate; `Diagnostics.certificate` says
    /// why. On a server this is the client certificate.
    CertificateRejected,
    /// No common protocol version, cipher suite, group, signature algorithm
    /// or ALPN protocol.
    Incompatible,
    /// The peer violated the protocol, or is not speaking TLS at all
    /// (`Diagnostics.not_tls`).
    ProtocolViolation,
    /// A failure on our side (internal error, randomness, allocation inside
    /// the backend). `Diagnostics.detail` has the backend's message.
    Internal,
};

pub const HandshakeError = TlsError || error{ ReadFailed, WriteFailed };

/// TLS alert descriptions (RFC 8446 section 6, plus older ones).
pub const Alert = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    decryption_failed = 21,
    record_overflow = 22,
    decompression_failure = 30,
    handshake_failure = 40,
    no_certificate = 41,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    export_restriction = 60,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    inappropriate_fallback = 86,
    user_canceled = 90,
    no_renegotiation = 100,
    missing_extension = 109,
    unsupported_extension = 110,
    certificate_unobtainable = 111,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    bad_certificate_hash_value = 114,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,
    _,
};

pub const CertificateProblem = struct {
    reason: Reason,
    /// Position in the chain, 0 being the leaf. Null if unknown.
    depth: ?u8 = null,

    pub const Reason = enum {
        /// Unknown issuer, self-signed, or incomplete chain.
        untrusted,
        /// Valid chain, but not for the requested host name or IP.
        name_mismatch,
        expired,
        not_yet_valid,
        /// Only reported when revocation checking is configured.
        revoked,
        bad_signature,
        /// Key usage, extended key usage, or a non-CA used as an issuer.
        invalid_usage,
        malformed,
        /// The peer sent no certificate but one was required.
        missing,
        other,
    };
};

/// Details of the most recent TLS failure on a connection. Every field is
/// optional; backends fill in what they know.
pub const Diagnostics = struct {
    /// Fatal alert received from the peer.
    alert_received: ?Alert = null,
    /// Alert we sent or queued when we aborted.
    alert_sent: ?Alert = null,
    /// Why the peer certificate was rejected.
    certificate: ?CertificateProblem = null,
    /// The peer's first bytes were not a TLS record (e.g. a plaintext HTTP
    /// request on a TLS port).
    not_tls: bool = false,
    /// Backend message for logs. Not stable; do not branch on it.
    detail: []const u8 = "",

    pub fn format(d: Diagnostics, w: *Io.Writer) Io.Writer.Error!void {
        var sep: []const u8 = "";
        if (d.not_tls) {
            try w.writeAll("peer is not speaking TLS");
            sep = "; ";
        }
        if (d.alert_received) |a| {
            try w.print("{s}received alert {f}", .{ sep, fmtAlert(a) });
            sep = "; ";
        }
        if (d.alert_sent) |a| {
            try w.print("{s}sent alert {f}", .{ sep, fmtAlert(a) });
            sep = "; ";
        }
        if (d.certificate) |cp| {
            try w.print("{s}certificate {t}", .{ sep, cp.reason });
            if (cp.depth) |depth| try w.print(" at depth {d}", .{depth});
            sep = "; ";
        }
        if (d.detail.len > 0) try w.print("{s}{s}", .{ sep, d.detail });
    }
};

/// Details of a failed context creation.
pub const ConfigDiagnostics = struct {
    buf: [256]u8 = undefined,
    len: usize = 0,

    pub fn message(d: *const ConfigDiagnostics) []const u8 {
        return d.buf[0..d.len];
    }

    pub fn set(d: *ConfigDiagnostics, comptime fmt: []const u8, args: anytype) void {
        const written: []const u8 = std.fmt.bufPrint(&d.buf, fmt, args) catch &d.buf;
        d.len = written.len;
    }
};

fn fmtAlert(a: Alert) std.fmt.Alt(Alert, formatAlert) {
    return .{ .data = a };
}

fn formatAlert(a: Alert, w: *Io.Writer) Io.Writer.Error!void {
    if (std.enums.tagName(Alert, a)) |name| {
        try w.writeAll(name);
    } else {
        try w.print("{d}", .{@intFromEnum(a)});
    }
}

/// Maximum host name length accepted as `server_name` (DNS limit).
pub const max_server_name_len = 253;
/// Maximum total length of an ALPN list in wire format.
pub const max_alpn_wire_len = 256;

/// ALPN wire format: length-prefixed protocol names, concatenated.
pub fn alpnWireFormat(buf: []u8, protocols: []const []const u8) error{InvalidAlpnProtocols}![]const u8 {
    var i: usize = 0;
    for (protocols) |proto| {
        if (proto.len == 0 or proto.len > 255) return error.InvalidAlpnProtocols;
        if (i + 1 + proto.len > buf.len) return error.InvalidAlpnProtocols;
        buf[i] = @intCast(proto.len);
        @memcpy(buf[i + 1 ..][0..proto.len], proto);
        i += 1 + proto.len;
    }
    return buf[0..i];
}

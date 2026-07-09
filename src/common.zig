//! Types shared by the facade and both backends.
const std = @import("std");

/// Why the most recent operation on an established connection failed.
/// Stored on the connection and surfaced through `Reader.err`/`Writer.err`.
pub const Failure = error{
    /// TLS protocol error (bad record, unexpected message, decrypt
    /// failure, ...).
    TlsFailure,
    /// Transport reached end of stream without a close_notify (possible
    /// truncation attack).
    TlsTruncated,
    TransportReadFailed,
    TransportWriteFailed,
};

pub const InitError = error{
    /// Backend object creation or configuration failed.
    TlsInitFailure,
    InvalidCertificate,
    InvalidPrivateKey,
    HostTooLong,
    AlpnProtocolsTooLong,
    OutOfMemory,
};

pub const HandshakeError = error{
    TlsHandshakeFailure,
    CertificateVerificationFailure,
    ReadFailed,
    WriteFailed,
};

pub const config = struct {
    pub const RootCa = union(enum) {
        /// The system trust store.
        system,
        /// One or more PEM-encoded certificates.
        pem: []const u8,
        /// No trust anchors; every peer certificate fails verification.
        none,
    };

    pub const CertKeyPair = struct {
        /// PEM: leaf certificate first, then any intermediates.
        cert_pem: []const u8,
        /// PEM-encoded private key for the leaf certificate.
        key_pem: []const u8,
    };

    pub const ClientAuth = struct {
        /// Trust anchors used to verify the client certificate.
        root_ca: RootCa,
        auth_type: Type = .require,

        pub const Type = enum {
            /// Request a client certificate but accept an empty response.
            request,
            /// Request and require a valid client certificate.
            require,
        };
    };

    pub const Client = struct {
        /// Server name used for SNI and certificate host verification.
        host: []const u8,
        root_ca: RootCa = .system,
        /// Skip server certificate chain and host name verification.
        insecure_skip_verify: bool = false,
        /// ALPN protocol names to advertise (e.g. "h2", "http/1.1").
        alpn_protocols: []const []const u8 = &.{},
        /// Client certificate and key, sent if the server requests them.
        auth: ?CertKeyPair = null,
        /// Used to parse certificates and keys during setup (tls_zig
        /// backend). The openssl backend allocates internally via libc and
        /// does not use it.
        allocator: std.mem.Allocator,
    };

    pub const Server = struct {
        /// Server certificate chain and private key.
        auth: CertKeyPair,
        /// If set, a client certificate is requested during the handshake.
        client_auth: ?ClientAuth = null,
        /// ALPN protocols supported by the server, in preference order.
        /// If the client offers ALPN and there is no overlap the handshake
        /// fails; if the client does not offer ALPN none is negotiated.
        alpn_protocols: []const []const u8 = &.{},
        /// Used to parse certificates and keys during setup (tls_zig
        /// backend). The openssl backend allocates internally via libc and
        /// does not use it.
        allocator: std.mem.Allocator,
    };
};

/// Maximum host name length accepted in `config.Client.host` (DNS limit).
pub const max_host_len = 253;
/// Maximum total length of the ALPN protocol list in wire format
/// (1 length byte + name, per protocol).
pub const max_alpn_wire_len = 256;

/// Config limits enforced by the facade so both backends accept and reject
/// the same inputs.
pub fn validate(
    host: []const u8,
    alpn_protocols: []const []const u8,
) error{ HostTooLong, AlpnProtocolsTooLong }!void {
    if (host.len > max_host_len) return error.HostTooLong;
    var wire_len: usize = 0;
    for (alpn_protocols) |proto| {
        if (proto.len == 0 or proto.len > 255) return error.AlpnProtocolsTooLong;
        wire_len += 1 + proto.len;
    }
    if (wire_len > max_alpn_wire_len) return error.AlpnProtocolsTooLong;
}

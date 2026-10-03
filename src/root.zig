//! anytls — TLS for Zig over any `std.Io` transport, with the backend
//! selected at build time (`-Dbackend`).
//!
//! * `ClientContext`/`ServerContext` hold configuration (certificates, keys,
//!   trust store). They are built once, are immutable afterwards, may be
//!   shared by any number of connections across threads, and must outlive
//!   every connection created from them.
//! * `Connection` is one TLS connection over a caller-provided transport
//!   `*Io.Reader`/`*Io.Writer`. It must not move after init.
//! * `Connection.reader`/`Connection.writer` give the cleartext
//!   `std.Io.Reader`/`std.Io.Writer`. One task may read while another
//!   writes.
const std = @import("std");
const build_options = @import("build_options");
const api = @import("api.zig");

pub const backend = build_options.backend;

const impl = switch (backend) {
    .openssl => struct {
        const context = @import("openssl/context.zig");
        const ClientContext = context.ClientContext;
        const ServerContext = context.ServerContext;
        const Connection = @import("openssl/Connection.zig");
    },
    .tls_zig => struct {
        const context = @import("tlszig/context.zig");
        const ClientContext = context.ClientContext;
        const ServerContext = context.ServerContext;
        const Connection = @import("tlszig/Connection.zig");
    },
};

/// What the selected backend supports, for adapting at compile time.
pub const features: Features = switch (backend) {
    .openssl => .{},
    .tls_zig => .{
        .verifies_certificate_constraints = false,
        .fragmented_post_handshake_messages = false,
        .server_tls_1_2 = false,
        .verify_ip_address = false,
        .certificate_depth = false,
        .client_handshake_alerts = false,
        .key_mismatch_detection = .ecdsa_only,
        .max_client_alpn_len = 32,
        .reads_after_write_failure = false,
        .immediate_read_alerts = false,
        .retry_handshake = false,
        .buffered_writes = false,
    },
};

pub const Features = struct {
    /// Certificate verification checks that every issuer is a CA, key
    /// usage, extended key usage, path length and name constraints.
    /// Without it (tls_zig, through std.crypto.Certificate), any certificate
    /// a trusted CA issued can be used to sign a certificate for any name,
    /// and it is accepted.
    verifies_certificate_constraints: bool = true,
    /// Post-handshake messages split across records (large session tickets)
    /// are handled. Without it (tls_zig), such a message is passed to the
    /// reader as application data.
    fragmented_post_handshake_messages: bool = true,
    /// The server accepts TLS 1.2 clients (otherwise TLS 1.3 only).
    server_tls_1_2: bool = true,
    /// A client can verify an IP literal `server_name` against the
    /// certificate. Without it, such a connection fails with
    /// `error.Unsupported` unless verification is off.
    verify_ip_address: bool = true,
    /// `CertificateProblem.depth` is filled in.
    certificate_depth: bool = true,
    /// A client tells the server why its handshake failed.
    client_handshake_alerts: bool = true,
    /// Which keys a context checks against their certificate.
    key_mismatch_detection: enum { all, ecdsa_only } = .all,
    /// Longest ALPN protocol name a client context accepts; longer names
    /// fail with `error.Unsupported`.
    max_client_alpn_len: u8 = 255,
    /// After the transport writer failed, the connection can still read.
    reads_after_write_failure: bool = true,
    /// The alert reporting a failed read is sent right away; otherwise only
    /// by `close()`.
    immediate_read_alerts: bool = true,
    /// A handshake that failed on a transport error (e.g. a canceled read)
    /// may be retried.
    retry_handshake: bool = true,
    /// Records written between flushes are batched in the transport writer;
    /// otherwise each record is flushed as it is written.
    buffered_writes: bool = true,
};

pub const ClientContext = impl.ClientContext;
pub const ServerContext = impl.ServerContext;
pub const Connection = impl.Connection;

/// Minimum transport reader buffer size: one full ciphertext record.
pub const input_buffer_len = Connection.input_buffer_len;
/// Minimum transport writer buffer size: one full record plus overhead.
pub const output_buffer_len = Connection.output_buffer_len;

pub const Source = api.Source;
pub const CaSource = api.CaSource;
pub const CertificateSource = api.CertificateSource;
pub const Verify = api.Verify;
pub const ClientOptions = api.ClientOptions;
pub const ServerOptions = api.ServerOptions;
pub const ClientAuth = api.ClientAuth;
pub const ClientConnectionOptions = api.ClientConnectionOptions;

pub const ConfigError = api.ConfigError;
pub const ConfigDiagnostics = api.ConfigDiagnostics;
pub const ConnectionInitError = api.ConnectionInitError;
pub const TlsError = api.TlsError;
pub const StreamError = api.StreamError;
pub const Diagnostics = api.Diagnostics;
pub const Alert = api.Alert;
pub const CertificateProblem = api.CertificateProblem;

test {
    _ = @import("record.zig");
    _ = @import("test.zig");
}

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
    .tls_zig => @compileError("the tls_zig backend has not been ported to the new API yet"),
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
pub const HandshakeError = api.HandshakeError;
pub const Diagnostics = api.Diagnostics;
pub const Alert = api.Alert;
pub const CertificateProblem = api.CertificateProblem;

test {
    _ = @import("record.zig");
    _ = @import("test.zig");
}

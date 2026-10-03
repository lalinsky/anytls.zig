const std = @import("std");
const Io = std.Io;
const testing = std.testing;

const anytls = @import("root.zig");

const ca_pem = @embedFile("testdata/ca.pem");
const other_ca_pem = @embedFile("testdata/other-ca.pem");
const server_pem = @embedFile("testdata/server.pem");
const server_key = @embedFile("testdata/server.key");
const client_pem = @embedFile("testdata/client.pem");
const client_key = @embedFile("testdata/client.key");
const other_key = @embedFile("testdata/other.key");

const server_cert: anytls.CertificateSource = .{
    .chain = .{ .pem = server_pem },
    .key = .{ .pem = server_key },
};
const client_cert: anytls.CertificateSource = .{
    .chain = .{ .pem = client_pem },
    .key = .{ .pem = client_key },
};

/// What the server task observed.
const ServerResult = struct {
    err: ?anyerror = null,
    diag: anytls.Diagnostics = .{},
    alpn_buf: [32]u8 = undefined,
    alpn: ?[]const u8 = null,

    fn record(r: *ServerResult, conn: *const anytls.Connection, err: anyerror) anyerror {
        r.err = err;
        r.diag = conn.diagnostics().*;
        r.diag.detail = "";
        return err;
    }
};

const Behavior = enum {
    /// Echo cleartext until close_notify, then send close_notify.
    echo,
    /// Handshake, send "hello", drop TCP at a record boundary.
    hello_then_eof,
    /// Handshake, send "hello", then a record cut short, then drop TCP.
    hello_then_truncate,
    /// Handshake only; record the outcome.
    handshake_only,
};

fn serverTask(io: Io, listener: *Io.net.Server, ctx: *anytls.ServerContext, behavior: Behavior, result: *ServerResult) anyerror!void {
    var tcp = try listener.accept(io);
    defer tcp.close(io);
    var in_buf: [anytls.input_buffer_len]u8 = undefined;
    var out_buf: [anytls.output_buffer_len]u8 = undefined;
    var tcp_reader = tcp.reader(io, &in_buf);
    var tcp_writer = tcp.writer(io, &out_buf);

    var conn: anytls.Connection = undefined;
    try conn.initServer(ctx, io, &tcp_reader.interface, &tcp_writer.interface);
    defer conn.deinit();

    conn.handshake() catch |err| return result.record(&conn, err);
    if (conn.alpnProtocol()) |p| {
        @memcpy(result.alpn_buf[0..p.len], p);
        result.alpn = result.alpn_buf[0..p.len];
    }

    switch (behavior) {
        .handshake_only => {
            // Wait for the client to go away so the handshake outcome is
            // what the client observes.
            var buf: [64]u8 = undefined;
            _ = conn.read(&buf) catch |err| switch (err) {
                error.EndOfStream => {},
                error.ReadFailed => if (conn.failure()) |e| return result.record(&conn, e),
            };
        },
        .echo => {
            var buf: [4096]u8 = undefined;
            while (true) {
                const n = conn.read(&buf) catch |err| switch (err) {
                    error.EndOfStream => break,
                    error.ReadFailed => return result.record(&conn, conn.failure() orelse err),
                };
                try conn.write(buf[0..n]);
                try conn.flush();
            }
            try conn.close();
        },
        .hello_then_eof => {
            try conn.write("hello");
            try conn.flush();
        },
        .hello_then_truncate => {
            try conn.write("hello");
            try conn.flush();
            try conn.write("world");
            // Cut the last record short before it reaches the network.
            tcp_writer.interface.end -= 3;
            try tcp_writer.interface.flush();
        },
    }
}

const Env = struct {
    threaded: Io.Threaded,
    io: Io,
    listener: Io.net.Server,
    server_ctx: anytls.ServerContext,
    server_future: Io.Future(anyerror!void),
    server_result: ServerResult,
    server_awaited: bool,
    tcp: Io.net.Stream,
    tcp_reader: Io.net.Stream.Reader,
    tcp_writer: Io.net.Stream.Writer,
    in_buf: [anytls.input_buffer_len]u8,
    out_buf: [anytls.output_buffer_len]u8,

    fn start(env: *Env, server_opt: anytls.ServerOptions, behavior: Behavior) !void {
        env.threaded = .init(testing.allocator, .{});
        errdefer env.threaded.deinit();
        env.io = env.threaded.io();
        const io = env.io;

        env.server_ctx = try .init(testing.allocator, io, server_opt, null);
        errdefer env.server_ctx.deinit();

        const loopback = try Io.net.IpAddress.parseLiteral("127.0.0.1:0");
        env.listener = try loopback.listen(io, .{});
        errdefer env.listener.deinit(io);

        env.server_result = .{};
        env.server_awaited = false;
        env.server_future = try io.concurrent(serverTask, .{ io, &env.listener, &env.server_ctx, behavior, &env.server_result });
        errdefer _ = env.server_future.cancel(io) catch {};

        env.tcp = try env.listener.socket.address.connect(io, .{ .mode = .stream });
        env.tcp_reader = env.tcp.reader(io, &env.in_buf);
        env.tcp_writer = env.tcp.writer(io, &env.out_buf);
    }

    fn connect(env: *Env, conn: *anytls.Connection, ctx: *anytls.ClientContext, server_name: []const u8) !void {
        try conn.initClient(ctx, env.io, &env.tcp_reader.interface, &env.tcp_writer.interface, .{ .server_name = server_name });
    }

    /// Half-closes the client's TCP connection (the server still gets to
    /// write) and waits for the server task.
    fn finish(env: *Env) anyerror!void {
        env.tcp.shutdown(env.io, .send) catch {};
        env.server_awaited = true;
        return env.server_future.await(env.io);
    }

    fn stop(env: *Env) void {
        if (!env.server_awaited) {
            env.tcp.shutdown(env.io, .both) catch {};
            _ = env.server_future.await(env.io) catch {};
        }
        env.tcp.close(env.io);
        env.listener.deinit(env.io);
        env.server_ctx.deinit();
        env.threaded.deinit();
    }
};

fn clientContext(env: *Env, opt: anytls.ClientOptions) !anytls.ClientContext {
    return anytls.ClientContext.init(testing.allocator, env.io, opt, null);
}

test "handshake, ALPN, echo through Reader/Writer, close_notify" {
    var env: Env = undefined;
    try env.start(.{ .certificate = server_cert, .alpn = &.{ "h2", "http/1.1" } }, .echo);
    defer env.stop();
    var ctx = try clientContext(&env, .{ .ca = .{ .pem = ca_pem }, .alpn = &.{ "http/1.1", "h2" } });
    defer ctx.deinit();

    var conn: anytls.Connection = undefined;
    try env.connect(&conn, &ctx, "localhost");
    defer conn.deinit();
    try conn.handshake();

    // Server preference order wins.
    try testing.expectEqualStrings("h2", conn.alpnProtocol().?);
    try testing.expectEqual(.tls_1_3, conn.protocolVersion());
    try testing.expect(conn.cipherSuite().len > 0);

    var rbuf: [256]u8 = undefined;
    var wbuf: [256]u8 = undefined;
    var reader = conn.reader(&rbuf);
    var writer = conn.writer(&wbuf);
    try writer.interface.print("count {d}\n", .{42});
    try writer.interface.flush();
    try testing.expectEqualStrings("count 42\n", try reader.interface.takeDelimiterInclusive('\n'));

    try conn.close();
    // The server answers close_notify with its own.
    try testing.expectError(error.EndOfStream, reader.interface.takeByte());
    try env.finish();
    try testing.expectEqualStrings("h2", env.server_result.alpn.?);
}

test "reader works with an empty buffer" {
    var env: Env = undefined;
    try env.start(.{ .certificate = server_cert }, .echo);
    defer env.stop();
    var ctx = try clientContext(&env, .{ .ca = .{ .pem = ca_pem } });
    defer ctx.deinit();

    var conn: anytls.Connection = undefined;
    try env.connect(&conn, &ctx, "localhost");
    defer conn.deinit();
    try conn.handshake();

    var wbuf: [64]u8 = undefined;
    var reader = conn.reader(&.{});
    var writer = conn.writer(&wbuf);
    try writer.interface.writeAll("ping");
    try writer.interface.flush();
    var got: [4]u8 = undefined;
    try reader.interface.readSliceAll(&got);
    try testing.expectEqualStrings("ping", &got);
    try conn.close();
    try env.finish();
}

test "EOF at a record boundary is a normal end of stream" {
    var env: Env = undefined;
    try env.start(.{ .certificate = server_cert }, .hello_then_eof);
    defer env.stop();
    var ctx = try clientContext(&env, .{ .ca = .{ .pem = ca_pem } });
    defer ctx.deinit();

    var conn: anytls.Connection = undefined;
    try env.connect(&conn, &ctx, "localhost");
    defer conn.deinit();
    try conn.handshake();

    var rbuf: [64]u8 = undefined;
    var reader = conn.reader(&rbuf);
    var got: [5]u8 = undefined;
    try reader.interface.readSliceAll(&got);
    try testing.expectEqualStrings("hello", &got);
    try testing.expectError(error.EndOfStream, reader.interface.takeByte());
    try env.finish();
}

test "EOF inside a record is truncation" {
    var env: Env = undefined;
    try env.start(.{ .certificate = server_cert }, .hello_then_truncate);
    defer env.stop();
    var ctx = try clientContext(&env, .{ .ca = .{ .pem = ca_pem } });
    defer ctx.deinit();

    var conn: anytls.Connection = undefined;
    try env.connect(&conn, &ctx, "localhost");
    defer conn.deinit();
    try conn.handshake();

    var rbuf: [64]u8 = undefined;
    var reader = conn.reader(&rbuf);
    var got: [5]u8 = undefined;
    try reader.interface.readSliceAll(&got);
    try testing.expectEqualStrings("hello", &got);
    try testing.expectError(error.ReadFailed, reader.interface.takeByte());
    try testing.expectEqual(error.ConnectionTruncated, reader.err.?);
    // Sticky.
    try testing.expectError(error.ReadFailed, reader.interface.takeByte());
    try env.finish();
}

test "unknown CA: CertificateRejected with reason and depth" {
    var env: Env = undefined;
    try env.start(.{ .certificate = server_cert }, .handshake_only);
    defer env.stop();
    var ctx = try clientContext(&env, .{ .ca = .{ .pem = other_ca_pem } });
    defer ctx.deinit();

    var conn: anytls.Connection = undefined;
    try env.connect(&conn, &ctx, "localhost");
    defer conn.deinit();
    try testing.expectError(error.CertificateRejected, conn.handshake());
    const diag = conn.diagnostics();
    try testing.expectEqual(.untrusted, diag.certificate.?.reason);
    try testing.expectEqual(0, diag.certificate.?.depth.?);
    try testing.expectEqual(.unknown_ca, diag.alert_sent.?);

    try testing.expectError(error.AlertReceived, env.finish());
    try testing.expectEqual(.unknown_ca, env.server_result.diag.alert_received.?);
}

test "wrong host name and wrong IP: name_mismatch" {
    for ([_][]const u8{ "example.com", "127.0.0.2" }) |name| {
        var env: Env = undefined;
        try env.start(.{ .certificate = server_cert }, .handshake_only);
        defer env.stop();
        var ctx = try clientContext(&env, .{ .ca = .{ .pem = ca_pem } });
        defer ctx.deinit();

        var conn: anytls.Connection = undefined;
        try env.connect(&conn, &ctx, name);
        defer conn.deinit();
        try testing.expectError(error.CertificateRejected, conn.handshake());
        try testing.expectEqual(.name_mismatch, conn.diagnostics().certificate.?.reason);
        env.finish() catch {};
    }
}

test "IP literal verifies against the IP SAN" {
    var env: Env = undefined;
    try env.start(.{ .certificate = server_cert }, .echo);
    defer env.stop();
    var ctx = try clientContext(&env, .{ .ca = .{ .pem = ca_pem } });
    defer ctx.deinit();

    var conn: anytls.Connection = undefined;
    try env.connect(&conn, &ctx, "127.0.0.1");
    defer conn.deinit();
    try conn.handshake();
    try conn.close();
    try env.finish();
}

test "insecure_no_verify accepts an unknown CA and a wrong name" {
    var env: Env = undefined;
    try env.start(.{ .certificate = server_cert }, .echo);
    defer env.stop();
    var ctx = try clientContext(&env, .{ .ca = .none, .verify = .insecure_no_verify });
    defer ctx.deinit();

    var conn: anytls.Connection = undefined;
    try env.connect(&conn, &ctx, "");
    defer conn.deinit();
    try conn.handshake();
    try conn.close();
    try env.finish();
}

test "missing server name is rejected when verifying" {
    var env: Env = undefined;
    try env.start(.{ .certificate = server_cert }, .handshake_only);
    defer env.stop();
    var ctx = try clientContext(&env, .{ .ca = .{ .pem = ca_pem } });
    defer ctx.deinit();

    var conn: anytls.Connection = undefined;
    try testing.expectError(error.MissingServerName, env.connect(&conn, &ctx, ""));
}

test "mTLS: client certificate accepted" {
    var env: Env = undefined;
    try env.start(.{
        .certificate = server_cert,
        .client_auth = .{ .ca = .{ .pem = ca_pem } },
    }, .echo);
    defer env.stop();
    var ctx = try clientContext(&env, .{ .ca = .{ .pem = ca_pem }, .certificate = client_cert });
    defer ctx.deinit();

    var conn: anytls.Connection = undefined;
    try env.connect(&conn, &ctx, "localhost");
    defer conn.deinit();
    try conn.handshake();
    var wbuf: [64]u8 = undefined;
    var rbuf: [64]u8 = undefined;
    var writer = conn.writer(&wbuf);
    var reader = conn.reader(&rbuf);
    try writer.interface.writeAll("hi");
    try writer.interface.flush();
    var got: [2]u8 = undefined;
    try reader.interface.readSliceAll(&got);
    try conn.close();
    try env.finish();
}

test "mTLS: missing client certificate" {
    var env: Env = undefined;
    try env.start(.{
        .certificate = server_cert,
        .client_auth = .{ .ca = .{ .pem = ca_pem }, .mode = .require },
    }, .handshake_only);
    defer env.stop();
    var ctx = try clientContext(&env, .{ .ca = .{ .pem = ca_pem } });
    defer ctx.deinit();

    var conn: anytls.Connection = undefined;
    try env.connect(&conn, &ctx, "localhost");
    defer conn.deinit();
    // TLS 1.3: the client finishes its side of the handshake before the
    // server rejects it, so the rejection arrives on the first read.
    try conn.handshake();
    var rbuf: [64]u8 = undefined;
    var reader = conn.reader(&rbuf);
    try testing.expectError(error.ReadFailed, reader.interface.takeByte());
    try testing.expectEqual(error.AlertReceived, reader.err.?);
    try testing.expectEqual(.certificate_required, conn.diagnostics().alert_received.?);

    try testing.expectError(error.CertificateRejected, env.finish());
    try testing.expectEqual(.missing, env.server_result.diag.certificate.?.reason);
}

test "no common ALPN protocol: Incompatible" {
    var env: Env = undefined;
    try env.start(.{ .certificate = server_cert, .alpn = &.{"h2"} }, .handshake_only);
    defer env.stop();
    var ctx = try clientContext(&env, .{ .ca = .{ .pem = ca_pem }, .alpn = &.{"http/1.1"} });
    defer ctx.deinit();

    var conn: anytls.Connection = undefined;
    try env.connect(&conn, &ctx, "localhost");
    defer conn.deinit();
    try testing.expectError(error.AlertReceived, conn.handshake());
    try testing.expectEqual(.no_application_protocol, conn.diagnostics().alert_received.?);
    try testing.expectError(error.Incompatible, env.finish());
}

test "plaintext on the TLS port: ProtocolViolation with not_tls" {
    var env: Env = undefined;
    try env.start(.{ .certificate = server_cert }, .handshake_only);
    defer env.stop();

    try env.tcp_writer.interface.writeAll("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    try env.tcp_writer.interface.flush();
    try testing.expectError(error.ProtocolViolation, env.finish());
    try testing.expect(env.server_result.diag.not_tls);
}

test "concurrent reader and writer tasks" {
    var env: Env = undefined;
    try env.start(.{ .certificate = server_cert }, .echo);
    defer env.stop();
    var ctx = try clientContext(&env, .{ .ca = .{ .pem = ca_pem } });
    defer ctx.deinit();

    var conn: anytls.Connection = undefined;
    try env.connect(&conn, &ctx, "localhost");
    defer conn.deinit();
    try conn.handshake();

    const total = 4 * 1024 * 1024;
    const gpa = testing.allocator;
    const send_data = try gpa.alloc(u8, total);
    defer gpa.free(send_data);
    const recv_data = try gpa.alloc(u8, total);
    defer gpa.free(recv_data);
    var rng = std.Random.DefaultPrng.init(0);
    rng.random().bytes(send_data);

    const Sender = struct {
        fn run(c: *anytls.Connection, data: []const u8) anyerror!void {
            var wbuf: [16 * 1024]u8 = undefined;
            var writer = c.writer(&wbuf);
            var off: usize = 0;
            while (off < data.len) {
                const n = @min(data.len - off, 3000);
                try writer.interface.writeAll(data[off..][0..n]);
                off += n;
            }
            try writer.interface.flush();
        }
    };
    // Far more than socket buffers hold, so the writer only makes progress
    // while the reader drains the echo concurrently.
    var sender = try env.io.concurrent(Sender.run, .{ &conn, send_data });

    var rbuf: [8192]u8 = undefined;
    var reader = conn.reader(&rbuf);
    reader.interface.readSliceAll(recv_data) catch |err| {
        _ = sender.cancel(env.io) catch {};
        return err;
    };
    try sender.await(env.io);
    try testing.expectEqualSlices(u8, send_data, recv_data);
    try conn.close();
    try env.finish();
}

test "transport read failure in the handshake stays a transport error" {
    const FailingReader = struct {
        fn stream(_: *Io.Reader, _: *Io.Writer, _: Io.Limit) Io.Reader.StreamError!usize {
            return error.ReadFailed;
        }
    };
    var threaded: Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var ctx = try anytls.ClientContext.init(testing.allocator, io, .{ .ca = .{ .pem = ca_pem } }, null);
    defer ctx.deinit();

    var in_buf: [anytls.input_buffer_len]u8 = undefined;
    var out_buf: [anytls.output_buffer_len]u8 = undefined;
    var reader: Io.Reader = .{ .vtable = &.{ .stream = FailingReader.stream }, .buffer = &in_buf, .seek = 0, .end = 0 };
    var discarding = Io.Writer.Discarding.init(&out_buf);

    var conn: anytls.Connection = undefined;
    try conn.initClient(&ctx, io, &reader, &discarding.writer, .{ .server_name = "localhost" });
    defer conn.deinit();
    try testing.expectError(error.ReadFailed, conn.handshake());
    try testing.expectEqual(null, conn.failure());
}

test "config errors" {
    var threaded: Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    var diag: anytls.ConfigDiagnostics = .{};

    try testing.expectError(error.KeyMismatch, anytls.ServerContext.init(gpa, io, .{
        .certificate = .{ .chain = .{ .pem = server_pem }, .key = .{ .pem = other_key } },
    }, &diag));
    try testing.expectError(error.InvalidCertificate, anytls.ServerContext.init(gpa, io, .{
        .certificate = .{ .chain = .{ .pem = "garbage" }, .key = .{ .pem = server_key } },
    }, &diag));
    try testing.expectError(error.InvalidPrivateKey, anytls.ServerContext.init(gpa, io, .{
        .certificate = .{ .chain = .{ .pem = server_pem }, .key = .{ .pem = "garbage" } },
    }, &diag));
    try testing.expectError(error.FileUnreadable, anytls.ClientContext.init(gpa, io, .{
        .ca = .{ .file = "does/not/exist.pem" },
    }, &diag));
    try testing.expect(std.mem.indexOf(u8, diag.message(), "does/not/exist.pem") != null);
    try testing.expectError(error.InvalidCaCertificates, anytls.ClientContext.init(gpa, io, .{
        .ca = .{ .pem = "no certificates here" },
    }, &diag));
    try testing.expectError(error.InvalidAlpnProtocols, anytls.ClientContext.init(gpa, io, .{
        .ca = .none,
        .alpn = &.{""},
    }, &diag));
}

test "CA sources: file, dir, system" {
    var threaded: Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;

    var from_file = try anytls.ClientContext.init(gpa, io, .{ .ca = .{ .file = "src/testdata/ca.pem" } }, null);
    from_file.deinit();
    var from_dir = try anytls.ClientContext.init(gpa, io, .{ .ca = .{ .dir = "src/testdata" } }, null);
    from_dir.deinit();
    var from_system = anytls.ClientContext.init(gpa, io, .{ .ca = .system }, null) catch |err| switch (err) {
        error.CaUnavailable => return error.SkipZigTest,
        else => return err,
    };
    from_system.deinit();
}

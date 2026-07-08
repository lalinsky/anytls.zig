const std = @import("std");
const Io = std.Io;
const testing = std.testing;

const anytls = @import("root.zig");

const test_cert_pem = @embedFile("testdata/cert.pem");
const test_key_pem = @embedFile("testdata/key.pem");

const TestServer = struct {
    /// Accepts one connection and TLS-echoes back to the client until clean close.
    fn echo(io: Io, listener: *Io.net.Server, opt: anytls.config.Server) anyerror!void {
        var stream = try listener.accept(io);
        defer stream.close(io);
        var in_buf: [4096]u8 = undefined;
        var out_buf: [4096]u8 = undefined;
        var stream_reader = stream.reader(io, &in_buf);
        var stream_writer = stream.writer(io, &out_buf);

        var conn = try anytls.server(&stream_reader.interface, &stream_writer.interface, opt);
        defer conn.deinit();

        var buf: [1024]u8 = undefined;
        while (true) {
            const n = try conn.read(&buf);
            if (n == 0) break; // clean close_notify
            try conn.writeAll(buf[0..n]);
        }
        try conn.close();
    }
};

const ClientEnd = struct {
    io: Io,
    threaded: Io.Threaded,
    listener: Io.net.Server,
    stream: Io.net.Stream,
    stream_reader: Io.net.Stream.Reader,
    stream_writer: Io.net.Stream.Writer,
    server_future: Io.Future(anyerror!void),
    server_done: bool,
    in_buf: [4096]u8,
    out_buf: [4096]u8,

    fn start(env: *ClientEnd, gpa: std.mem.Allocator, server_opt: anytls.config.Server) !void {
        env.threaded = .init(gpa, .{});
        errdefer env.threaded.deinit();
        const io = env.threaded.io();
        env.io = io;

        const loopback = try Io.net.IpAddress.parseLiteral("127.0.0.1:0");
        env.listener = try loopback.listen(io, .{});
        errdefer env.listener.deinit(io);

        env.server_done = false;
        env.server_future = try io.concurrent(TestServer.echo, .{ io, &env.listener, server_opt });
        errdefer {
            env.server_done = true;
            env.server_future.cancel(io) catch {};
        }

        env.stream = try env.listener.socket.address.connect(io, .{ .mode = .stream });

        env.stream_reader = env.stream.reader(io, &env.in_buf);
        env.stream_writer = env.stream.writer(io, &env.out_buf);
    }

    fn transport(env: *ClientEnd) struct { *Io.Reader, *Io.Writer } {
        return .{ &env.stream_reader.interface, &env.stream_writer.interface };
    }

    fn awaitServer(env: *ClientEnd) anyerror!void {
        env.server_done = true;
        return env.server_future.await(env.io);
    }

    fn stop(env: *ClientEnd) void {
        if (!env.server_done) env.server_future.cancel(env.io) catch {};
        env.stream.close(env.io);
        env.listener.deinit(env.io);
        env.threaded.deinit();
    }
};

test "handshake, echo, ALPN, clean close" {
    var env: ClientEnd = undefined;
    try env.start(testing.allocator, .{
        .auth = .{ .cert_pem = test_cert_pem, .key_pem = test_key_pem },
        .alpn_protocols = &.{ "h2", "http/1.1" },
    });
    defer env.stop();
    const input, const output = env.transport();

    var conn = try anytls.client(input, output, .{
        .host = "localhost",
        .root_ca = .{ .pem = test_cert_pem },
        .alpn_protocols = &.{ "h2", "http/1.1" },
    });
    defer conn.deinit();

    try testing.expectEqualStrings("h2", conn.alpn_protocol.?);

    // Direct read/write methods.
    try conn.writeAll("hello over tls");
    var buf: [64]u8 = undefined;
    var got: usize = 0;
    while (got < "hello over tls".len) {
        const n = try conn.read(buf[got..]);
        try testing.expect(n != 0);
        got += n;
    }
    try testing.expectEqualStrings("hello over tls", buf[0..got]);

    // Io.Reader/Io.Writer adapters, exercising buffering and print.
    var rd_buf: [256]u8 = undefined;
    var wr_buf: [256]u8 = undefined;
    var tls_reader = conn.reader(&rd_buf);
    var tls_writer = conn.writer(&wr_buf);
    try tls_writer.interface.print("count {d}\n", .{42});
    try tls_writer.interface.flush();
    const line = try tls_reader.interface.takeDelimiterInclusive('\n');
    try testing.expectEqualStrings("count 42\n", line);

    try conn.close();
    // Server saw close_notify, echoed everything, and exited cleanly.
    try env.awaitServer();
    // Our side then reads the server's close_notify as clean EOF.
    try testing.expectEqual(@as(usize, 0), try conn.read(&buf));
}

test "server picks its preference order for ALPN" {
    var env: ClientEnd = undefined;
    try env.start(testing.allocator, .{
        .auth = .{ .cert_pem = test_cert_pem, .key_pem = test_key_pem },
        .alpn_protocols = &.{"http/1.1"},
    });
    defer env.stop();
    const input, const output = env.transport();

    var conn = try anytls.client(input, output, .{
        .host = "localhost",
        .root_ca = .{ .pem = test_cert_pem },
        .alpn_protocols = &.{ "h2", "http/1.1" },
    });
    defer conn.deinit();

    try testing.expectEqualStrings("http/1.1", conn.alpn_protocol.?);
    try conn.close();
    try env.awaitServer();
}

test "certificate verification failure without trust anchor" {
    var env: ClientEnd = undefined;
    try env.start(testing.allocator, .{
        .auth = .{ .cert_pem = test_cert_pem, .key_pem = test_key_pem },
    });
    defer env.stop();
    const input, const output = env.transport();

    try testing.expectError(error.CertificateVerificationFailure, anytls.client(input, output, .{
        .host = "localhost",
        .root_ca = .none,
    }));
    // The server side fails too (it receives the client's fatal alert).
    try testing.expectError(error.TlsHandshakeFailure, env.awaitServer());
}

test "insecure_skip_verify connects despite unknown CA and wrong host" {
    var env: ClientEnd = undefined;
    try env.start(testing.allocator, .{
        .auth = .{ .cert_pem = test_cert_pem, .key_pem = test_key_pem },
    });
    defer env.stop();
    const input, const output = env.transport();

    var conn = try anytls.client(input, output, .{
        .host = "does-not-match.example.com",
        .root_ca = .none,
        .insecure_skip_verify = true,
    });
    defer conn.deinit();

    try conn.writeAll("ping");
    var buf: [16]u8 = undefined;
    const n = try conn.read(&buf);
    try testing.expectEqualStrings("ping", buf[0..n]);
    try conn.close();
    try env.awaitServer();
}

test "large transfer with small buffers" {
    var env: ClientEnd = undefined;
    try env.start(testing.allocator, .{
        .auth = .{ .cert_pem = test_cert_pem, .key_pem = test_key_pem },
    });
    defer env.stop();
    const input, const output = env.transport();

    var conn = try anytls.client(input, output, .{
        .host = "localhost",
        .root_ca = .{ .pem = test_cert_pem },
    });
    defer conn.deinit();

    // Bigger than one TLS record, exercising chunking on the write path and
    // partial-record reads on the read path. An SSL object is not
    // thread-safe, so the transfer is sequential (write everything, then
    // read the echo); sized to fit in kernel socket buffers to avoid
    // deadlocking against the echo server.
    const total = 64 * 1024;
    const gpa = testing.allocator;
    const send_data = try gpa.alloc(u8, total);
    defer gpa.free(send_data);
    const recv_data = try gpa.alloc(u8, total);
    defer gpa.free(recv_data);
    var rng = std.Random.DefaultPrng.init(0);
    rng.random().bytes(send_data);

    try conn.writeAll(send_data);

    var got: usize = 0;
    while (got < total) {
        const n = try conn.read(recv_data[got..]);
        try testing.expect(n != 0);
        got += n;
    }
    try testing.expectEqualSlices(u8, send_data, recv_data);
    try conn.close();
    try env.awaitServer();
}

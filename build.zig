const std = @import("std");

pub const Backend = enum {
    /// System libssl (OpenSSL 3) driven sans-I/O over memory BIOs.
    openssl,
    /// Pure Zig ianic/tls.zig.
    tls_zig,
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const backend = b.option(Backend, "backend", "TLS implementation backend") orelse .openssl;

    const options = b.addOptions();
    options.addOption(Backend, "backend", backend);

    const mod = b.addModule("anytls", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addOptions("build_options", options);

    switch (backend) {
        .openssl => {
            mod.link_libc = true;
            const translate_c = b.addTranslateC(.{
                .root_source_file = b.path("src/c.h"),
                .target = target,
                .optimize = optimize,
            });
            mod.addImport("c", translate_c.createModule());
            mod.linkSystemLibrary("ssl", .{});
            mod.linkSystemLibrary("crypto", .{});
        },
        .tls_zig => {
            const tls_dep = b.dependency("tls", .{
                .target = target,
                .optimize = optimize,
            });
            mod.addImport("tls", tls_dep.module("tls"));
        },
    }

    const test_filters = b.option([]const []const u8, "test-filter", "Only run tests matching filter") orelse &.{};
    const tests = b.addTest(.{
        .root_module = mod,
        .filters = test_filters,
    });
    b.installArtifact(tests);
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);
}

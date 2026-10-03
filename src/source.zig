//! Reading configuration sources through `std.Io`, shared by the backends.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const api = @import("api.zig");

const ConfigError = api.ConfigError;
const ConfigDiagnostics = api.ConfigDiagnostics;

pub const max_file_size = 16 * 1024 * 1024;

/// Bytes of a `Source`; owned (and freed by `deinit`) when read from a file.
pub const Loaded = struct {
    bytes: []const u8,
    owned: bool,

    pub fn deinit(l: Loaded, gpa: Allocator) void {
        if (l.owned) gpa.free(l.bytes);
    }
};

pub fn read(gpa: Allocator, io: Io, src: api.Source, d: *ConfigDiagnostics) ConfigError!Loaded {
    return switch (src) {
        .pem => |pem| .{ .bytes = pem, .owned = false },
        .file => |path| .{ .bytes = try readFile(gpa, io, Io.Dir.cwd(), path, d), .owned = true },
    };
}

pub fn readFile(gpa: Allocator, io: Io, dir: Io.Dir, path: []const u8, d: *ConfigDiagnostics) ConfigError![]u8 {
    return dir.readFileAlloc(io, path, gpa, .limited(max_file_size)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Canceled => return error.Canceled,
        else => {
            d.set("{s}: {t}", .{ path, err });
            return error.FileUnreadable;
        },
    };
}

/// Calls `addFile(ctx, bytes)` for every regular file in the directory and
/// returns the sum of what it returned (the number of certificates added).
pub fn forEachFileInDir(
    gpa: Allocator,
    io: Io,
    path: []const u8,
    d: *ConfigDiagnostics,
    ctx: anytype,
    comptime addFile: fn (@TypeOf(ctx), []const u8) ConfigError!usize,
) ConfigError!usize {
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
        // Files without certificates (READMEs, keys, CRLs) are skipped.
        count += addFile(ctx, bytes) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => 0,
        };
    }
    return count;
}

pub fn noCaCerts(d: *ConfigDiagnostics, what: []const u8) ConfigError {
    d.set("{s}: no CA certificates found", .{what});
    return error.InvalidCaCertificates;
}

/// Counts live connections of a context in safe builds, to catch a context
/// being deinitialized while connections still use it.
pub const LiveCount = struct {
    count: if (std.debug.runtime_safety) std.atomic.Value(u32) else void =
        if (std.debug.runtime_safety) .init(0) else {},

    pub fn inc(l: *LiveCount) void {
        if (std.debug.runtime_safety) _ = l.count.fetchAdd(1, .monotonic);
    }

    pub fn dec(l: *LiveCount) void {
        if (std.debug.runtime_safety) _ = l.count.fetchSub(1, .monotonic);
    }

    pub fn check(l: *LiveCount) void {
        if (!std.debug.runtime_safety) return;
        const live = l.count.load(.monotonic);
        if (live != 0) std.log.scoped(.anytls).err("context deinitialized with {d} live connection(s)", .{live});
    }
};

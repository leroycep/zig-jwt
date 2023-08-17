const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const optimize = b.standardOptimizeOption(.{});

    const target = b.standardTargetOptions(.{});
    _ = b.addModule("jwt", .{
        .source_file = .{ .path = "jwt.zig" },
    });

    const lib = b.addStaticLibrary(.{
        .name = "zig-jwt",
        .root_source_file = .{ .path = "jwt.zig" },
        .optimize = optimize,
        .target = target,
    });
    b.installArtifact(lib);

    const main_tests = b.addTest(.{
        .root_source_file = .{ .path = "jwt.zig" },
    });
    const run_main_tests = b.addRunArtifact(main_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
}

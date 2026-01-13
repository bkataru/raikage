// build.zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "raikage",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    b.installArtifact(exe);

    // Export raikage module for use as a library
    const raikage_module = b.addModule("raikage", .{
        .root_source_file = b.path("src/shared.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Examples
    const examples_step = b.step("examples", "Build all examples");

    const example_names = [_][]const u8{
        "key_derivation",
        "file_hashing",
        "custom_encryption",
    };

    inline for (example_names) |example_name| {
        const example = b.addExecutable(.{
            .name = example_name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(b.fmt("examples/{s}.zig", .{example_name})),
                .target = target,
                .optimize = optimize,
            }),
        });

        example.root_module.addImport("raikage", raikage_module);

        const install_example = b.addInstallArtifact(example, .{});
        examples_step.dependOn(&install_example.step);

        // Add run step for each example
        const run_example = b.addRunArtifact(example);
        const run_example_step = b.step(b.fmt("run-{s}", .{example_name}), b.fmt("Run the {s} example", .{example_name}));
        run_example_step.dependOn(&run_example.step);
    }
}

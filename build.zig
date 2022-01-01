const zbuild = @import("std").build;

pub fn add_deps(b: *zbuild.LibExeObjStep) void {
    b.addIncludeDir("/opt/homebrew/include");
    b.addIncludeDir(".");
    b.addCSourceFile("lib/zig_ssl_config.c", &[_][]const u8{"-std=c99"});
    b.addLibPath("/opt/homebrew/lib");
    b.linkSystemLibrary("mbedcrypto");
    b.linkSystemLibrary("mbedtls");
    b.linkSystemLibrary("mbedx509");
}

pub fn build(b: *zbuild.Builder) void {
    b.verbose_cimport = true;
    //b.verbose_cc = true;
    //b.verbose_link = true;

    const mode = b.standardReleaseOptions();
    const lib = b.addStaticLibrary("zig-mbedtls", "src/main.zig");
    add_deps(lib);
    lib.setBuildMode(mode);
    lib.install();

    var main_tests = b.addTest("src/main.zig");
    add_deps(main_tests);
    main_tests.setBuildMode(.Debug);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);

    const example = b.addExecutable("simple", "examples/simple.zig");
    add_deps(example);
    example.setBuildMode(mode);
    example.addPackagePath("mbedtls", "mbedtls.zig");
    example.install();

    const examples = b.step("examples", "Build examples");
    examples.dependOn(&example.step);
}

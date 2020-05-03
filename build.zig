const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    b.verbose_cimport = true;
    //b.verbose_cc = true;
    //b.verbose_link = true;

    const mode = b.standardReleaseOptions();
    const lib = b.addStaticLibrary("zig-mbedtls", "src/main.zig");
    lib.setBuildMode(mode);
    lib.addIncludeDir("/usr/local/opt/mbedtls/include");
    lib.addIncludeDir(".");
    lib.addCSourceFile("lib/zig_ssl_config.c", &[_][]const u8{"-std=c99"});
    lib.linkSystemLibrary("mbedcrypto");
    lib.linkSystemLibrary("mbedtls");
    lib.linkSystemLibrary("mbedx509");
    lib.install();

    var main_tests = b.addTest("src/main.zig");
    main_tests.setBuildMode(.Debug);
    main_tests.addIncludeDir("/usr/local/Cellar/mbedtls/2.16.6/include");
    main_tests.addIncludeDir(".");
    main_tests.addCSourceFile("lib/zig_ssl_config.c", &[_][]const u8{"-std=c99"});
    main_tests.linkSystemLibrary("mbedcrypto");
    main_tests.linkSystemLibrary("mbedtls");
    main_tests.linkSystemLibrary("mbedx509");

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}

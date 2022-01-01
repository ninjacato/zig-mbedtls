const m = @import("bits.zig");
const std = @import("std");
const c = @cImport({
    @cInclude("lib/zig_ssl_config.h");
    @cInclude("mbedtls/entropy.h");
    @cInclude("mbedtls/ctr_drbg.h");
    @cInclude("mbedtls/net_sockets.h");
    @cInclude("mbedtls/ssl.h");
    @cInclude("mbedtls/x509.h");
    @cInclude("mbedtls/debug.h");
});

const os = std.os;
const io = std.io;
const Allocator = std.mem.Allocator;
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;
const expect = std.testing.expect;
const assert = std.debug.assert;

pub const mbedTLS = struct {
    server_fd: *c.mbedtls_net_context,
    ssl_conf: *c.mbedtls_ssl_config,
    ssl: *c.mbedtls_ssl_context,
    entropy: *c.mbedtls_entropy_context,
    drbg: *c.mbedtls_ctr_drbg_context,
    ca_chain: *c.mbedtls_x509_crt,
    entropyfn: @TypeOf(c.mbedtls_entropy_func),
    allocator: Allocator,

    pub fn init(allocator: Allocator) !mbedTLS {
        var net_ctx = try allocator.create(c.mbedtls_net_context);
        var entropy_ctx = try allocator.create(c.mbedtls_entropy_context);
        var ssl_config = c.zmbedtls_ssl_config_alloc();
        var ssl_ctx = try allocator.create(c.mbedtls_ssl_context);
        var drbg_ctx = try allocator.create(c.mbedtls_ctr_drbg_context);
        var ca_chain = try allocator.create(c.mbedtls_x509_crt);

        c.mbedtls_net_init(net_ctx);
        c.mbedtls_entropy_init(entropy_ctx);
        c.mbedtls_ssl_init(ssl_ctx);
        c.zmbedtls_ssl_config_init(ssl_config);
        c.mbedtls_ctr_drbg_init(drbg_ctx);
        c.mbedtls_x509_crt_init(ca_chain);

        return mbedTLS{ .server_fd = net_ctx, .entropy = entropy_ctx, .ssl = ssl_ctx, .ssl_conf = @ptrCast(*c.mbedtls_ssl_config, ssl_config), .drbg = drbg_ctx, .ca_chain = ca_chain, .entropyfn = c.mbedtls_entropy_func, .allocator = allocator };
    }

    const X509Error = error{
        AllocationFailed,
        BadInputData,
        FileIoError,
        OutOfMemory,
    };

    pub fn x509CrtParseFile(self: *mbedTLS, cafile: []const u8) X509Error!void {
        const rc = c.mbedtls_x509_crt_parse_file(self.ca_chain, &cafile[0]);
        switch (rc) {
            0 => {},
            m.MBEDTLS_ERR_PK_ALLOC_FAILED => return error.AllocationFailed,
            m.MBEDTLS_ERR_PK_BAD_INPUT_DATA => return error.BadInputData,
            m.MBEDTLS_ERR_PK_FILE_IO_ERROR => return error.FileIoError,
            else => unreachable,
        }
    }

    pub const Proto = enum(u2) { TCP, UDP };

    const ConnError = error{ Corruption, UnknownHost, SocketFailed, ConnectionFailed, OutOfMemory };

    pub fn netConnect(self: *mbedTLS, host: [*]const u8, port: [*]const u8, proto: Proto) ConnError!void {
        const rc = c.mbedtls_net_connect(self.server_fd, host, port, @enumToInt(proto));
        switch (rc) {
            0 => {},
            m.MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED => return error.Corruption,
            m.MBEDTLS_ERR_NET_UNKNOWN_HOST => return error.UnknownHost,
            m.MBEDTLS_ERR_NET_SOCKET_FAILED => return error.SocketFailed,
            m.MBEDTLS_ERR_NET_CONNECT_FAILED => return error.ConnectionFailed,
            else => unreachable,
        }
    }

    pub const SSLEndpoint = enum(u2) { IS_CLIENT, IS_SERVER };
    pub const SSLPreset = enum(u2) { DEFAULT, SUITEB };

    const SSLConfigError = error{ Corruption, BadInputData };

    pub fn sslConfDefaults(self: *mbedTLS, ep: SSLEndpoint, pro: Proto, pre: SSLPreset) SSLConfigError!void {
        const rc = switch (pre) {
            .SUITEB => c.mbedtls_ssl_config_defaults(self.ssl_conf, @enumToInt(ep), @enumToInt(pro), m.MBEDTLS_SSL_PRESET_SUITEB),
            .DEFAULT => c.mbedtls_ssl_config_defaults(self.ssl_conf, @enumToInt(ep), @enumToInt(pro), m.MBEDTLS_SSL_PRESET_DEFAULT),
        };

        switch (rc) {
            0 => {},
            m.MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED => return error.Corruption,
            m.MBEDTLS_ERR_MPI_BAD_INPUT_DATA => return error.BadInputData,
            else => unreachable,
        }
    }

    pub const SSLVerify = enum(u2) { NONE, OPTIONAL, REQUIRED };

    pub fn sslConfAuthmode(self: *mbedTLS, verify: SSLVerify) void {
        c.mbedtls_ssl_conf_authmode(self.ssl_conf, @enumToInt(verify));
    }

    const rng_cb = fn (?*anyopaque, [*c]u8, usize) callconv(.C) c_int;

    pub fn sslConfRng(self: *mbedTLS, f_rng: ?rng_cb) void {
        if (f_rng) |cb| {
            c.mbedtls_ssl_conf_rng(self.ssl_conf, cb, self.drbg);
        } else {
            c.mbedtls_ssl_conf_rng(self.ssl_conf, c.mbedtls_ctr_drbg_random, self.drbg);
        }
    }

    fn dbgfn(ctx: ?*anyopaque, level: c_int, file: [*c]const u8, line: c_int, str: [*c]const u8) callconv(.C) void {
        _ = ctx;
        _ = level;
        std.debug.print("{s}:{}: {s}", .{ file, line, str });
    }

    const debug_fn = fn (?*anyopaque, c_int, [*c]const u8, c_int, [*c]const u8) callconv(.C) void;

    pub fn setConfDebug(self: *mbedTLS, debug: ?debug_fn) void {
        var stdout = io.getStdOut().handle;

        if (debug) |dbg| {
            c.mbedtls_ssl_conf_dbg(self.ssl_conf, dbg, &stdout);
        } else {
            c.mbedtls_ssl_conf_dbg(self.ssl_conf, dbgfn, &stdout);
        }
    }

    pub fn sslConfCaChain(self: *mbedTLS, ca_chain: ?*c.mbedtls_x509_crt) void {
        // TODO: Add CRL support
        if (ca_chain) |ca| {
            c.mbedtls_ssl_conf_ca_chain(self.ssl_conf, ca, 0);
        } else {
            c.mbedtls_ssl_conf_ca_chain(self.ssl_conf, self.ca_chain, 0);
        }
    }

    const SSLSetupError = error{ OutOfMemory, Corruption };

    pub fn sslSetup(self: *mbedTLS) SSLSetupError!void {
        const rc = c.mbedtls_ssl_setup(self.ssl, self.ssl_conf);
        switch (rc) {
            0 => {},
            m.MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED => return error.Corruption,
            m.MBEDTLS_ERR_SSL_ALLOC_FAILED => return error.OutOfMemory,
            else => unreachable,
        }
    }

    pub fn sslSetBIO(self: *mbedTLS) void {
        c.mbedtls_ssl_set_bio(self.ssl, self.server_fd, c.mbedtls_net_send, c.mbedtls_net_recv, null);
    }

    const SSLHandshakeError = error{ Success, WantWrite, WantRead, Corruption, BadInputData, FeatureUnavailable, CipherBadInputData, CipherHardwareAccelFailed, CipherFeatureUnavailable, CipherInvalidContext, InvalidContext, ConnectionReset, SendFailed, HardwareAccelFailed, CompressionFailed, BufferTooSmall };

    pub fn sslHandshake(self: *mbedTLS) SSLHandshakeError!bool {
        const rc = c.mbedtls_ssl_handshake(self.ssl);
        return switch (rc) {
            m.MBEDTLS_ERR_SSL_WANT_WRITE => error.WantWrite,
            m.MBEDTLS_ERR_SSL_WANT_READ => error.WantRead,
            m.MBEDTLS_ERR_SSL_BAD_INPUT_DATA => error.BadInputData,
            m.MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE => error.FeatureUnavailable,
            m.MBEDTLS_ERR_NET_INVALID_CONTEXT => error.InvalidContext,
            m.MBEDTLS_ERR_NET_CONN_RESET => error.ConnectionReset,
            m.MBEDTLS_ERR_NET_SEND_FAILED => error.SendFailed,
            m.MBEDTLS_ERR_SSL_HW_ACCEL_FAILED => error.HardwareAccelFailed,
            m.MBEDTLS_ERR_SSL_COMPRESSION_FAILED => error.CompressionFailed,
            m.MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL => error.BufferTooSmall,
            else => return true,
        };
    }

    const SSLHostnameError = error{ BadInputData, OutOfMemory };

    pub fn setHostname(self: *mbedTLS, hostname: []const u8) SSLHostnameError!void {
        const rc = c.mbedtls_ssl_set_hostname(self.ssl, hostname.ptr);
        switch (rc) {
            0 => {},
            m.MBEDTLS_ERR_SSL_BAD_INPUT_DATA => return error.BadInputData,
            m.MBEDTLS_ERR_SSL_ALLOC_FAILED => return error.OutOfMemory,
            else => unreachable,
        }
    }

    const SeedError = error{ GenericError, Corruption, BadInputData, InvalidKeyLength, InvalidInputLength, OutOfMemory };

    pub fn ctrDrbgSeed(self: *mbedTLS, additional: ?[]const u8) SeedError!void {
        var rc: c_int = 1;

        if (additional) |str| {
            rc = c.mbedtls_ctr_drbg_seed(self.drbg, self.entropyfn, self.entropy, str.ptr, str.len);
        } else {
            rc = c.mbedtls_ctr_drbg_seed(self.drbg, self.entropyfn, self.entropy, 0x0, 0x0);
        }

        switch (rc) {
            0 => {},
            m.MBEDTLS_ERR_ERROR_GENERIC_ERROR => return error.GenericError,
            m.MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED => return error.Corruption,
            m.MBEDTLS_ERR_AES_BAD_INPUT_DATA => return error.BadInputData,
            m.MBEDTLS_ERR_AES_INVALID_KEY_LENGTH => return error.InvalidKeyLength,
            m.MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH => return error.InvalidInputLength,
            else => unreachable,
        }
    }

    pub const SSLWriteError = error{ Corruption, BadInputData, FeatureUnavailable, WantWrite, WantRead };

    pub fn sslWrite(self: *mbedTLS, str: []const u8) SSLWriteError!i32 {
        const rc = c.mbedtls_ssl_write(self.ssl, str.ptr, str.len);

        return switch (rc) {
            m.MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED => error.Corruption,
            m.MBEDTLS_ERR_SSL_BAD_INPUT_DATA => error.BadInputData,
            m.MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE => error.FeatureUnavailable,
            m.MBEDTLS_ERR_SSL_WANT_WRITE => error.WantWrite,
            m.MBEDTLS_ERR_SSL_WANT_READ => error.WantRead,
            else => rc,
        };
    }

    pub const SSLReadError = error{ Corruption, BadInputData, FeatureUnavailable, WantWrite, WantRead, PeerCloseNotify };

    pub fn sslRead(self: *mbedTLS, buffer: []u8) SSLReadError!i32 {
        const rc = c.mbedtls_ssl_read(self.ssl, buffer.ptr, buffer.len);

        return switch (rc) {
            m.MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED => error.Corruption,
            m.MBEDTLS_ERR_SSL_BAD_INPUT_DATA => error.BadInputData,
            m.MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE => error.FeatureUnavailable,
            m.MBEDTLS_ERR_SSL_WANT_WRITE => error.WantWrite,
            m.MBEDTLS_ERR_SSL_WANT_READ => error.WantRead,
            m.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY => error.PeerCloseNotify,
            else => rc,
        };
    }

    pub fn deinit(self: *mbedTLS) void {
        c.mbedtls_net_close(self.server_fd);
        c.zmbedtls_ssl_config_free(self.ssl_conf);

        self.allocator.destroy(self.server_fd);
        self.allocator.destroy(self.entropy);
        self.allocator.destroy(self.ssl);
        self.allocator.destroy(self.drbg);
        self.allocator.destroy(self.ca_chain);
        self.* = undefined;
    }
};

const ArenaAllocator = std.heap.ArenaAllocator;
const PageAllocator = std.heap.page_allocator;
var arena = ArenaAllocator.init(PageAllocator);

test "initialize mbedtls" {
    var mbed = try mbedTLS.init(&arena.allocator);
    defer mbed.deinit();

    expectEqual(@as(c_int, -1), mbed.server_fd.fd);
}

test "load certificate file" {
    const cafile = "cacert.pem";
    var mbed = try mbedTLS.init(&arena.allocator);
    defer mbed.deinit();

    expectEqual(@as(c_int, 0), mbed.ca_chain.*.version);
    try mbed.x509CrtParseFile(cafile);
    expectEqual(@as(c_int, 3), mbed.ca_chain.*.version);
}

test "run seed function" {
    var mbed = try mbedTLS.init(&arena.allocator);
    defer mbed.deinit();

    expectEqual(mbed.drbg.entropy_len, 0);

    // Check that it works with additional data and without
    try mbed.ctrDrbgSeed(null);
    try mbed.ctrDrbgSeed("SampleDevice");
    expectEqual(mbed.drbg.entropy_len, 48);
}

test "connect to host" {
    const cafile = "cacert.pem";
    var mbed = try mbedTLS.init(&arena.allocator);
    defer mbed.deinit();

    try mbed.x509CrtParseFile(cafile);
    try mbed.ctrDrbgSeed("SampleDevice");
    expectError(error.UnknownHost, mbed.netConnect("google.zom", "443", mbedTLS.Proto.TCP));
    expectEqual(mbed.server_fd.fd, -1);

    try mbed.netConnect("google.com", "443", mbedTLS.Proto.TCP);
    expect(mbed.server_fd.fd > -1);
}

test "set hostname" {
    var mbed = try mbedTLS.init(&arena.allocator);
    defer mbed.deinit();

    const excessive =
        \\ qiqQuz2BRgENxEBUhbMTp0bimui7axuo7jy4WNbopNrNnWSkypugXLNFeionxlwAUhSxlMkVsyc6VGmRTz0gUG
        \\ A3KRDbPCUBPiM7JsdgpI7rLP8EakT5cok2gF6KkAeVr7gfHNdg4auaEDHQfcp5OcLPIQnlVzt4OWSvRl2cOX3G
        \\ V8haOdljSwnmptEWSwFWe2FVsj0s8orr5JGNi91kLrTTpPzaXSoClrGTuireAlLaGExuer1Ue7LAAypC2FWV"
    ;

    expectError(error.BadInputData, mbed.setHostname(excessive));
}

test "can write a request" {
    const cafile = "cacert.pem";
    var mbed = try mbedTLS.init(&arena.allocator);
    defer mbed.deinit();

    try mbed.x509CrtParseFile(cafile);
    try mbed.ctrDrbgSeed("SampleDevice");
    try mbed.netConnect("google.com", "443", mbedTLS.Proto.TCP);
    try mbed.setHostname("zig-mbedtls");
    const req = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";

    const ret = try mbed.sslWrite(req);
    expect(ret > 0);
}

// This test is very sketchy and will break on any ssl_conf struct changes in
// mbedTLS. Disable if too much hassle too maintain
test "set ssl defaults and presets" {
    const Preset = mbedTLS.SSLPreset;
    const Endpoint = mbedTLS.SSLEndpoint;
    const Proto = mbedTLS.Proto;
    var mbed = try mbedTLS.init(&arena.allocator);
    defer mbed.deinit();

    // We cant access these by field since the struct is opaque
    // These entries in the struct is on memory address 0x170 after base
    // If 0x00500000 is the base address, then:
    // 0x100500170: 3 == unsigned char max_major_ver;
    // 0x100500171: 3 == unsigned char max_minor_ver;
    // 0x100500172: 3 == unsigned char min_major_ver;
    // 0x100500173: 1 == unsigned char min_minor_ver;
    const memaddr: usize = @ptrToInt(mbed.ssl_conf);
    const max_major_ver: *u2 = @intToPtr(*align(1) u2, memaddr + 0x170);
    const max_minor_ver: *u2 = @intToPtr(*align(1) u2, memaddr + 0x171);
    const min_major_ver: *u2 = @intToPtr(*align(1) u2, memaddr + 0x172);
    const min_minor_ver: *u2 = @intToPtr(*align(1) u2, memaddr + 0x173);

    expect(0 == max_major_ver.*);
    expect(0 == max_minor_ver.*);
    expect(0 == min_major_ver.*);
    expect(0 == min_minor_ver.*);
    try mbed.sslConfDefaults(Endpoint.IS_CLIENT, Proto.TCP, Preset.DEFAULT);
    expect(3 == max_major_ver.*);
    expect(3 == max_minor_ver.*);
    expect(3 == min_major_ver.*);
    expect(1 == min_minor_ver.*);
}

test "can do mbedtls_ssl_config workaround" {
    var a = c.zmbedtls_ssl_config_alloc();
    c.zmbedtls_ssl_config_init(a);
    var b = c.zmbedtls_ssl_config_defaults(a, 0, 0, 0);
    expectEqual(@as(c_int, 0), b);

    c.zmbedtls_ssl_config_free(a);
}

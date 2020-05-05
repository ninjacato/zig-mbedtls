const std = @import("std");
const c = @cImport({
    @cInclude("lib/zig_ssl_config.h");
    @cInclude("mbedtls/entropy.h");
    @cInclude("mbedtls/ctr_drbg.h");
    @cInclude("mbedtls/net.h");
    @cInclude("mbedtls/ssl.h");
    @cInclude("mbedtls/x509.h");
    @cInclude("mbedtls/debug.h");
});

const os = std.os;
const Allocator = std.mem.Allocator;
const c_allocator = std.heap.c_allocator;
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;
const expect = std.testing.expect;
const assert = std.debug.assert;

const MBEDTLS_ERR_PK_ALLOC_FAILED   = -0x3F80;
const MBEDTLS_ERR_PK_BAD_INPUT_DATA = -0x3E80;
const MBEDTLS_ERR_PK_FILE_IO_ERROR  = -0x3E00;

const MBEDTLS_ERR_ERROR_GENERIC_ERROR       = -0x0001;
const MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED = -0x006E;

const MBEDTLS_ERR_AES_BAD_INPUT_DATA        = -0x0021;
const MBEDTLS_ERR_AES_INVALID_KEY_LENGTH    = -0x0020;
const MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH  = -0x0022;

const MBEDTLS_ERR_NET_UNKNOWN_HOST          = -0x0052;
const MBEDTLS_ERR_NET_SOCKET_FAILED         = -0x0042;
const MBEDTLS_ERR_NET_CONNECT_FAILED        = -0x0044;

const MBEDTLS_ERR_MPI_BAD_INPUT_DATA        = -0x0004;

const MBEDTLS_SSL_VERIFY_REQUIRED           = 2;

pub const mbedTLS = struct {
    server_fd: *c.mbedtls_net_context,
    ssl_conf: *c.mbedtls_ssl_config,
    ssl: *c.mbedtls_ssl_context,
    entropy: *c.mbedtls_entropy_context,
    drbg: *c.mbedtls_ctr_drbg_context,
    ca_chain: *c.mbedtls_x509_crt,
    entropyfn: @TypeOf(c.mbedtls_entropy_func),
    proto: Proto,
    allocator: *Allocator,

    pub fn init(allocator: *Allocator) !mbedTLS {
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

        return mbedTLS {
            .server_fd = net_ctx,
            .entropy = entropy_ctx,
            .ssl = ssl_ctx,
            .ssl_conf = @ptrCast(*c.mbedtls_ssl_config, ssl_config),
            .drbg = drbg_ctx,
            .ca_chain = ca_chain,
            .entropyfn = c.mbedtls_entropy_func,
            .proto = undefined,
            .allocator = allocator
        };
    }

    const X509Error = error {
        AllocationFailed,
        BadInputData,
        FileIoError,
        OutOfMemory,
    };

    pub fn x509CrtParseFile(self: *mbedTLS, cafile: []const u8) X509Error!void {
        const rc = c.mbedtls_x509_crt_parse_file(self.ca_chain, &cafile[0]);
        switch(rc) {
            0 => {},
            MBEDTLS_ERR_PK_ALLOC_FAILED => return error.AllocationFailed,
            MBEDTLS_ERR_PK_BAD_INPUT_DATA => return error.BadInputData,
            MBEDTLS_ERR_PK_FILE_IO_ERROR => return error.FileIoError,
            else => unreachable
        }
    }

    pub const Proto = enum(u2) { PROTO_TCP, PROTO_UDP };

    const ConnError = error {
        Corruption,
        UnknownHost,
        SocketFailed,
        ConnectionFailed,
        OutOfMemory
    };

    pub fn netConnect(self: *mbedTLS, host: [*]const u8, port: [*]const u8, proto: Proto) ConnError!void {  
        self.proto = proto;
        const rc = c.mbedtls_net_connect(self.server_fd, host, port, @enumToInt(proto)); 
        switch(rc) {
            0 => {},
            MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED => return error.Corruption,
            MBEDTLS_ERR_NET_UNKNOWN_HOST => return error.UnknownHost,
            MBEDTLS_ERR_NET_SOCKET_FAILED => return error.SocketFailed,
            MBEDTLS_ERR_NET_CONNECT_FAILED => return error.ConnectionFailed,
            else => unreachable
        }

    }  

    pub const SSLEndpoint = enum(u2) { IS_CLIENT, IS_SERVER };
    
    pub const SSLPreset = enum(u2) { DEFAULT, SUITEB };

    const SSLConfigError = error {
        Corruption,
        BadInputData
    };

    pub fn sslConfigDefaults(self: *mbedTLS, endpoint: SSLEndpoint, presets: SSLPreset) SSLConfigError!void {
        const rc = switch(presets) {
            .SUITEB => c.mbedtls_ssl_config_defaults(self.ssl_conf, @enumToInt(endpoint), @enumToInt(self.proto), 2),
            .DEFAULT => c.mbedtls_ssl_config_defaults(self.ssl_conf, @enumToInt(endpoint), @enumToInt(self.proto), 0),
            else => unreachable
        };
        
        switch(rc) {
            0 => {},
            MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED => return error.Corruption,
            MBEDTLS_ERR_MPI_BAD_INPUT_DATA => return error.BadInputData,
            else => unreachable
        }
    }

    const SeedError = error {
        GenericError,
        Corruption,
        BadInputData,
        InvalidKeyLength,
        InvalidInputLength,
        OutOfMemory
    };

    pub fn ctrDrbgSeed(self: *mbedTLS, additional: ?[]const u8) SeedError!void {
        var rc: c_int = 1;

        if(additional) |str| {
            // Nasty
            var custom = try std.mem.dupe(self.allocator, u8, str);
            defer self.allocator.free(custom);
            rc = c.mbedtls_ctr_drbg_seed(self.drbg, self.entropyfn, self.entropy, custom.ptr, str.len);
        } else {
            rc = c.mbedtls_ctr_drbg_seed(self.drbg, self.entropyfn, self.entropy, 0x0, 0x0);
        }

        switch(rc) {
            0 => {},
            MBEDTLS_ERR_ERROR_GENERIC_ERROR => return error.GenericError,
            MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED => return error.Corruption,
            MBEDTLS_ERR_AES_BAD_INPUT_DATA => return error.BadInputData,
            MBEDTLS_ERR_AES_INVALID_KEY_LENGTH => return error.InvalidKeyLength,
            MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH => return error.InvalidInputLength,
            else => unreachable
        }
    }

    pub fn deinit(self: *mbedTLS) void {
        if(self.server_fd.fd > 0)
            os.close(self.server_fd.fd);

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
    expectError(error.UnknownHost, mbed.netConnect("google.zom", "443", mbedTLS.Proto.PROTO_TCP));
    expectEqual(mbed.server_fd.fd, -1);

    try mbed.netConnect("google.com", "443", mbedTLS.Proto.PROTO_TCP);
    expect(mbed.server_fd.fd > -1);
}

// This test is very sketchy and will break on any ssl_conf struct changes in 
// mbedTLS. Disable if too much hassle too maintain
test "set ssl defaults and presets" {
    var mbed = try mbedTLS.init(&arena.allocator);
    defer mbed.deinit();

    // We dont have field access since ssl_conf is an opaque type, hence
    // there is no good way to test this function. That said, as a simple
    // sanity check I am here checking that the different version limits
    // for TLS versions in the struct is set to 3 after defaults is set.
    // These entries in the struct is on memor address 0x170 after base
    // If 0x00500000 is the base address, then:
    // 0x100500170: 3 == unsigned char max_major_ver; 
    // 0x100500171: 3 == unsigned char max_minor_ver;
    // 0x100500172: 3 == unsigned char min_major_ver;
    // 0x100500173: 1 == unsigned char min_minor_ver;
    const memaddr: usize = @ptrToInt(mbed.ssl_conf);
    const max_major_ver: *u2 = @intToPtr(*align(1) u2, memaddr+0x170);
    const max_minor_ver: *u2 = @intToPtr(*align(1) u2, memaddr+0x171);
    const min_major_ver: *u2 = @intToPtr(*align(1) u2, memaddr+0x172);
    const min_minor_ver: *u2 = @intToPtr(*align(1) u2, memaddr+0x173);

    expect(0 == max_major_ver.*);
    expect(0 == max_minor_ver.*);
    expect(0 == min_major_ver.*);
    expect(0 == min_minor_ver.*);
    try mbed.sslConfigDefaults(mbedTLS.SSLEndpoint.IS_CLIENT, mbedTLS.SSLPreset.DEFAULT);
    expect(3 == max_major_ver.*);
    expect(3 == max_minor_ver.*);
    expect(3 == min_major_ver.*);
    expect(1 == min_minor_ver.*);
}

test "can do mbedtls_ssl_config workaround" {
    var a = c.zmbedtls_ssl_config_alloc();
    c.zmbedtls_ssl_config_init(a);    
    var b = c.zmbedtls_ssl_config_defaults(a);    
    expectEqual(@as(c_int, 0), b);

    c.zmbedtls_ssl_config_free(a);
}

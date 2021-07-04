const std = @import("std");
const Allocator = std.mem.Allocator;

const mbedTLS = @import("mbedtls").mbedTLS;

pub fn main() !void {
    const ArenaAllocator = std.heap.ArenaAllocator;
    const PageAllocator = std.heap.page_allocator;
    var arena = ArenaAllocator.init(PageAllocator);
    const cafile = "cacert.pem";
    var mbed = try mbedTLS.init(&arena.allocator);
    defer mbed.deinit();

    try mbed.x509CrtParseFile(cafile);
    try mbed.ctrDrbgSeed("SampleDevice");
    try mbed.netConnect("google.com", "443", mbedTLS.Proto.TCP);
    try mbed.sslConfDefaults(.IS_CLIENT, .TCP, .DEFAULT);

    mbed.sslConfAuthmode(.NONE);
    mbed.sslConfRng(null); //use default
    mbed.setConfDebug(null); // use default
    mbed.sslConfCaChain(null); // use parsed CA file from earlier

    try mbed.sslSetup(); // use parsed CA file from earlier
    try mbed.setHostname("hello");
    mbed.sslSetBIO();

    var run = true;
    while (run) {
        const r: bool = mbed.sslHandshake() catch |err| res: {
            switch (err) {
                error.WantRead => break :res false,
                error.WantWrite => break :res false,
                else => unreachable,
            }
        };

        run = !r;
    }

    const req = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
    var ret: i32 = 0;
    while (ret <= 0) {
        ret = try mbed.sslWrite(req);
    }

    ret = 0;
    while (true) {
        var buf: [1024]u8 = undefined;
        ret = try mbed.sslRead(buf[0..]);
        if (ret == 0) break;
        if (ret < 0) break;

        std.debug.warn("Bytes read {s}", .{buf});
        break;
    }

    return;
}

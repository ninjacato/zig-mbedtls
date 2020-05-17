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
    try mbed.sslConfigDefaults(.IS_CLIENT, .TCP, .DEFAULT);

    mbed.sslConfAuthmode(.NONE);
    mbed.sslConfRng(null); //use default
    mbed.setDebug(null); // use default

    try mbed.setHostname("hello"); // use default
    const req = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
    const ret = try mbed.sslWrite(req);
    return;
}

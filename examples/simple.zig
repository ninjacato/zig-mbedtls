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
    try mbed.netConnect("google.com", "443", mbedTLS.Proto.PROTO_TCP);
    try mbed.sslConfigDefaults(mbedTLS.SSLEndpoint.IS_CLIENT, mbedTLS.SSLPreset.DEFAULT);
    
    return;
}

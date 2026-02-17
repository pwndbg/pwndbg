// This binary is there to test commands that access memory
// like dq, dd, dw, db, dc etc.

#include <stdint.h>

// Use arrays directly with aligned attribute to ensure contiguous layout
// The aligned attribute ensures data2 starts right after data
uint64_t __attribute__((aligned(8))) data[] = {
    0x0, 0x1, 0x0000000100000002, 0x0001000200030004, 0x0102030405060708};

uint64_t __attribute__((aligned(8))) data2[] = {
    0x1122334455667788, 0x0123456789abcdef, 0x0,
    0xffffffffffffffff, 0x0011223344556677, 0x8899aabbccddeeff};

char short_str[] = "some cstring here";

char long_str[] =
    "long string: "
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAA";

int main() { return 0; }

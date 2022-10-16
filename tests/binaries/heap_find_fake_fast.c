/* Test the find_fake_fast command.
 *
 * No need to test the output as find_fake_fast wraps malloc_chunk,
 * which can be tested separately.
 *
 * Just test for the command completing without a crash.
 * Purposefully pass a fake chunk with no parent arena, with a set
 * NON_MAIN_ARENA flag to ensure no error occurs when attempting to read
 * the non-existent heap_info struct - issue #1142
 */

#include <stdlib.h>
#include <assert.h>

void break_here(void) {}

// Fake chunk size field with a set NON_MAIN_ARENA flag.
// Enough space afterwards to ensure only this fake size field is a candidate.
char fake_chunk[0x80] __attribute__((aligned(0x10))) = "XXXXXXXX\x7f";

// This buffer will contain the fake chunk sizes
unsigned long buf[64] __attribute__((aligned(0x10)));

// This is the address we want the fake chunks to overlap with
unsigned long target_address;

/**
 * Put the value of `size` at `distance` bytes before the address of
 * `target_address`
 */
void setup_mem(unsigned long size, unsigned distance) {
    memset(buf, 0, sizeof(buf));
    target_address = 0;

    char *chunk_size_addr = (char*)&target_address - distance;
    *(unsigned long*)chunk_size_addr = size;
}

int main(void) {
    assert((unsigned long)&target_address - (unsigned long)buf == sizeof(buf));
    // Initialize malloc so heap commands can run.
    void* m = malloc(0x18);

    // A valid aligned fastbin chunk with no flags set
    setup_mem(0x20, 0x8);
    break_here();

    // A valid aligned fastbin chunk with all flags set
    setup_mem(0x2F, 0x8);
    break_here();

    // A valid unaligned fastbin chunk
    setup_mem(0x20, 0x9);
    break_here();

    // A valid aligned fastbin chunk that's too close to the target address (the
    // size overlaps the target address)
    setup_mem(0x20, 0x0);
    break_here();

    // A valid unaligned fastbin chunk that's too close to the target address (the
    // size overlaps the target address)
    setup_mem(0x20, 0x7);
    break_here();

    // An invalid chunk with a size below the minimum chunk size
    setup_mem(0x1F, 0x8);
    break_here();

    // A valid aligned fastbin chunk just in range of the target address
    setup_mem(0x80, 0x78);
    break_here();

    // A valid unaligned fastbin chunk just in range of the target address
    /* setup_mem(0x80, 0x7F); */
    /* break_here(); */

    // A valid aligned fastbin chunk just out of range of the target address
    setup_mem(0x80, 0x80);
    break_here();

    // A fastbin chunk with a size greater than `global_max_fast`, less than
    // `global_max_fast` bytes away from the target address
    setup_mem(0x100, 0x10);
    break_here();

    // A fastbin chunk with a size greater than `global_max_fast`, more than
    // `global_max_fast` bytes away from the target address
    setup_mem(0x100, 0x90);
    break_here();

    // A fastbin chunk with a size greater than `global_max_fast`, just out of
    // range of the target address
    setup_mem(0x100, 0x100);
    break_here();
}

// Test the find_fake_fast command.

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

// Part of this test requires unmapped virtual memory at a specific alignment.
#define LIKELY_UNMAPPED_MEMORY_ADDRESS (void*)0x500000000000

/* GLIBC's HEAP_MAX_SIZE constant, used to align the aforementioned unmapped virtual memory.
 * HEAP_MAX_SIZE is defined at:
 * https://github.com/bminor/glibc/blob/f704192911c6c7b65a54beab3ab369fca7609a5d/malloc/arena.c#L31
 * It is calculated using DEFAULT_MMAP_THRESHOLD_MAX, which is defined at:
 * https://github.com/bminor/glibc/blob/f704192911c6c7b65a54beab3ab369fca7609a5d/malloc/malloc.c#L956
 * (x64 architecture is assumed for this test)
 */
#define HEAP_MAX_SIZE (2 * 4 * 1024 * 1024 * sizeof(long))

void break_here(void) {}

// Fake chunk size field for use with issue #1142 test.
char* fake_chunk = NULL;

// This buffer will contain the fake chunk sizes
unsigned long buf[64] __attribute__((aligned(0x10)));

// This is the address we want the fake chunks to overlap with
unsigned long target_address;

/*
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

    /* Test whether the find_fake_fast command can deal with a fake chunk that has a set
     * NON_MAIN_ARENA flag, but no heap_info struct (the struct would reside in unmapped memory).
     * Issue #1142
     */
    void* aligned_memory = NULL;
    for (void* requested_address = LIKELY_UNMAPPED_MEMORY_ADDRESS; requested_address > 0; requested_address -= HEAP_MAX_SIZE)
    {
        // Attempt to find unmapped memory aligned to HEAP_MAX_SIZE.
        void* mmapped_address = mmap(requested_address, 2*getpagesize(), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (mmapped_address == requested_address)
        {
            aligned_memory = mmapped_address;
            break;
        }
        else
        {
            munmap(mmapped_address, 2*getpagesize());
        }
    }
    assert(aligned_memory != NULL);

    // Set up a candidate fake fast chunk size field with a set NON_MAIN_ARENA flag.
    fake_chunk = aligned_memory + getpagesize();
    fake_chunk[8] = '\x85';

    // Unmap the memory where the fake chunk's heap_info struct would reside.
    int unmapped = munmap(aligned_memory, getpagesize());
    assert(unmapped == 0);

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

    /* // A valid unaligned fastbin chunk just in range of the target address */
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

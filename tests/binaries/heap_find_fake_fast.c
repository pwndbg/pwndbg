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

void break_here(void) {}

// Fake chunk size field with a set NON_MAIN_ARENA flag.
// Enough space afterwards to ensure only this fake size field is a candidate.
char fake_chunk[0x80] __attribute__((aligned(0x10))) = "XXXXXXXX\x7f";

int main(void)
{
    // Initialize malloc so heap commands can run.
    void* m = malloc(0x18);

    break_here();
}

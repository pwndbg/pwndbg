/* Exercises the heap tracker (`track-heap enable`) on a realloc() that fails.
 *
 * `realloc(p, (size_t)-1)` requests an impossible size, so the allocator
 * returns NULL. Per the C standard the original block `p` is left untouched
 * and remains valid, so the final free(p) must succeed.
 *
 * Regression test for https://github.com/pwndbg/pwndbg/issues/3998: the tracker
 * used to call get_chunk() on the NULL return, reading a chunk header at
 * address 0 - sizeof(void*) and crashing with an uncaught
 * "Cannot access memory at address 0xfffffffffffffff8".
 */

#include <stdlib.h>

int main(void) {
    void *p = malloc(0x20);

    /* Impossible size: realloc() must fail and return NULL, leaving p valid. */
    void *r = realloc(p, (size_t)-1);
    if (r != NULL) {
        /* Not expected, but keep p pointing at the live block either way. */
        p = r;
    }

    free(p);
    return 0;
}

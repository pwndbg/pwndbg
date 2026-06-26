/* Exercises the heap tracker (`track-heap enable`) printer.
 *
 * The allocations are arranged so a test can verify that:
 *   - a realloc()'d pointer is colorized in the report and shares its color
 *     with the later free() of that same pointer, and
 *   - realloc(ptr, 0) is handled gracefully (it must only print a warning,
 *     never raise a Python exception or leave the tracker in a bad state).
 *
 * `break_here()` is called before any allocation so a test can enable the
 * tracker at that point and then let the allocations run.
 */

#include <stdlib.h>

void break_here(void) {}

int main(void)
{
    break_here();

    char *b = malloc(32);

    /* A neighbouring allocation right after `b` so the realloc() below cannot
     * grow in place and is forced to move, giving a return pointer that
     * differs from the input pointer. */
    char *blocker = malloc(32);

    /* Reallocated (moved) pointer: its return value differs from `b`. It is
     * kept allocated until the end so its address is not reused, then freed -
     * the free() must share the realloc()'s color. */
    char *c = realloc(b, 4096);

    /* realloc(ptr, 0): implementation-defined, must not crash the tracker. */
    char *d = malloc(8);
    char *e = realloc(d, 0);

    free(c);

    (void)blocker;
    (void)e;
    return 0;
}

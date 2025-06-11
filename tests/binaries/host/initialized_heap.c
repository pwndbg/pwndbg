/* Initialize the main arena by requesting a single chunk.
 * For general GLIBC malloc testing.
 */

#include <stdlib.h>

void break_here(void) {}

int main(void)
{
    __attribute__((unused))
    void* m = malloc(1);

    break_here();

    return 0;
}

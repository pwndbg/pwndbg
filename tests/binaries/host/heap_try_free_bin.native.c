/* For testing the try-free command.
 *
 * Free a small chunk into its bin and corrupt its bk. On glibc < 2.41 the chunk
 * goes into the unsorted bin, on glibc >= 2.41 straight into its smallbin. Freeing
 * another chunk of the same size makes glibc check the bin and abort.
 */

#include <stdlib.h>

void break_here(void) {}

void* victim = NULL;
void* to_free = NULL;

int main(void)
{
    // The default tcache count was 7 and is 16 since glibc 2.43, free more
    // than that so the tcache is full whatever the version
    void* tcache_fill[64];

    for (int i = 0; i < 64; i++) {
        tcache_fill[i] = malloc(0x100);
        malloc(0x18); // so the chunks don't consolidate when freed
    }

    victim = malloc(0x100);
    malloc(0x18);
    to_free = malloc(0x100);
    malloc(0x18); // so to_free isn't next to the top chunk

    for (int i = 0; i < 64; i++)
        free(tcache_fill[i]);

    free(victim);
    ((size_t*)victim)[1] = (size_t)to_free; // victim->bk = to_free

    break_here();

    return 0;
}

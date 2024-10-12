/* For testing the search command.
 *
 * We just spray some known patterns into memory
 */

#include <stdlib.h>
#include <string.h>

void break_here(void) {}

size_t marker = 0xABCDEF1234567890;

static const char* literal = "Hello!";

int main(void)
{
    void *p;
    size_t *heap_marker;
    size_t local_marker;

    p = malloc(0x100000);
    memset(p, 0x0, 0x100000);

    // Pattern we want to find with -i 0x1000
    for (int i = 0; i < 0x100000; i += 0x100) {
        *(unsigned int *)(p + i) = 0xd00dbeef;
    }

    // Pattern we want to avoid with -a 0x8
    for (int i = 0; i < 0x100000; i += 0x100) {
        *(unsigned int *)(p + i + 0x17) = 0xd00dbeef;
    }

    heap_marker = malloc(8);
    *heap_marker = marker;
    local_marker = marker;

    break_here();

    return 0;
}


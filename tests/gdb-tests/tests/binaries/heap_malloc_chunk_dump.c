#include <stdlib.h>
#include <string.h>


#define INTERNAL_SIZE_T size_t
#define SIZE_SZ (sizeof (INTERNAL_SIZE_T))
#define CHUNK_HDR_SZ (2 * SIZE_SZ)
#define mem2chunk(mem) ((void*)(mem) - CHUNK_HDR_SZ)

void break_here(void) {}

void* test_chunk = NULL;

int main() {
    char* str = (char*)malloc(0x20);
    strncpy(str, "This is a test string", 0x20);

    test_chunk = mem2chunk(str);

    break_here();

    free(test_chunk);

    return 0;
}

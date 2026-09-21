#include <stdlib.h>
#include <stdint.h>

void *do_alloc(void) {
    return malloc(0x18);
}

void *do_realloc(void *p) {
    return realloc(p, 0x30);
}

void *do_failed_realloc(void *p) {
    volatile size_t impossible_size = SIZE_MAX;
    return realloc(p, impossible_size);
}

int main(void) {
    void *p = do_alloc();
    p = do_realloc(p);
    void *failed = do_failed_realloc(p);
    if (failed != NULL) {
        free(failed);
        return 1;
    }
    free(p);
    return 0;
}

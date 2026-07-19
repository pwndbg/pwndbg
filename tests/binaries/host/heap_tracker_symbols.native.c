#include <stdlib.h>

void *do_alloc(void) {
    return malloc(0x18);
}

void *do_realloc(void *p) {
    return realloc(p, 0x30);
}

int main(void) {
    void *p = do_alloc();
    p = do_realloc(p);
    free(p);
    return 0;
}

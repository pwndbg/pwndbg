#include <stdint.h>

struct dt3076_bitfields {
    void *a;
    void *b;
    uintptr_t last_idx : 5;
    uintptr_t freeable : 1;
    uintptr_t sizeclass : 6;
};

struct dt3076_bitfields global_bf = {
    .a = (void *)0x11,
    .b = (void *)0x22,
    .last_idx = 3,
    .freeable = 1,
    .sizeclass = 7,
};

void break_here(void) {}

int main(void)
{
    break_here();
    return 0;
}

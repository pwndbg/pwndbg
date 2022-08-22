#include <stdio.h>
#include <stdlib.h>

void break_here() {}

int main() {
    void* allocs[6] = {0};

    allocs[0] = malloc(10);
    allocs[1] = malloc(10);

    break_here();

    allocs[2] = malloc(40);

    break_here();

    free(allocs[1]);

    break_here();
}

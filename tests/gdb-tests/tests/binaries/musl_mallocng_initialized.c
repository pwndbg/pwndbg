#include <stdlib.h>

void break_here(void) {}

int main(void) {

    char *p = malloc(10);
    break_here();
}

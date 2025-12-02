#include <stdio.h>
#include <string.h>

void inner_function(void) {
    char buffer[64];
    int local_var = 42;

    strcpy(buffer, "Hello from inner function!");

    printf("local_var = %d\n", local_var);
    printf("buffer = %s\n", buffer);
}

void outer_function() {
    inner_function();
}

int main() {
    printf("Starting test program...\n");
    outer_function();
    printf("Done\n");
    return 0;
}

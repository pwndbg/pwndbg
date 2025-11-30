#include <stdio.h>
#include <string.h>

void inner_function(int param1, int param2) {
    char buffer[64];
    int local_var = 42;
    long another_var = 0x1234567890ABCDEF;

    strcpy(buffer, "Hello from inner function!");

    printf("param1 = %d\n", param1);
    printf("param2 = %d\n", param2);
    printf("local_var = %d\n", local_var);
    printf("another_var = 0x%lx\n", another_var);
    printf("buffer = %s\n", buffer);

    // Breakpoint here to inspect stack
    asm("int3");
}

void outer_function() {
    int meow1 = 100;
    int meow2 = 200;
    int meow3 = 300;

    printf("meow1 = %d, meow2 = %d, meow3 = %d\n", meow1, meow2, meow3);

    inner_function(meow1, meow2);
}

int main() {
    printf("Starting test program...\n");
    outer_function();
    printf("Done!\n");
    return 0;
}

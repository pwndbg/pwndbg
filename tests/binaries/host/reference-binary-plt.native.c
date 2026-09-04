#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void break_here() {};

int main(int argc, char const* argv[]) {
    puts("Hello World");
    printf("Hello world again %d", argc);

    write(0,"Hello",6);

    srand(0);

    break_here();

    return 0;
}

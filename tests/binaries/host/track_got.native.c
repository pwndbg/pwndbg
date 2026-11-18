#include <stdio.h>
#include <stdlib.h>

void break_here() {};

int main(int argc, char const* argv[]) {
    break_here();

    for (int i = 0; i < 3; i++)
        puts("Hello World");

    break_here();

    srand(1);
    srand(2);

    break_here();

    return 0;
}

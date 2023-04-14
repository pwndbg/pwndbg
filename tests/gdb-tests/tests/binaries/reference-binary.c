#include <stdio.h>

void break_here() {};

int main(int argc, char const* argv[]) {
    puts("Hello World");

    break_here();

    return 0;
}

#include <stdio.h>

const char short_str[] = "some cstring here";

void break_here() {};

int main(int argc, char const* argv[]) {
    puts("Hello World");

    break_here();

    return 0;
}

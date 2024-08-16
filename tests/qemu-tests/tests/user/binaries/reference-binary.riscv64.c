#include <stdio.h>

int main(int argc, char const* argv[]) {
    if (argc > 1) {
        puts("Enough args");
    } else {
        puts("Not enough args");
    }
    return 0;
}

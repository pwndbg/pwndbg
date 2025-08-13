#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
    // Allocate a chunk and fill it with zeros to test collapsing
    char *a = malloc(256);
    memset(a, 0, 256);

    // Allocate a second chunk
    char *b = malloc(128);

    // Keep the program running so we can attach to it
    while(1) {
        sleep(1);
    }
    return 0;
}

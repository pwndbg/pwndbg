#include <stdio.h>
#include <stdlib.h>

#include <pthread.h>

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

    // We do not really need it for our test
    // but we need it so that our CI test pass can get TLS variables
    // See:
    // - https://github.com/pwndbg/pwndbg/pull/1086
    // - https://sourceware.org/bugzilla/show_bug.cgi?id=24548
    pthread_create(0,0,0,0);
}

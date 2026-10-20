// Creates an anonymous pipe(2) so that pwndbg's procinfo command has a known
// pair of pipe FDs to introspect: a read end and a write end held by the
// same process.

#include <stdio.h>
#include <unistd.h>

void break_here() {};

int main(void) {
    int fds[2];
    if (pipe(fds) < 0) {
        perror("pipe");
        return 1;
    }

    break_here();

    close(fds[0]);
    close(fds[1]);
    return 0;
}

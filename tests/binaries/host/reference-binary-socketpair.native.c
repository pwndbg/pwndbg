// Creates a unix-domain socketpair so that pwndbg's procinfo command has a
// pair of connected anonymous unix sockets to introspect peer info on.

#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>

void break_here() {};

int main(void) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        perror("socketpair");
        return 1;
    }

    break_here();

    close(fds[0]);
    close(fds[1]);
    return 0;
}

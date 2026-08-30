// Creates two anonymous pipes split across a fork so that procinfo has both
// kinds of pipe peers to find:
//   - "own":   the parent keeps the read AND write end (same-process peer)
//   - "cross": the parent keeps the read end, the child keeps the write end
//     (cross-process peer - only discoverable through a system-wide FD walk)
//
// The child sleeps for a bounded time and exits on its own, so nothing leaks
// even if the test harness never gets to kill it.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void break_here() {}

int main(void) {
    int own[2];
    int cross[2];

    if (pipe(own) < 0 || pipe(cross) < 0) {
        perror("pipe");
        return 1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        close(cross[0]);
        close(own[0]);
        close(own[1]);
        sleep(60);
        _exit(0);
    }

    close(cross[1]);

    break_here();

    close(own[0]);
    close(own[1]);
    close(cross[0]);
    return 0;
}

#include <stdio.h>

volatile int stdin_value;

__attribute__((noinline)) void break_here(void) {}

int main(void) {
    char input[16];
    if (fgets(input, sizeof(input), stdin) == NULL) {
        return 1;
    }

    for (int i = 0; input[i] >= '0' && input[i] <= '9'; i++) {
        stdin_value = stdin_value * 10 + input[i] - '0';
    }

    printf("stdout: %d\n", stdin_value);
    fflush(stdout);
    fprintf(stderr, "stderr: %d\n", stdin_value);
    fflush(stderr);

    break_here();
    return 0;
}

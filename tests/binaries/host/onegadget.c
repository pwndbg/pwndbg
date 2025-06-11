#include <string.h>

#define BUF_SIZE 0x1000

char buf[BUF_SIZE] = {};

void break_here(char **argv, char **envp){}

int main(int argc, char* argv[], char* envp[]) {
    char *valid_argv[] = {"xxxx", NULL};
    memset(buf, 0, BUF_SIZE);
    break_here(valid_argv, envp);
    return 0;
}
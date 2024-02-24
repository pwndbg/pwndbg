#include <string.h>

#define BUF_SIZE 0x1000

char buf[BUF_SIZE] = {};

void break_here(char **envp){}

int main(int argc, char* argv[], char* envp[]) {
    memset(buf, 0, BUF_SIZE);
    break_here(envp);
    return 0;
}
#include <unistd.h>
#include <sys/syscall.h>

char* str = "hello";

int main(int argc, char const* argv[])
{
    // Starting from main, this program has about ~1500 instructions until exit in most arches
    syscall(SYS_write,1,str,5);
    return 0;
}


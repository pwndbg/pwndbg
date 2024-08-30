#include <stdlib.h>
#include <jemalloc/jemalloc.h>

void break_here(void) {}

int main(void)
{

    // Allocate a small memory
    char *ptr = (char *)malloc(2 * sizeof(char));
    ptr[0] = 'A';
    ptr[1] = 'B';

    // Allocate a large memory
    char *ptr2 = (char *)malloc(3.7 * 1024 * 1024);
    ptr2[0] = 'A';
    ptr2[1] = 'B';
    
    break_here();

}
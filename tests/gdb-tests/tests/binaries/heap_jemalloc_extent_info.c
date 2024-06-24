#include <stdlib.h>
#include <jemalloc/jemalloc.h>

void break_here(void) {}

int main(void)
{

    char *ptr = (char *)malloc(2 * sizeof(char));
    ptr[0] = 'A';
    ptr[1] = 'B';
    
    break_here();

}
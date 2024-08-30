#include <stdlib.h>
#include <jemalloc/jemalloc.h>

void break_here(void) {}

char *ptr = NULL;

int main(void)
{

    ptr = (char *)malloc(2 * sizeof(char));
    ptr[0] = 'A';
    ptr[1] = 'B';
    
    break_here();

}
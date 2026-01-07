#include <stdio.h>

void func_with_args(int a, int b, int c, int d, int e, int f)
{
    printf("a=%d\n", a);
}

int main()
{
    func_with_args(0x10, 0x20, 0x30, 0x40, 0x50, 0x60);
    return 0;
}

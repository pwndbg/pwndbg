#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct A {
    void* func_ptr;
    void* stack_ptr;
    void* heap_ptr;
    char buf[16];
    char gap[128];
};

void break_here() {}

int main() {
    struct A a = {};
    a.func_ptr = (void*)main;
    a.stack_ptr = (void*) &a;
    a.heap_ptr = malloc(10);
    strcpy(a.buf, "aaa");
    break_here();
}

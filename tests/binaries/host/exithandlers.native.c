#include <stdlib.h>
#include <pthread.h>
#include <malloc.h>

extern int __cxa_thread_atexit_impl (void (*dtor) (void *), void *obj,
                              void *dso_symbol);
void break_here() {}

int main(int argc, char* argv[])  {
    atexit((void(*)(void))0xdeadbeef);
    on_exit((void (*)(int,  void *))system, "/bin/whoami");
    __cxa_thread_atexit_impl(
        (void (*)(void *))0xcafebabe,
        (void*)0xfeedface,
        (void*)0xd00df00d
    );
    break_here();
}

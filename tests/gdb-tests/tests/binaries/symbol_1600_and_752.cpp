void break_here(void* p) { }

struct A {
    __attribute__((noinline))
    void foo(int, int) { break_here(0); }

    void call_foo() { foo(1, 2); }
};

int main() {
    break_here((void*)main);
    break_here((void*)break_here);

    // code for issue 1600
    break_here((void*)&A::foo);

    // just another check for mangled symbols
    break_here((void*)&A::call_foo);

    // code for issue 752
    A a;
    a.call_foo();
}

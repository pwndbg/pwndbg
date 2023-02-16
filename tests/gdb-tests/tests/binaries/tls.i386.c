void *tls_address;

void break_here(void) {}

int main(){
    // TODO: This only works for i386, we should support arm/aarch64 in the future
    asm("movl %%gs:0, %0" : "=r" (tls_address));
    break_here();
    return 0;
}
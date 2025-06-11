void *tls_address;

void break_here(void) {}

int main(){
    // TODO: This only works for x86-64, we should support arm/aarch64 in the future
    asm("movq %%fs:0, %0" : "=r" (tls_address));
    break_here();
    return 0;
}
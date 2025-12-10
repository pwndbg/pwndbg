
__attribute__((naked))
void _start(void) {
#if defined(__x86_64__)
    // x86_64: guaranteed illegal instruction
    __asm__("ud2");
#elif defined(__i386__)
    // x86 (i386): guaranteed illegal instruction
    __asm__("ud2");
#elif defined(__aarch64__)
    // AArch64: undefined instruction
    __asm__("udf #0");
#elif defined(__arm__)
    // ARM32 (A32): UDF undefined instruction
    __asm__(".word 0xE7F000F0");
#elif defined(__riscv) || defined(__riscv__)
    // RISC-V: opcode=0 is not a valid instruction (illegal)
    __asm__(".word 0x00000000");
#elif defined(__powerpc64__) || defined(__ppc64__)
    // PowerPC64: reserved/illegal instruction
    __asm__(".long 0x00000000");
#elif defined(__powerpc__) || defined(__ppc__)
    // PowerPC32: reserved/illegal instruction
    __asm__(".long 0x00000000");
#elif defined(__mips__) && (__mips == 64)
    // MIPS64: reserved/illegal instruction
    __asm__(".word 0x00000000");
#elif defined(__mips__)
    // MIPS32: reserved/illegal instruction
    __asm__(".word 0x00000000");
#elif defined(__loongarch__) || defined(__loongarch64__)
    // LoongArch64: guaranteed illegal instruction
    __asm__(".word 0x002a0000");
#elif defined(__s390x__)
    // IBM Z (s390x): illegal instruction
    __asm__(".long 0x00000000");
#else
    #error "Unsupported architecture: no illegal instruction defined"
#endif
}
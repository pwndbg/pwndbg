global _start

CHAIN_LEN   equ 32

section .text

_start:
    sub     rsp, CHAIN_LEN * 8
    call    gadget_setup
    ud2

gadget_setup:
    mov     rdi, rsp
    mov     rax, self_ret
    mov     rcx, CHAIN_LEN - 1
    rep     stosq
    mov     rax, nop_sled
    stosq
self_ret:
    ret

nop_sled:
    times 64 nop
    mov     edi, 0
    mov     eax, 60
    syscall
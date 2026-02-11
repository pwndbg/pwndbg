global _start

_start:
A:
    mov     eax, 0
    cmp     eax, 1
    je      B
    add     eax, 2
    jmp     C

B:
    sub     eax, 1
    cmp     eax, 0
    jne     C
    nop
    nop

C:
    ret


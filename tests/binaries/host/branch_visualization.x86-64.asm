global _start

; This binary is there to test
; emulate vs nearpc/u/pdisas commands
; The emulate should show just jump and one nop
; The rest should show jump and two nops
;
; Motivated by https://github.com/pwndbg/pwndbg/issues/315

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


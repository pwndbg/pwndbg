global _start

_start:

; Memory lookup for the jump target will segfault

mov rbx, rsp
jmp [rbx]

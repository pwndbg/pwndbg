section .text
    global _start


_start:

mov rax, 1
add rsp, rax
mov rdx, 100
add rdx, rbx

times 1000 nop

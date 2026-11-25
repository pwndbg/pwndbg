section .text
    global _start

_start:
test_getcpu:
    mov rax, 309        ; syscall: getcpu
    mov rdi, 0          ; cpu: NULL
    mov rsi, 0          ; node: NULL
syscall_getcpu_label:
    syscall

test_exit_group:
    mov rax, 231        ; syscall: exit_group
    mov rdi, 0          ; status: 0
syscall_exit_group_label:
    syscall

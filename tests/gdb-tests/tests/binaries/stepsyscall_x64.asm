section .text
    global _start


write:
    mov rax, 1
    mov rdi, 1
    mov rsi, msg
    mov rdx, len
syscall_write_label:
    syscall
    ret

_start:
    nop
    jmp label1
    nop

label1:
    call write

exit:
    mov rax, 60
    mov rdi, 0

syscall_exit_label:
    syscall



section .data
    msg db 'hello world', 0xA
    len equ $ - msg
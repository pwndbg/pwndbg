section .text
    global _start


write_stdout:
    mov rax, 1          ; syscall: write
    mov rdi, 1          ; fd: stdout (1)
    mov rsi, msg
    mov rdx, len
syscall_write_stdout_label:
    syscall
    ret

write_stderr:
    mov rax, 1          ; syscall: write
    mov rdi, 2          ; fd: stderr (2)
    mov rsi, msg2
    mov rdx, len2
syscall_write_stderr_label:
    syscall
    ret

do_read:
    mov rax, 0          ; syscall: read
    mov rdi, 0          ; fd: stdin
    mov rsi, buf
    mov rdx, 1
syscall_read_label:
    syscall
    ret

_start:
    nop
    jmp label1
    nop

label1:
    call write_stdout
    call write_stderr

exit:
    mov rax, 60
    mov rdi, 0

syscall_exit_label:
    syscall



section .data
    msg db 'hello stdout', 0xA
    len equ $ - msg
    msg2 db 'hello stderr', 0xA
    len2 equ $ - msg2

section .bss
    buf resb 16
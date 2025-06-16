section .text
    global _start

_start:
    call function
    mov rax, 2
    mov rbx, 3
    add rax, rbx
    xor rax, rbx
    nop
    jmp exit

; make sure the entire function does not fit into the context disasm view
function:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ret

exit:
    mov rax, 60
    mov rdi, 0
    syscall


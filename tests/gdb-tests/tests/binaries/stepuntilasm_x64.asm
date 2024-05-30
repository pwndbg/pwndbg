section .text
    global _start
    global break_here
    global stop1
    global stop2
    global stop3
    global stop4
_start:
break_here:
    xor rax, rax
stop1:
    nop ; Stop point #1: No operands
stop2:
    xor rax, rax ; Stop point #2: Some simple operands

    lea rax, [some_data]
stop3:
    ; Stop point #3: More complex operands.
    mov qword [rax], 0x20

    call loop
    lea rax, [some_data]
stop4:
    ; Stop point #4: Even more complex operands, after loop.
    mov dword [rax+4], 0x20

exit:
    ; Terminate the process by calling sys_exit(0) in Linux.
    mov rax, 60
    mov rdi, 0
    syscall


; Loop subroutine. Loops for a while so we can test whether stepuntilasm can get
; to a directive that's sitting after a few iterations of a loop.
loop:
    mov rax, 100
loop_iter:
    sub rax, 1
    jnz loop_iter

    ret

section .bss
some_data: resq 1

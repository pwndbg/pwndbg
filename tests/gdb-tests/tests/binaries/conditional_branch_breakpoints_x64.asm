section .text
    global _start
    global break_here
    global break_here0
    global break_here1
    global branch0
    global branch1
    global branch2
    global branch3

_start:
break_here:
    mov rax, 0
    cmp rax, 0
branch0:
    ; Break on branch taken. Branch will be taken. (test for PC=branch0)
    jz branch0_done
branch0_done:
    nop
branch1:
    ; Break on branch taken. Branch will not be taken. (test for PC=break_here0)
    jnz branch1_done
branch1_done:
break_here0:
    mov rax, 10
    cmp rax, 0
branch2:
    ; Break on branch not taken. Branch will be taken. (test for PC=break_here1)
    jne branch2_done
branch2_done:
break_here1:
    nop
branch3:
    ; Break on branch not taken. Branch will not be taken. (test for PC=branch3)
    je branch3_done
branch3_done:
exit:
    ; Call sys_exit(0) on Linux.
    mov rax, 60
    mov rsi, 0
    syscall

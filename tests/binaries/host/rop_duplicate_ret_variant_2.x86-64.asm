global _start

; This program essentially does "ROP" on itself
; It constructs a double "ret", and does so in a way such that
; the first ret causes the program counter to not change (it rets back to itself)

_start:
sub rsp, 16
call rop_setup
ud2
times 32 nop

rop_setup:
mov rax, self_ret
mov [rsp], rax
mov rax, nop_sled
mov [rsp + 8], rax

one_before_self_ret:
nop

; When this ret executes, it will jump back to itself!
self_ret:
nop
ret

nop_sled:
times 32 nop

mov     edi, 0
mov     eax, 60
syscall
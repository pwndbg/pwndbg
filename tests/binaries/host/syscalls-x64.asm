global _start

; This binary is there to test syscall arguments display on x64
; along with 32-bit syscalls executed on x64
; Motivated by https://github.com/pwndbg/pwndbg/issues/1188

_start:
mov rax, 0
mov rdi, 0x1337
mov rsi, 0xdeadbeef
mov rcx, 0x10
syscall
mov eax, 10
int 0x80

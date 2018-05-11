global _start

; This binary is there to test
; emulate vs nearpc/u/pdisas commands
;
; The emulation should show `rep movsb` 4 times
;
; This might be a bit unclear because if we step through instructions in GDB we step just three times.
; The instruction is displayed 4 times because that is how Unicorn Emulation works:
; it emulates string loop instructions as a loop and the 4th instruction can be understand as 4th iteration
; which doesn't do the copy...

_start:
mov rsi, string
mov rdi, rsp
mov rcx, 3
rep movsb

string db '12345', 0

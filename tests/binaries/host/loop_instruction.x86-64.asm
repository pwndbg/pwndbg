global _start

_start:
nop
nop
xor ecx, ecx


loop:
    inc ecx
    cmp ecx, 4
    jl loop
nop
nop

; These bytes don't decode to anything, making the test easier as the disassembly is cut off here
db 0xFF, 0xFF


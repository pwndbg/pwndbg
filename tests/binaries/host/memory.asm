global _start

; This binary is there to test commands that access memory
; like dq, dd, dw, db, dc etc.
; So while the program does nothing, we create some data for testing those

_start:
    nop

data:
    dq 0x0
    dq 0x1
    dq 0x0000000100000002
    dq 0x0001000200030004
    dq 0x0102030405060708

data2:
    dq 0x1122334455667788
    dq 0x0123456789abcdef
    dq 0x0
    dq 0xffffffffffffffff
    dq 0x0011223344556677
    dq 0x8899aabbccddeeff

short_str:
    db "some cstring here"
    db 0

long_str:
    db "long string: "
    times 300 db 'A'
    db 0

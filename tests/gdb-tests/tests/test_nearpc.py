from __future__ import annotations

import gdb
import pytest

import tests

SYSCALLS_BINARY = tests.binaries.get("syscalls-x64.out")

OPCODE_BYTES_TESTS_EXPECTED_OUTPUT = {
    1: [
        "b8\x1b[90m...\x1b[0m",
        "bf\x1b[90m...\x1b[0m",
        "be\x1b[90m...\x1b[0m",
        "b9\x1b[90m...\x1b[0m",
        "0f\x1b[90m...\x1b[0m",
        "b8\x1b[90m...\x1b[0m",
        "cd\x1b[90m...\x1b[0m",
        "00\x1b[90m...\x1b[0m",
        "00\x1b[90m...\x1b[0m",
        "00\x1b[90m...\x1b[0m",
        "00\x1b[90m...\x1b[0m",
    ],
    2: [
        "b8 00\x1b[90m...\x1b[0m",
        "bf 37\x1b[90m...\x1b[0m",
        "be ef\x1b[90m...\x1b[0m",
        "b9 10\x1b[90m...\x1b[0m",
        "0f 05   ",
        "b8 0a\x1b[90m...\x1b[0m",
        "cd 80   ",
        "00 00   ",
        "00 00   ",
        "00 00   ",
        "00 00   ",
    ],
    3: [
        "b8 00 00\x1b[90m...\x1b[0m",
        "bf 37 13\x1b[90m...\x1b[0m",
        "be ef be\x1b[90m...\x1b[0m",
        "b9 10 00\x1b[90m...\x1b[0m",
        "0f 05      ",
        "b8 0a 00\x1b[90m...\x1b[0m",
        "cd 80      ",
        "00 00      ",
        "00 00      ",
        "00 00      ",
        "00 00      ",
    ],
    4: [
        "b8 00 00 00\x1b[90m...\x1b[0m",
        "bf 37 13 00\x1b[90m...\x1b[0m",
        "be ef be ad\x1b[90m...\x1b[0m",
        "b9 10 00 00\x1b[90m...\x1b[0m",
        "0f 05         ",
        "b8 0a 00 00\x1b[90m...\x1b[0m",
        "cd 80         ",
        "00 00         ",
        "00 00         ",
        "00 00         ",
        "00 00         ",
    ],
    5: [
        "b8 00 00 00 00   ",
        "bf 37 13 00 00   ",
        "be ef be ad de   ",
        "b9 10 00 00 00   ",
        "0f 05            ",
        "b8 0a 00 00 00   ",
        "cd 80            ",
        "00 00            ",
        "00 00            ",
        "00 00            ",
        "00 00            ",
    ],
}

OPCODE_SEPERATOR_TESTS_EXPECTED_OUTPUT = {
    0: [
        "b800000000   ",
        "bf37130000   ",
        "beefbeadde   ",
        "b910000000   ",
        "0f05         ",
        "b80a000000   ",
        "cd80         ",
        "0000         ",
        "0000         ",
        "0000         ",
        "0000         ",
    ],
    1: [
        "b8 00 00 00 00   ",
        "bf 37 13 00 00   ",
        "be ef be ad de   ",
        "b9 10 00 00 00   ",
        "0f 05            ",
        "b8 0a 00 00 00   ",
        "cd 80            ",
        "00 00            ",
        "00 00            ",
        "00 00            ",
        "00 00            ",
    ],
    2: [
        "b8  00  00  00  00   ",
        "bf  37  13  00  00   ",
        "be  ef  be  ad  de   ",
        "b9  10  00  00  00   ",
        "0f  05               ",
        "b8  0a  00  00  00   ",
        "cd  80               ",
        "00  00               ",
        "00  00               ",
        "00  00               ",
        "00  00               ",
    ],
}


@pytest.mark.parametrize("opcode_bytes", (1, 2, 3, 4, 5))
def test_nearpc_opcode_bytes(start_binary, opcode_bytes):
    start_binary(SYSCALLS_BINARY)
    gdb.execute("nextsyscall")

    gdb.execute(f"set nearpc-num-opcode-bytes {opcode_bytes}")
    dis = gdb.execute("nearpc", to_string=True)
    expected = (
        "   0x400080 {} <_start>       mov    eax, 0                 EAX => 0\n"
        "   0x400085 {} <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        "   0x40008a {} <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f {} <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        " ► 0x400094 {} <_start+20>    syscall  <SYS_read>\n"
        "        fd:        0x1337\n"
        "        buf:       0xdeadbeef\n"
        "        nbytes:    0\n"
        "   0x400096 {} <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        "   0x40009b {} <_start+27>    int    0x80\n"
        "   0x40009d {}                add    byte ptr [rax], al\n"
        "   0x40009f {}                add    byte ptr [rax], al\n"
        "   0x4000a1 {}                add    byte ptr [rax], al\n"
        "   0x4000a3 {}                add    byte ptr [rax], al\n"
    ).format(*OPCODE_BYTES_TESTS_EXPECTED_OUTPUT[opcode_bytes])
    assert dis == expected


@pytest.mark.parametrize("separator_bytes", (0, 1, 2))
def test_nearpc_opcode_seperator(start_binary, separator_bytes):
    start_binary(SYSCALLS_BINARY)
    gdb.execute("nextsyscall")
    gdb.execute("set nearpc-num-opcode-bytes 5")
    gdb.execute(f"set nearpc-opcode-separator-bytes {separator_bytes}")
    dis = gdb.execute("nearpc", to_string=True)
    excepted = (
        "   0x400080 {} <_start>       mov    eax, 0                 EAX => 0\n"
        "   0x400085 {} <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        "   0x40008a {} <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f {} <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        " ► 0x400094 {} <_start+20>    syscall  <SYS_read>\n"
        "        fd:        0x1337\n"
        "        buf:       0xdeadbeef\n"
        "        nbytes:    0\n"
        "   0x400096 {} <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        "   0x40009b {} <_start+27>    int    0x80\n"
        "   0x40009d {}                add    byte ptr [rax], al\n"
        "   0x40009f {}                add    byte ptr [rax], al\n"
        "   0x4000a1 {}                add    byte ptr [rax], al\n"
        "   0x4000a3 {}                add    byte ptr [rax], al\n"
    ).format(*OPCODE_SEPERATOR_TESTS_EXPECTED_OUTPUT[separator_bytes])
    assert dis == excepted


def test_nearpc_opcode_invalid_config():
    expected = "integer -1 out of range"
    try:
        # We try to catch the output since GDB < 9 won't raise the exception
        assert gdb.execute("set nearpc-num-opcode-bytes -1", to_string=True).rstrip() == expected
    except gdb.error as e:
        assert expected == str(e)

    try:
        assert (
            gdb.execute("set nearpc-opcode-separator-bytes -1", to_string=True).rstrip() == expected
        )
    except gdb.error as e:
        assert expected == str(e)


def test_nearpc_highlight_breakpoint(start_binary):
    start_binary(SYSCALLS_BINARY)
    gdb.execute("break *_start+5")
    gdb.execute("break *_start+22")
    dis = gdb.execute("nearpc", to_string=True)
    expected = (
        " ► 0x400080 <_start>       mov    eax, 0                 EAX => 0\n"
        "b+ 0x400085 <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        "   0x40008a <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        "   0x400094 <_start+20>    syscall \n"
        "b+ 0x400096 <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        "   0x40009b <_start+27>    int    0x80\n"
        "   0x40009d                add    byte ptr [rax], al\n"
        "   0x40009f                add    byte ptr [rax], al\n"
        "   0x4000a1                add    byte ptr [rax], al\n"
        "   0x4000a3                add    byte ptr [rax], al\n"
    )
    assert dis == expected

    gdb.execute("stepi")
    dis = gdb.execute("nearpc", to_string=True)
    # When we stop on a breakpoint, we only highlight it (and not show the "b+" marker)
    expected = (
        "   0x400080 <_start>       mov    eax, 0                 EAX => 0\n"
        " ► 0x400085 <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        "   0x40008a <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        "   0x400094 <_start+20>    syscall \n"
        "b+ 0x400096 <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        "   0x40009b <_start+27>    int    0x80\n"
        "   0x40009d                add    byte ptr [rax], al\n"
        "   0x40009f                add    byte ptr [rax], al\n"
        "   0x4000a1                add    byte ptr [rax], al\n"
        "   0x4000a3                add    byte ptr [rax], al\n"
    )
    assert dis == expected

    gdb.execute("stepi")
    dis = gdb.execute("nearpc", to_string=True)
    expected = (
        "   0x400080 <_start>       mov    eax, 0                 EAX => 0\n"
        "b+ 0x400085 <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        " ► 0x40008a <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        "   0x400094 <_start+20>    syscall \n"
        "b+ 0x400096 <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        "   0x40009b <_start+27>    int    0x80\n"
        "   0x40009d                add    byte ptr [rax], al\n"
        "   0x40009f                add    byte ptr [rax], al\n"
        "   0x4000a1                add    byte ptr [rax], al\n"
        "   0x4000a3                add    byte ptr [rax], al\n"
    )
    assert dis == expected

    gdb.execute("disable breakpoint 1")
    dis = gdb.execute("nearpc", to_string=True)
    expected = (
        "   0x400080 <_start>       mov    eax, 0                 EAX => 0\n"
        "   0x400085 <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        " ► 0x40008a <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        "   0x400094 <_start+20>    syscall \n"
        "b+ 0x400096 <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        "   0x40009b <_start+27>    int    0x80\n"
        "   0x40009d                add    byte ptr [rax], al\n"
        "   0x40009f                add    byte ptr [rax], al\n"
        "   0x4000a1                add    byte ptr [rax], al\n"
        "   0x4000a3                add    byte ptr [rax], al\n"
    )
    assert dis == expected

    gdb.execute("enable breakpoint 1")
    dis = gdb.execute("nearpc", to_string=True)
    expected = (
        "   0x400080 <_start>       mov    eax, 0                 EAX => 0\n"
        "b+ 0x400085 <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        " ► 0x40008a <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        "   0x400094 <_start+20>    syscall \n"
        "b+ 0x400096 <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        "   0x40009b <_start+27>    int    0x80\n"
        "   0x40009d                add    byte ptr [rax], al\n"
        "   0x40009f                add    byte ptr [rax], al\n"
        "   0x4000a1                add    byte ptr [rax], al\n"
        "   0x4000a3                add    byte ptr [rax], al\n"
    )
    assert dis == expected

    gdb.execute("delete breakpoint 1")
    dis = gdb.execute("nearpc", to_string=True)
    expected = (
        "   0x400080 <_start>       mov    eax, 0                 EAX => 0\n"
        "   0x400085 <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        " ► 0x40008a <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        "   0x400094 <_start+20>    syscall \n"
        "b+ 0x400096 <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        "   0x40009b <_start+27>    int    0x80\n"
        "   0x40009d                add    byte ptr [rax], al\n"
        "   0x40009f                add    byte ptr [rax], al\n"
        "   0x4000a1                add    byte ptr [rax], al\n"
        "   0x4000a3                add    byte ptr [rax], al\n"
    )
    assert dis == expected

    gdb.execute("delete breakpoint 2")
    dis = gdb.execute("nearpc", to_string=True)
    expected = (
        "   0x400080 <_start>       mov    eax, 0                 EAX => 0\n"
        "   0x400085 <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        " ► 0x40008a <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        "   0x400094 <_start+20>    syscall \n"
        "   0x400096 <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        "   0x40009b <_start+27>    int    0x80\n"
        "   0x40009d                add    byte ptr [rax], al\n"
        "   0x40009f                add    byte ptr [rax], al\n"
        "   0x4000a1                add    byte ptr [rax], al\n"
        "   0x4000a3                add    byte ptr [rax], al\n"
    )
    assert dis == expected

from __future__ import annotations

import pytest

from ....host import Controller
from . import get_binary
from . import pwndbg_test

SYSCALLS_BINARY = get_binary("syscalls-x64.out")

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


@pwndbg_test
@pytest.mark.parametrize("opcode_bytes", (1, 2, 3, 4, 5))
async def test_nearpc_opcode_bytes(ctrl: Controller, opcode_bytes: int) -> None:
    await ctrl.launch(SYSCALLS_BINARY)
    await ctrl.execute("nextsyscall")

    await ctrl.execute(f"set nearpc-num-opcode-bytes {opcode_bytes}")
    dis = await ctrl.execute_and_capture("nearpc")
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


@pwndbg_test
@pytest.mark.parametrize("separator_bytes", (0, 1, 2))
async def test_nearpc_opcode_seperator(ctrl: Controller, separator_bytes: int) -> None:
    await ctrl.launch(SYSCALLS_BINARY)
    await ctrl.execute("nextsyscall")

    await ctrl.execute("set nearpc-num-opcode-bytes 5")
    await ctrl.execute(f"set nearpc-opcode-separator-bytes {separator_bytes}")

    dis = await ctrl.execute_and_capture("nearpc")
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


@pwndbg_test
async def test_nearpc_highlight_breakpoint(ctrl: Controller) -> None:
    import pwndbg.aglib.symbol
    from pwndbg.dbg import BreakpointLocation

    await ctrl.launch(SYSCALLS_BINARY)

    start_base = pwndbg.aglib.symbol.lookup_symbol_addr("_start")

    bp1 = pwndbg.dbg.selected_inferior().break_at(BreakpointLocation(start_base + 5))
    bp2 = pwndbg.dbg.selected_inferior().break_at(BreakpointLocation(start_base + 22))

    dis = await ctrl.execute_and_capture("nearpc")
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

    await ctrl.step_instruction()
    dis = await ctrl.execute_and_capture("nearpc")
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

    await ctrl.step_instruction()
    dis = await ctrl.execute_and_capture("nearpc")
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

    bp1.set_enabled(False)
    dis = await ctrl.execute_and_capture("nearpc")
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

    bp1.set_enabled(True)
    dis = await ctrl.execute_and_capture("nearpc")
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

    bp1.remove()
    dis = await ctrl.execute_and_capture("nearpc")
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

    bp2.remove()
    dis = await ctrl.execute_and_capture("nearpc")
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

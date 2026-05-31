from __future__ import annotations

import pytest

from ....host import Controller
from . import get_binary
from . import launch_to
from . import pwndbg_test

SYSCALLS_BINARY = get_binary("syscalls.x86-64.out")
BRANCH_VISUALIZATION_BINARY = get_binary("branch_visualization.x86-64.out")

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
    dis = await ctrl.execute_and_capture("nearpc -t 11")
    expected = (
        "   0x400080 {} <_start>       mov    eax, 0                 EAX => 0\n"
        "   0x400085 {} <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        "   0x40008a {} <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f {} <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        " ► 0x400094 {} <_start+20>    syscall <SYS_read>\n"
        "        fd:        0x1337\n"
        "        buf:       0xdeadbeef\n"
        "        nbytes:    0\n"
        "   0x400096 {} <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        "   0x40009b {} <_start+27>    int    0x80 <SYS_unlink>\n"
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

    dis = await ctrl.execute_and_capture("nearpc -t 11")
    excepted = (
        "   0x400080 {} <_start>       mov    eax, 0                 EAX => 0\n"
        "   0x400085 {} <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        "   0x40008a {} <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f {} <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        " ► 0x400094 {} <_start+20>    syscall <SYS_read>\n"
        "        fd:        0x1337\n"
        "        buf:       0xdeadbeef\n"
        "        nbytes:    0\n"
        "   0x400096 {} <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        "   0x40009b {} <_start+27>    int    0x80 <SYS_unlink>\n"
        "   0x40009d {}                add    byte ptr [rax], al\n"
        "   0x40009f {}                add    byte ptr [rax], al\n"
        "   0x4000a1 {}                add    byte ptr [rax], al\n"
        "   0x4000a3 {}                add    byte ptr [rax], al\n"
    ).format(*OPCODE_SEPERATOR_TESTS_EXPECTED_OUTPUT[separator_bytes])
    assert dis == excepted


@pwndbg_test
async def test_nearpc_highlight_breakpoint(ctrl: Controller) -> None:
    import pwndbg.aglib.symbol
    from pwndbg.dbg_mod import BreakpointLocation

    await ctrl.launch(SYSCALLS_BINARY)

    start_base = pwndbg.aglib.symbol.lookup_symbol_addr("_start")

    bp1 = pwndbg.dbg.selected_inferior().break_at(BreakpointLocation(start_base + 5))
    bp2 = pwndbg.dbg.selected_inferior().break_at(BreakpointLocation(start_base + 22))

    dis = await ctrl.execute_and_capture("nearpc -t 11")
    expected = (
        " ► 0x400080 <_start>       mov    eax, 0                 EAX => 0\n"
        "b+ 0x400085 <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        "   0x40008a <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        "   0x400094 <_start+20>    syscall <SYS_read>\n"
        "b+ 0x400096 <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        "   0x40009b <_start+27>    int    0x80 <SYS_unlink>\n"
        "   0x40009d                add    byte ptr [rax], al\n"
        "   0x40009f                add    byte ptr [rax], al\n"
        "   0x4000a1                add    byte ptr [rax], al\n"
        "   0x4000a3                add    byte ptr [rax], al\n"
    )
    assert dis == expected

    await ctrl.step_instruction()
    dis = await ctrl.execute_and_capture("nearpc -t 11")

    # When we stop on a breakpoint, we show a special marker
    expected = (
        "   0x400080 <_start>       mov    eax, 0                 EAX => 0\n"
        "b► 0x400085 <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        "   0x40008a <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        "   0x400094 <_start+20>    syscall <SYS_read>\n"
        "b+ 0x400096 <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        "   0x40009b <_start+27>    int    0x80 <SYS_unlink>\n"
        "   0x40009d                add    byte ptr [rax], al\n"
        "   0x40009f                add    byte ptr [rax], al\n"
        "   0x4000a1                add    byte ptr [rax], al\n"
        "   0x4000a3                add    byte ptr [rax], al\n"
    )
    assert dis == expected

    await ctrl.step_instruction()
    dis = await ctrl.execute_and_capture("nearpc -t 11")
    expected = (
        "   0x400080 <_start>       mov    eax, 0                 EAX => 0\n"
        "b+ 0x400085 <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        " ► 0x40008a <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        "   0x400094 <_start+20>    syscall <SYS_read>\n"
        "b+ 0x400096 <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        "   0x40009b <_start+27>    int    0x80 <SYS_unlink>\n"
        "   0x40009d                add    byte ptr [rax], al\n"
        "   0x40009f                add    byte ptr [rax], al\n"
        "   0x4000a1                add    byte ptr [rax], al\n"
        "   0x4000a3                add    byte ptr [rax], al\n"
    )
    assert dis == expected

    bp1.set_enabled(False)
    dis = await ctrl.execute_and_capture("nearpc -t 11")
    expected = (
        "   0x400080 <_start>       mov    eax, 0                 EAX => 0\n"
        "   0x400085 <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        " ► 0x40008a <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        "   0x400094 <_start+20>    syscall <SYS_read>\n"
        "b+ 0x400096 <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        "   0x40009b <_start+27>    int    0x80 <SYS_unlink>\n"
        "   0x40009d                add    byte ptr [rax], al\n"
        "   0x40009f                add    byte ptr [rax], al\n"
        "   0x4000a1                add    byte ptr [rax], al\n"
        "   0x4000a3                add    byte ptr [rax], al\n"
    )
    assert dis == expected

    bp1.set_enabled(True)
    dis = await ctrl.execute_and_capture("nearpc -t 11")
    expected = (
        "   0x400080 <_start>       mov    eax, 0                 EAX => 0\n"
        "b+ 0x400085 <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        " ► 0x40008a <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        "   0x400094 <_start+20>    syscall <SYS_read>\n"
        "b+ 0x400096 <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        "   0x40009b <_start+27>    int    0x80 <SYS_unlink>\n"
        "   0x40009d                add    byte ptr [rax], al\n"
        "   0x40009f                add    byte ptr [rax], al\n"
        "   0x4000a1                add    byte ptr [rax], al\n"
        "   0x4000a3                add    byte ptr [rax], al\n"
    )
    assert dis == expected

    bp1.remove()
    dis = await ctrl.execute_and_capture("nearpc -t 11")
    expected = (
        "   0x400080 <_start>       mov    eax, 0                 EAX => 0\n"
        "   0x400085 <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        " ► 0x40008a <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        "   0x400094 <_start+20>    syscall <SYS_read>\n"
        "b+ 0x400096 <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        "   0x40009b <_start+27>    int    0x80 <SYS_unlink>\n"
        "   0x40009d                add    byte ptr [rax], al\n"
        "   0x40009f                add    byte ptr [rax], al\n"
        "   0x4000a1                add    byte ptr [rax], al\n"
        "   0x4000a3                add    byte ptr [rax], al\n"
    )
    assert dis == expected

    bp2.remove()
    dis = await ctrl.execute_and_capture("nearpc -t 11")
    expected = (
        "   0x400080 <_start>       mov    eax, 0                 EAX => 0\n"
        "   0x400085 <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        " ► 0x40008a <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        "   0x400094 <_start+20>    syscall <SYS_read>\n"
        "   0x400096 <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        "   0x40009b <_start+27>    int    0x80 <SYS_unlink>\n"
        "   0x40009d                add    byte ptr [rax], al\n"
        "   0x40009f                add    byte ptr [rax], al\n"
        "   0x4000a1                add    byte ptr [rax], al\n"
        "   0x4000a3                add    byte ptr [rax], al\n"
    )
    assert dis == expected


@pwndbg_test
async def test_nearpc_branch_visualization(ctrl: Controller) -> None:
    import pwndbg.color

    await ctrl.launch(BRANCH_VISUALIZATION_BINARY)

    dis = await ctrl.execute_and_capture("nearpc 11")
    dis = pwndbg.color.strip(dis)

    expected = (
        " ► 0x400080 <_start>                            mov    eax, 0     EAX => 0\n"
        "   0x400085 <_start+5>                          cmp    eax, 1     0 - 1\n"
        "   0x400088 <_start+8>                     ┌<   je     B                           <B>\n"
        "                                           │ \n"
        "   0x40008a <_start+10>                    │    add    eax, 2\n"
        "   0x40008d <_start+13>                   ┌─<   jmp    C                           <C>\n"
        "                                          ││ \n"
        "   0x40008f <B>                           │└>   sub    eax, 1\n"
        "   0x400092 <B+3>                         │     cmp    eax, 0\n"
        "   0x400095 <B+6>                        ┌──<   jne    C                           <C>\n"
        "                                         ││  \n"
        "   0x400097 <B+8>                        ││     nop   \n"
        "   0x400098 <B+9>                        ││     nop   \n"
        "   0x400099 <C>                          └└─>   ret   \n"
    )

    assert dis == expected


@pwndbg_test
async def test_nearpc_function(ctrl: Controller) -> None:
    await launch_to(ctrl, get_binary("initialized_heap.x86-64.out"), "break_here")
    await ctrl.execute("set disasm-annotations off")
    await ctrl.step_instruction()

    # disassemble current function
    dis = await ctrl.execute_and_capture("nearpc --function")
    expected_break_here = (
        "b+ 0x10014d0 <break_here>      push   rbp\n"
        " ► 0x10014d1 <break_here+1>    mov    rbp, rsp\n"
        "   0x10014d4 <break_here+4>    pop    rbp\n"
        "   0x10014d5 <break_here+5>    ret   \n"
    )
    assert dis == expected_break_here

    # disassemble parent function
    await ctrl.execute("up")
    dis = (await ctrl.execute_and_capture("nearpc --function")).splitlines()[-4:]
    expected = [
        " ► 0x1001502 <main+34>    xor    eax, eax",
        "   0x1001504 <main+36>    add    rsp, 0x10",
        "   0x1001508 <main+40>    pop    rbp",
        "   0x1001509 <main+41>    ret   ",
    ]
    assert dis == expected

    # disassemble break_here again
    dis = await ctrl.execute_and_capture("nearpc -f (char*)break_here+2")
    # no "►" prefix this time cause we switched to the parent frame:
    assert dis == expected_break_here.replace("►", " ")

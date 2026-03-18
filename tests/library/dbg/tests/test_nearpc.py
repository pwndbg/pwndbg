from __future__ import annotations

import pytest

from ....host import Controller
from . import get_binary
from . import launch_to
from . import pwndbg_test

SYSCALLS_BINARY = get_binary("syscalls.x86-64.out")
BRANCH_VISUALIZATION_BINARY = get_binary("branch_visualization.x86-64.out")
CONTEXT_ARGS_BINARY = get_binary("context_args.native.out")

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
    await launch_to(ctrl, CONTEXT_ARGS_BINARY, "func_with_args")

    # disable annotations because libc addresses vary across distros
    await ctrl.execute("set disasm-annotations off")
    await ctrl.step_instruction()

    # disassemble current function
    dis = await ctrl.execute_and_capture("nearpc --function -t 10")
    func_expected = (
        "b+ 0x1001560 <func_with_args>       push   rbp\n"
        " {} 0x1001561 <func_with_args+1>     mov    rbp, rsp\n"
        "   0x1001564 <func_with_args+4>     sub    rsp, 0x20\n"
        "   0x1001568 <func_with_args+8>     mov    dword ptr [rbp - 4], edi\n"
        "   0x100156b <func_with_args+11>    mov    dword ptr [rbp - 8], esi\n"
        "   0x100156e <func_with_args+14>    mov    dword ptr [rbp - 0xc], edx\n"
        "   0x1001571 <func_with_args+17>    mov    dword ptr [rbp - 0x10], ecx\n"
        "   0x1001574 <func_with_args+20>    mov    dword ptr [rbp - 0x14], r8d\n"
        "   0x1001578 <func_with_args+24>    mov    dword ptr [rbp - 0x18], r9d\n"
        "   0x100157c <func_with_args+28>    mov    esi, dword ptr [rbp - 4]\n"
    )
    assert dis == func_expected.format("►")

    # disassemble parent function
    await ctrl.execute("up")
    dis = (await ctrl.execute_and_capture("nearpc --function")).splitlines()[-4:]
    expected = [
        " ► 0x10015d4 <main+52>    xor    eax, eax",
        "   0x10015d6 <main+54>    add    rsp, 0x10",
        "   0x10015da <main+58>    pop    rbp",
        "   0x10015db <main+59>    ret   ",
    ]
    assert dis == expected

    # disassemble func_with_args again
    dis = await ctrl.execute_and_capture("nearpc -f (char*)func_with_args+9 -t 10")
    # no "►" prefix this time cause we switched to the parent frame:
    assert dis == func_expected.format(" ")

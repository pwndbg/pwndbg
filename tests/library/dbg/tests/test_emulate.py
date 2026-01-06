from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import pwndbg_test

EMULATE_DISASM_BINARY = get_binary("emulate_disasm.x86-64.out")
EMULATE_DISASM_LOOP_BINARY = get_binary("emulate_disasm_loop.x86-64.out")


@pwndbg_test
async def test_emulate_disasm(ctrl: Controller) -> None:
    """
    Tests emulate command and its caching behavior
    """
    await ctrl.launch(EMULATE_DISASM_BINARY)

    disasm_with_emu_0x400080 = [
        " ► 0x400080 <_start>    jmp    label                       <label>",
        "    ↓",
        "   0x400083 <label>     nop   ",
        "   0x400084             add    byte ptr [rax], al",
        "   0x400086             add    byte ptr [rax], al",
        "   0x400088             add    byte ptr [rax], al",
        "   0x40008a             add    byte ptr [rax], al",
        "   0x40008c             add    byte ptr [rax], al",
        "   0x40008e             add    byte ptr [rax], al",
        "   0x400090             add    byte ptr [rax], al",
        "   0x400092             add    byte ptr [rax], al",
        "   0x400094             add    byte ptr [rax], al",
    ]

    disasm_without_emu_0x400080 = [
        " ► 0x400080 <_start>      jmp    label                       <label>",
        " ",
        "   0x400082 <_start+2>    nop   ",
        "   0x400083 <label>       nop   ",
        "   0x400084               add    byte ptr [rax], al",
        "   0x400086               add    byte ptr [rax], al",
        "   0x400088               add    byte ptr [rax], al",
        "   0x40008a               add    byte ptr [rax], al",
        "   0x40008c               add    byte ptr [rax], al",
        "   0x40008e               add    byte ptr [rax], al",
        "   0x400090               add    byte ptr [rax], al",
        "   0x400092               add    byte ptr [rax], al",
    ]

    compare_output_emu(disasm_with_emu_0x400080)
    compare_output_without_emu(disasm_without_emu_0x400080)


@pwndbg_test
async def test_emulate_disasm_loop(ctrl: Controller) -> None:
    import pwndbg.aglib

    await ctrl.launch(EMULATE_DISASM_LOOP_BINARY)

    disasm_with_emu_0x400080 = [
        " ► 0x400080 <_start>       movabs rsi, string                           RSI => 0x400094 (string) ◂— xor dword ptr [rdx], esi /* '12345' */",
        f"   0x40008a <_start+10>    mov    rdi, rsp                              RDI => {hex(pwndbg.aglib.regs.sp)} ◂— 1",
        "   0x40008d <_start+13>    mov    ecx, 3                                ECX => 3",
        "   0x400092 <_start+18>    rep movsb byte ptr [rdi], byte ptr [rsi]",
        "    ↓",
        "   0x400092 <_start+18>    rep movsb byte ptr [rdi], byte ptr [rsi]",
        "    ↓",
        "   0x400092 <_start+18>    rep movsb byte ptr [rdi], byte ptr [rsi]",
        "    ↓",
        "   0x400092 <_start+18>    rep movsb byte ptr [rdi], byte ptr [rsi]",
        "   0x400094 <string>       xor    dword ptr [rdx], esi",
        "   0x400096 <string+2>     xor    esi, dword ptr [rsi]",
        "   0x40009d                add    byte ptr [rax], al",
        "   0x40009f                add    byte ptr [rax], al",
    ]

    disasm_without_emu_0x400080 = [
        " ► 0x400080 <_start>       movabs rsi, string                           RSI => 0x400094 (string) ◂— xor dword ptr [rdx], esi /* '12345' */",
        f"   0x40008a <_start+10>    mov    rdi, rsp                              RDI => {hex(pwndbg.aglib.regs.sp)}",
        "   0x40008d <_start+13>    mov    ecx, 3                                ECX => 3",
        "   0x400092 <_start+18>    rep movsb byte ptr [rdi], byte ptr [rsi]",
        "   0x400094 <string>       xor    dword ptr [rdx], esi",
        "   0x400096 <string+2>     xor    esi, dword ptr [rsi]",
        "   0x40009d                add    byte ptr [rax], al",
        "   0x40009f                add    byte ptr [rax], al",
        "   0x4000a1                add    byte ptr [rax], al",
        "   0x4000a3                add    byte ptr [rax], al",
        "   0x4000a5                add    byte ptr [rax], al",
    ]

    compare_output_emu(disasm_with_emu_0x400080)
    compare_output_without_emu(disasm_without_emu_0x400080)


def compare_output_emu(expected_output):
    from pwndbg.aglib.nearpc import nearpc

    assert nearpc(back_lines=5, total_lines=11, emulate=True) == expected_output


def compare_output_without_emu(expected_output):
    from pwndbg.aglib.nearpc import nearpc

    assert nearpc(back_lines=5, total_lines=11, linear=True) == expected_output

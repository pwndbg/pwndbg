from __future__ import annotations

from collections.abc import Awaitable
from collections.abc import Callable

from ....host import Controller
from . import get_binary
from . import pwndbg_test

LOOP_INSTRUCTION_BINARY = get_binary("loop_instruction.x86-64.out")


async def context_disasm_loop_instruction_helper(
    ctrl: Controller, callback: Callable[[Controller], Awaitable[None]] | None
) -> None:
    """
    This makes sure that when stepping through tight loops, the correct
    sequence of executed instructions is recorded
    """
    import pwndbg.color

    await ctrl.launch(LOOP_INSTRUCTION_BINARY)

    await ctrl.execute("set context-disasm-lines 30")
    dis = await ctrl.execute_and_capture("context disasm")
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────\n"
        " ► 0x400080 <_start>      nop   \n"
        "   0x400081 <_start+1>    nop   \n"
        "   0x400082 <_start+2>    xor    ecx, ecx     ECX => 0\n"
        "   0x400084 <loop>        inc    ecx          ECX => 1\n"
        "   0x400086 <loop+2>      cmp    ecx, 4       1 - 4     EFLAGS => 0x293 [ CF pf AF zf SF IF df of iopl:00 ac ]\n"
        "   0x400089 <loop+5>    ✔ jl     loop                        <loop>\n"
        "    ↓\n"
        "   0x400084 <loop>        inc    ecx          ECX => 2\n"
        "   0x400086 <loop+2>      cmp    ecx, 4       2 - 4     EFLAGS => 0x293 [ CF pf AF zf SF IF df of iopl:00 ac ]\n"
        "   0x400089 <loop+5>    ✔ jl     loop                        <loop>\n"
        "    ↓\n"
        "   0x400084 <loop>        inc    ecx          ECX => 3\n"
        "   0x400086 <loop+2>      cmp    ecx, 4       3 - 4     EFLAGS => 0x297 [ CF PF AF zf SF IF df of iopl:00 ac ]\n"
        "   0x400089 <loop+5>    ✔ jl     loop                        <loop>\n"
        "    ↓\n"
        "   0x400084 <loop>        inc    ecx          ECX => 4\n"
        "   0x400086 <loop+2>      cmp    ecx, 4       4 - 4     EFLAGS => 0x246 [ cf PF af ZF sf IF df of iopl:00 ac ]\n"
        "   0x400089 <loop+5>    ✘ jl     loop                        <loop>\n"
        " \n"
        "   0x40008b <loop+7>      nop   \n"
        "   0x40008c <loop+8>      nop   \n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected

    # Step to end of loop (after unrolling)
    for _ in range(14):
        await ctrl.step_instruction()
        if callback is not None:
            await callback(ctrl)

    dis = await ctrl.execute_and_capture("context disasm")
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────\n"
        "   0x400080 <_start>      nop   \n"
        "   0x400081 <_start+1>    nop   \n"
        "   0x400082 <_start+2>    xor    ecx, ecx     ECX => 0\n"
        "   0x400084 <loop>        inc    ecx          ECX => 1\n"
        "   0x400086 <loop+2>      cmp    ecx, 4       1 - 4     EFLAGS => 0x293 [ CF pf AF zf SF IF df of iopl:00 ac ]\n"
        "   0x400089 <loop+5>    ✔ jl     loop                        <loop>\n"
        "    ↓\n"
        "   0x400084 <loop>        inc    ecx          ECX => 2\n"
        "   0x400086 <loop+2>      cmp    ecx, 4       2 - 4     EFLAGS => 0x293 [ CF pf AF zf SF IF df of iopl:00 ac ]\n"
        "   0x400089 <loop+5>    ✔ jl     loop                        <loop>\n"
        "    ↓\n"
        "   0x400084 <loop>        inc    ecx          ECX => 3\n"
        "   0x400086 <loop+2>      cmp    ecx, 4       3 - 4     EFLAGS => 0x297 [ CF PF AF zf SF IF df of iopl:00 ac ]\n"
        "   0x400089 <loop+5>    ✔ jl     loop                        <loop>\n"
        "    ↓\n"
        "   0x400084 <loop>        inc    ecx          ECX => 4\n"
        "   0x400086 <loop+2>      cmp    ecx, 4       4 - 4     EFLAGS => 0x246 [ cf PF af ZF sf IF df of iopl:00 ac ]\n"
        " ► 0x400089 <loop+5>    ✘ jl     loop                        <loop>\n"
        " \n"
        "   0x40008b <loop+7>      nop   \n"
        "   0x40008c <loop+8>      nop   \n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


@pwndbg_test
async def test_context_disasm_loop_instruction(ctrl: Controller):
    await context_disasm_loop_instruction_helper(ctrl, None)


@pwndbg_test
async def test_context_disasm_loop_instruction_with_multiple_ctx_disasm_calls(ctrl: Controller):
    """
    "context disasm" run multiple times when stopping should not mess with the caches.
    """

    async def ctx_disasm(ctrl: Controller) -> None:
        await ctrl.execute("context disasm")

    await context_disasm_loop_instruction_helper(ctrl, ctx_disasm)


ADD_TO_RSP_BINARY = get_binary("add_to_rsp.x86-64.out")


@pwndbg_test
async def test_context_disasm_non_global_cache(ctrl: Controller) -> None:
    """
    This checks that a call to `nearpc` does not interfere with the `context disasm` instruction flow cache.

    The cache for `context disasm` should be isolated from the rest of the calls to disassemble instructions.

    We have an `add rsp, rax` (using RSP so it cannot be computed statically, so it must have been generated by the disasm system during emulation/while paused there)

    If the annotation for that disappears, it means the `nearpc` is messing with the `context disasm` cache.
    """
    import pwndbg.aglib
    import pwndbg.color

    await ctrl.launch(ADD_TO_RSP_BINARY)

    rsp: int = pwndbg.aglib.regs.sp

    await ctrl.step_instruction()
    await ctrl.step_instruction()

    # Do a nearpc at a faraway address.
    # This should not interfere with the context disasm caches
    await ctrl.execute("nearpc $rip+400")

    # Do not call context disasm after the nearpc
    await ctrl.step_instruction()

    dis_0 = await ctrl.execute_and_capture("context disasm")
    dis_0 = pwndbg.color.strip(dis_0)

    expected_0 = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────\n"
        "   0x400080 <_start>       mov    eax, 1        EAX => 1\n"
        f"   0x400085 <_start+5>     add    rsp, rax      RSP => 0x{rsp + 1:x} (0x{rsp:x} + 0x1)\n"
        "   0x400088 <_start+8>     mov    edx, 0x64     EDX => 0x64\n"
        " ► 0x40008d <_start+13>    add    rdx, rbx      RDX => 0x64 (0x64 + 0x0)\n"
        "   0x400090 <_start+16>    nop   \n"
        "   0x400091 <_start+17>    nop   \n"
        "   0x400092 <_start+18>    nop   \n"
        "   0x400093 <_start+19>    nop   \n"
        "   0x400094 <_start+20>    nop   \n"
        "   0x400095 <_start+21>    nop   \n"
        "   0x400096 <_start+22>    nop   \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis_0 == expected_0

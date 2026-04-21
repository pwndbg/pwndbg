from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import pwndbg_test

LOOP_INSTRUCTION_BINARY = get_binary("loop_instruction.x86-64.out")


@pwndbg_test
async def test_context_disasm_loop_instruction(ctrl: Controller) -> None:
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

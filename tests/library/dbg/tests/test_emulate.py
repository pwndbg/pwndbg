from __future__ import annotations

from ....host import Controller
from . import break_at_sym
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


STEPSYSCALL_X64_BINARY = get_binary("stepsyscall.x86-64.out")


@pwndbg_test
async def test_backwards_disassemble_heuristic(ctrl: Controller) -> None:
    """
    This tests our capability of disassembling backwards in a variable length instruction set, where instruction alignment is not known ahead of time.
    """
    import pwndbg.aglib

    await ctrl.launch(STEPSYSCALL_X64_BINARY)

    # Enable the heuristic
    await ctrl.execute_and_capture("set heuristic-backwards-disasm on")

    dis = await ctrl.execute_and_capture("nearpc -n -t 11")

    # Data region location can differ based on the system
    buf_addr = int(pwndbg.aglib.symbol.lookup_symbol_addr("buf"))

    expected = (
        "   0x4000bd <do_read+5>               mov    edi, 0       EDI => 0\n"
        f"   0x4000c2 <do_read+10>              movabs rsi, buf     RSI => 0x{buf_addr:x} (buf)\n"
        "   0x4000cc <do_read+20>              mov    edx, 1       EDX => 1\n"
        "   0x4000d1 <syscall_read_label>      syscall\n"
        "   0x4000d3 <syscall_read_label+2>    ret   \n"
        " \n"
        " ► 0x4000d4 <_start>                  nop   \n"
        "   0x4000d5 <_start+1>                jmp    label1                      <label1>\n"
        " \n"
        "   0x4000d7 <_start+3>                nop   \n"
        "   0x4000d8 <label1>                  call   write_stdout                <write_stdout>\n"
        " \n"
        "   0x4000dd <label1+5>                call   write_stderr                <write_stderr>\n"
        " \n"
        "   0x4000e2 <exit>                    mov    eax, 0x3c     EAX => 0x3c\n"
    )

    assert dis == expected


@pwndbg_test
async def test_backwards_linear_cache_populate_when_disassemble_from_pc(ctrl: Controller) -> None:
    """
    When disassembling from an arbitrary point, such as `nearpc random_address`, we don't want to
    populate the "linear backward cache" immediately. This is because `random_address` may not be at a real instruction boundary,
    and we don't want corrupted values in the cache. Instead, we disassembling N instructions (N is some heuristic amount), and assume the
    instruction stream has self-aligned at that point. Only then do we start populating the linear backward cache.

    However, there is an edge case where we populate this cache immediately: when disassembling from the program PC.
    1. When stepping in the disasm view, we know the PC is aligned to a real instruction as interpreted by the CPU
    2. In this case, make sure we track the linear flow of instructions ("linear backward cache") in this case

    This is an edge case, because if the user does `nearpc random_address`, we don't want to add next couple instructions
    to the linear backward cache, because "random_address" may not be aligned to a real address. This would corrupt the cache,
    causing future disassembles at "random_address+offset" to not be able to disassemble backwards correctly (they would use the corrupted cache, and not the heuristic)

    This is NOT testing the backwards disassembly itself. It is rather testing that the method of populating the linear cache works.
    """

    await ctrl.launch(STEPSYSCALL_X64_BINARY)

    # This filling up caches, disassembling from PC
    dis = await ctrl.execute_and_capture("nearpc -n -t 11")

    await ctrl.step_instruction()

    dis = await ctrl.execute_and_capture("nearpc -n -t 11")

    # This should be able to disassemble backwards using the backwards caches!
    expected = (
        "   0x4000d4 <_start>                nop   \n"
        " ► 0x4000d5 <_start+1>              jmp    label1                      <label1>\n"
        " \n"
        "   0x4000d7 <_start+3>              nop   \n"
        "   0x4000d8 <label1>                call   write_stdout                <write_stdout>\n"
        " \n"
        "   0x4000dd <label1+5>              call   write_stderr                <write_stderr>\n"
        " \n"
        "   0x4000e2 <exit>                  mov    eax, 0x3c              EAX => 0x3c\n"
        "   0x4000e7 <exit+5>                mov    edi, 0                 EDI => 0\n"
        "   0x4000ec <syscall_exit_label>    syscall <SYS_exit>\n"
        "   0x4000ee                         add    byte ptr [rax], al\n"
        "   0x4000f0                         add    byte ptr [rax], al\n"
        "   0x4000f2                         add    byte ptr [rax], al\n"
    )
    assert dis == expected


@pwndbg_test
async def test_backwards_linear_cache_misaligned_disasm(ctrl: Controller) -> None:
    """
    Testing same mechanism as previous test, but not disassembling from PC.

    Do not let the "linear backward cache" be corrupted if disassemble at a misaligned address.
    Doing this is very common when "guessing" address to "nearpc" from.
    """

    # Do not allow the disassembly section to run to populate the caches
    await ctrl.execute_and_capture("set context-sections ''")

    await ctrl.launch(STEPSYSCALL_X64_BINARY)

    # Disassemble from misaligned address
    dis_0 = await ctrl.execute_and_capture("nearpc $rip-2 -t 11")

    # Misaligned disassembly!
    expected_0 = (
        " ► 0x4000d2 <syscall_read_label+1>    add    eax, 0x1eb90c3\n"
        "   0x4000d7 <_start+3>                nop   \n"
        "   0x4000d8 <label1>                  call   write_stdout                <write_stdout>\n"
        " \n"
        "   0x4000dd <label1+5>                call   write_stderr                <write_stderr>\n"
        " \n"
        "   0x4000e2 <exit>                    mov    eax, 0x3c              EAX => 0x3c\n"
        "   0x4000e7 <exit+5>                  mov    edi, 0                 EDI => 0\n"
        "   0x4000ec <syscall_exit_label>      syscall <SYS_exit>\n"
        "   0x4000ee                           add    byte ptr [rax], al\n"
        "   0x4000f0                           add    byte ptr [rax], al\n"
        "   0x4000f2                           add    byte ptr [rax], al\n"
        "   0x4000f4                           add    byte ptr [rax], al\n"
    )

    assert dis_0 == expected_0

    # Disable the heuristic
    await ctrl.execute_and_capture("set heuristic-backwards-disasm off")
    await ctrl.execute_and_capture("set context-disasm-back-linear-lines 0")

    # Without the heuristic, we disassemble straightline
    dis = await ctrl.execute_and_capture("nearpc $rip+4 -t 11")

    expected = (
        " ► 0x4000d8 <label1>                call   write_stdout                <write_stdout>\n"
        " \n"
        "   0x4000dd <label1+5>              call   write_stderr                <write_stderr>\n"
        " \n"
        "   0x4000e2 <exit>                  mov    eax, 0x3c              EAX => 0x3c\n"
        "   0x4000e7 <exit+5>                mov    edi, 0                 EDI => 0\n"
        "   0x4000ec <syscall_exit_label>    syscall <SYS_exit>\n"
        "   0x4000ee                         add    byte ptr [rax], al\n"
        "   0x4000f0                         add    byte ptr [rax], al\n"
        "   0x4000f2                         add    byte ptr [rax], al\n"
        "   0x4000f4                         add    byte ptr [rax], al\n"
        "   0x4000f6                         add    byte ptr [rax], al\n"
        "   0x4000f8                         add    byte ptr [rax], al\n"
    )
    assert dis == expected

    # Enable the heuristic
    await ctrl.execute_and_capture("set heuristic-backwards-disasm on")

    # The caches should NOT be filled.
    # Instead, the heuristic will be used to disassemble backwards
    dis_2 = await ctrl.execute_and_capture("nearpc $rip+4 -n -t 11")

    # This should be able to disassemble backwards using the backwards caches!
    expected_2 = (
        "   0x4000d1 <syscall_read_label>      syscall\n"
        "   0x4000d3 <syscall_read_label+2>    ret   \n"
        " \n"
        "   0x4000d4 <_start>                  nop   \n"
        "   0x4000d5 <_start+1>                jmp    label1                      <label1>\n"
        " \n"
        "   0x4000d7 <_start+3>                nop   \n"
        " ► 0x4000d8 <label1>                  call   write_stdout                <write_stdout>\n"
        " \n"
        "   0x4000dd <label1+5>                call   write_stderr                <write_stderr>\n"
        " \n"
        "   0x4000e2 <exit>                    mov    eax, 0x3c              EAX => 0x3c\n"
        "   0x4000e7 <exit+5>                  mov    edi, 0                 EDI => 0\n"
        "   0x4000ec <syscall_exit_label>      syscall <SYS_exit>\n"
        "   0x4000ee                           add    byte ptr [rax], al\n"
    )
    assert dis_2 == expected_2


DOUBLE_RET_ROP_CHAIN_BINARY = get_binary("rop_duplicate_ret.x86-64.out")


@pwndbg_test
async def test_emulate_double_ret_chain_with_leadup(ctrl: Controller) -> None:
    """
    This makes sure we handle the check for allowing to read from current process state during enhancement correctly.

    This test involves a double "ret" to the same "ret" instruction in memory (two instructions, at the same address executed back to back!)
    We should treat allow enhancement for the current `ret` (the one the CPU PC is on) to read from memory, and not future ones that we emulate through.
    """

    # Do not allow the disassembly section to run to populate the caches automatically
    await ctrl.execute_and_capture("set context-sections ''")

    await ctrl.launch(DOUBLE_RET_ROP_CHAIN_BINARY)

    break_at_sym("one_before_self_ret")

    await ctrl.cont()

    dis_0 = await ctrl.execute_and_capture("context disasm")

    expected_0 = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────\n"
        "b► 0x4000c8 <one_before_self_ret>    nop   \n"
        "   0x4000c9 <self_ret>               ret                                <self_ret>\n"
        "    ↓\n"
        "   0x4000c9 <self_ret>               ret                                <nop_sled>\n"
        "    ↓\n"
        "   0x4000ca <nop_sled>               nop   \n"
        "   0x4000cb <nop_sled+1>             nop   \n"
        "   0x4000cc <nop_sled+2>             nop   \n"
        "   0x4000cd <nop_sled+3>             nop   \n"
        "   0x4000ce <nop_sled+4>             nop   \n"
        "   0x4000cf <nop_sled+5>             nop   \n"
        "   0x4000d0 <nop_sled+6>             nop   \n"
        "   0x4000d1 <nop_sled+7>             nop   \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis_0 == expected_0

    await ctrl.step_instruction()

    dis_1 = await ctrl.execute_and_capture("context disasm")

    expected_1 = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────\n"
        "b+ 0x4000c8 <one_before_self_ret>    nop   \n"
        " ► 0x4000c9 <self_ret>               ret                                <self_ret>\n"
        "    ↓\n"
        "   0x4000c9 <self_ret>               ret                                <nop_sled>\n"
        "    ↓\n"
        "   0x4000ca <nop_sled>               nop   \n"
        "   0x4000cb <nop_sled+1>             nop   \n"
        "   0x4000cc <nop_sled+2>             nop   \n"
        "   0x4000cd <nop_sled+3>             nop   \n"
        "   0x4000ce <nop_sled+4>             nop   \n"
        "   0x4000cf <nop_sled+5>             nop   \n"
        "   0x4000d0 <nop_sled+6>             nop   \n"
        "   0x4000d1 <nop_sled+7>             nop   \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis_1 == expected_1

    await ctrl.step_instruction()

    dis_2 = await ctrl.execute_and_capture("context disasm")

    expected_2 = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────\n"
        "b+ 0x4000c8 <one_before_self_ret>    nop   \n"
        "   0x4000c9 <self_ret>               ret                                <self_ret>\n"
        "    ↓\n"
        " ► 0x4000c9 <self_ret>               ret                                <nop_sled>\n"
        "    ↓\n"
        "   0x4000ca <nop_sled>               nop   \n"
        "   0x4000cb <nop_sled+1>             nop   \n"
        "   0x4000cc <nop_sled+2>             nop   \n"
        "   0x4000cd <nop_sled+3>             nop   \n"
        "   0x4000ce <nop_sled+4>             nop   \n"
        "   0x4000cf <nop_sled+5>             nop   \n"
        "   0x4000d0 <nop_sled+6>             nop   \n"
        "   0x4000d1 <nop_sled+7>             nop   \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis_2 == expected_2


@pwndbg_test
async def test_emulate_double_ret_chain(ctrl: Controller) -> None:
    """
    Similar to the above test, except we go directly to the first ret (we don't know the instruction flow into it)

    If this fails with the result show a bunch of ret instructions before the ret we are on (where there should be none),
    it means that while handling the current pc's ret, we are corrupting the cache, affecting how we pull instructions from "backwards"
    (it may be writing "this ret comes back the next ret" (which is at the same), which is a fact that pollutes pulling values from "behind" us).
    """

    # Do not allow the disassembly section to run to populate the caches automatically
    await ctrl.execute_and_capture("set context-sections ''")

    await ctrl.launch(DOUBLE_RET_ROP_CHAIN_BINARY)

    break_at_sym("self_ret")

    await ctrl.cont()

    dis_0 = await ctrl.execute_and_capture("context disasm")

    expected_0 = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────\n"
        "b► 0x4000c9 <self_ret>      ret                                <self_ret>\n"
        "    ↓\n"
        "b+ 0x4000c9 <self_ret>      ret                                <nop_sled>\n"
        "    ↓\n"
        "   0x4000ca <nop_sled>      nop   \n"
        "   0x4000cb <nop_sled+1>    nop   \n"
        "   0x4000cc <nop_sled+2>    nop   \n"
        "   0x4000cd <nop_sled+3>    nop   \n"
        "   0x4000ce <nop_sled+4>    nop   \n"
        "   0x4000cf <nop_sled+5>    nop   \n"
        "   0x4000d0 <nop_sled+6>    nop   \n"
        "   0x4000d1 <nop_sled+7>    nop   \n"
        "   0x4000d2 <nop_sled+8>    nop   \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis_0 == expected_0

    await ctrl.step_instruction()

    # This second check requires we are careful about our caching!
    # Having two of the same instruction, if a cache is keyed off of only the
    # instruction address, can cause the remembered control flow to be incorrect
    # for a given instance of the instruction at that address.
    dis_1 = await ctrl.execute_and_capture("context disasm")

    expected_1 = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────\n"
        "b+ 0x4000c9 <self_ret>      ret                                <self_ret>\n"
        "    ↓\n"
        "b► 0x4000c9 <self_ret>      ret                                <nop_sled>\n"
        "    ↓\n"
        "   0x4000ca <nop_sled>      nop   \n"
        "   0x4000cb <nop_sled+1>    nop   \n"
        "   0x4000cc <nop_sled+2>    nop   \n"
        "   0x4000cd <nop_sled+3>    nop   \n"
        "   0x4000ce <nop_sled+4>    nop   \n"
        "   0x4000cf <nop_sled+5>    nop   \n"
        "   0x4000d0 <nop_sled+6>    nop   \n"
        "   0x4000d1 <nop_sled+7>    nop   \n"
        "   0x4000d2 <nop_sled+8>    nop   \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis_1 == expected_1

    # TODO and TO FIX:
    # What if run ctx disasm twice here
    # --- make it be stateful: current_state, next_state

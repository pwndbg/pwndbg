from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import pwndbg_test

SYSCALL_ARGS_X64_BINARY = get_binary("syscall_args.x86-64.out")


@pwndbg_test
async def test_syscall_args(ctrl: Controller) -> None:
    import pwndbg.aglib

    await ctrl.launch(SYSCALL_ARGS_X64_BINARY)
    # LLDB launches with -s flag which causes a SIGSTOP that can interfere with
    # stepping commands. Step once to move past the initial stop state.
    if not pwndbg.dbg.is_gdblib_available():
        await ctrl.step_instruction()

    await ctrl.execute("stepsyscall")
    dis = await ctrl.execute_and_capture("context disasm")
    assert dis == (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────\n"
        "   0x400080 <_start>                      mov    eax, 0x135             EAX => 0x135\n"
        "   0x400085 <_start+5>                    mov    edi, 0                 EDI => 0\n"
        "   0x40008a <_start+10>                   mov    esi, 0                 ESI => 0\n"
        " ► 0x40008f <syscall_getcpu_label>        syscall <SYS_getcpu>\n"
        "        cpup:      0\n"
        "        nodep:     0\n"
        "        unused:    0\n"
        "   0x400091 <test_exit_group>             mov    eax, 0xe7              EAX => 0xe7\n"
        "   0x400096 <test_exit_group+5>           mov    edi, 0                 EDI => 0\n"
        "   0x40009b <syscall_exit_group_label>    syscall <SYS_exit_group>\n"
        "   0x40009d                               add    byte ptr [rax], al\n"
        "   0x40009f                               add    byte ptr [rax], al\n"
        "   0x4000a1                               add    byte ptr [rax], al\n"
        "   0x4000a3                               add    byte ptr [rax], al\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    await ctrl.execute("stepsyscall")
    dis = await ctrl.execute_and_capture("context disasm")
    assert dis == (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────\n"
        "   0x400085 <_start+5>                    mov    edi, 0                 EDI => 0\n"
        "   0x40008a <_start+10>                   mov    esi, 0                 ESI => 0\n"
        "   0x40008f <syscall_getcpu_label>        syscall <SYS_getcpu>\n"
        "   0x400091 <test_exit_group>             mov    eax, 0xe7              EAX => 0xe7\n"
        "   0x400096 <test_exit_group+5>           mov    edi, 0                 EDI => 0\n"
        " ► 0x40009b <syscall_exit_group_label>    syscall <SYS_exit_group>\n"
        "        error_code: 0\n"
        "   0x40009d                               add    byte ptr [rax], al\n"
        "   0x40009f                               add    byte ptr [rax], al\n"
        "   0x4000a1                               add    byte ptr [rax], al\n"
        "   0x4000a3                               add    byte ptr [rax], al\n"
        "   0x4000a5                               add    byte ptr [rax], al\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

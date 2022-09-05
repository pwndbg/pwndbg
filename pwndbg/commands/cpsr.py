import pwndbg.commands
import pwndbg.gdblib.arch
import pwndbg.gdblib.regs
from pwndbg.color import context
from pwndbg.color import message


@pwndbg.commands.ArgparsedCommand("Print out ARM CPSR or xPSR register")
@pwndbg.commands.OnlyWhenRunning
def cpsr():
    arm_print_psr()


@pwndbg.commands.ArgparsedCommand("Print out ARM xPSR or CPSR register")
@pwndbg.commands.OnlyWhenRunning
def xpsr():
    arm_print_psr()


def arm_print_psr():
    if pwndbg.gdblib.arch.current not in ("arm", "armcm"):
        print(message.warn("This is only available on ARM"))
        return

    reg = "cpsr" if pwndbg.gdblib.arch.current == "arm" else "xpsr"
    print(
        "%s %s"
        % (
            reg,
            context.format_flags(getattr(pwndbg.gdblib.regs, reg), pwndbg.gdblib.regs.flags[reg]),
        )
    )

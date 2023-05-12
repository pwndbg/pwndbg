import pwndbg.auxv
import pwndbg.commands
import pwndbg.commands.telescope
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
import pwndbg.search
from pwndbg.color import message
from pwndbg.commands import CommandCategory


def canary_value():
    auxv = pwndbg.auxv.get()
    at_random = auxv.get("AT_RANDOM", None)
    if at_random is None:
        return None, None

    global_canary = pwndbg.gdblib.memory.pvoid(at_random)

    # masking canary value as canaries on the stack has last byte = 0
    global_canary &= pwndbg.gdblib.arch.ptrmask ^ 0xFF

    return global_canary, at_random


@pwndbg.commands.ArgparsedCommand(
    "Print out the current stack canary.",
    category=CommandCategory.STACK,
)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.ParsedCommand(parser)
def canary(args):
    global_canary, at_random = canary_value()

    if global_canary is None or at_random is None:
        print(
            message.error("Couldn't find AT_RANDOM - can't display canary.")
        )
        return

    print(
        message.notice(
            "AT_RANDOM = %#x # points to (not masked) global canary value"
            % at_random
        )
    )
    print(
        message.notice(
            "Canary    = 0x%x (may be incorrect on != glibc)"
            % global_canary
        )
    )

    if args.all:
        print(message.success("Found valid canaries on the stacks:"))
        for stack in pwndbg.gdblib.stack.stacks.values():
            stack_canary = pwndbg.search.search(pwndbg.gdblib.arch.pack(global_canary), mappings=[stack])
            if not stack_canary:
                continue
            stack_canary = stack_canary[0]
            thread = pwndbg.proc.get_thread_containing(stack_canary)
            if thread is None:
                continue
            print(
                message.success(
                    f"Thread {thread.num}: {stack_canary - thread.sp} bytes from RSP"
                )
            )
            pwndbg.commands.telescope.telescope(
                address=stack_canary, count=1
            )
        return

    stack = pwndbg.gdblib.stack.current_stack()
    stack_canary = pwndbg.search.search(
        pwndbg.gdblib.arch.pack(global_canary), mappings=[stack]
    )

    if not stack_canary:
        print(message.warn("No valid canary found on the stack."))
        return

    stack_canary = stack_canary[0]
    thread = pwndbg.proc.get_thread_containing(stack_canary)
    if thread is None:
        print(message.warn("No thread found at current canary address."))
    else:
        print(
            message.success(
                f"Thread {thread.num}: {stack_canary - thread.sp} bytes from RSP"
            )
        )
    pwndbg.commands.telescope.telescope(address=stack_canary, count=

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
    aliases=("canary",),
)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.aliases("canary")
@pwndbg.commands.with_argparser
def canary(all: bool = False) -> None:
    global_canary, at_random = canary_value()

    if global_canary is None or at_random is None:
        print(message.error("Couldn't find AT_RANDOM - can't display canary."))
        return

    print(
        message.notice("AT_RANDOM = %#x # points to (not masked) global canary value" % at_random)
    )
    print(message.notice("Canary    = 0x%x (may be incorrect on != glibc)" % global_canary))

    stack_canaries = list(
        pwndbg.search.search(
            pwndbg.gdblib.arch.pack(global_canary), mappings=pwndbg.gdblib.stack.stacks.values()
        )
    )

    if not stack_canaries:
        print(message.warn("No valid canaries found on the stacks."))
        return

    if not all:
        current_thread = pwndbg.proc.current_thread
        current_rsp = int(pwndbg.regs.rsp)
        stack_canaries = [x for x in stack_canaries if x >= current_rsp]
        stack_canaries.sort()

        if not stack_canaries:
            print(message.warn("No valid canaries found on the current stack."))
            return

        print(message.success("Found valid canaries on the current stack:"))
        for stack_canary in stack_canaries:
            offset = current_rsp - stack_canary
            print(
                "Thread ID: %d, Address: %#x, Offset from RSP: %#x"
                % (current_thread.id, stack_canary, offset)
            )
            pwndbg.commands.telescope.telescope(address=stack_canary, count=1)
    else:
        print(message.success("Found valid canaries on the stacks:"))
        for stack in pwndbg.gdblib.stack.stacks.values():
            print(f"Stack {stack.id}:")
            stack_canaries = list(pwndbg.search.search(pwndbg.gdblib.arch.pack(global_canary), mappings=[stack]))
            if not stack_canaries:
                print(message.warn(f"No valid canaries found on stack {stack.id}."))
                continue

            for stack_canary in stack_canaries:
                offset = stack.rsp - stack_canary
                print(f"\tAddress: {stack_canary:#x}, Offset from RSP: {offset:#

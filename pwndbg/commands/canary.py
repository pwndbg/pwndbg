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
    "Print out the current stack canary.", category=CommandCategory.STACK
)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.aliases("can")
@pwndbg.commands.add_argument(
    "--all",
    "-a",
    action="store_true",
    help="Display all canaries for all threads.",
)
def canary(all: bool = False) -> None:
    global_canary, at_random = canary_value()

    if global_canary is None or at_random is None:
        print(message.error("Couldn't find AT_RANDOM - can't display canary."))
        return

    print(
        message.notice(
            "AT_RANDOM = %#x # points to (not masked) global canary value" % at_random
        )
    )
    print(
        message.notice(
            "Canary    = 0x%x (may be incorrect on != glibc)" % global_canary
        )
    )

    if not all:
        # Display canary for current thread
        stack_canary = find_canary_for_thread(pwndbg.procinfo.procs[0].tid)
        if not stack_canary:
            print(
                message.warn(
                    "No valid canary found on the stack for current thread."
                )
            )
            return

        print(
            message.success(
                f"Found valid canary on the stack for current thread ({pwndbg.procinfo.procs[0].tid}):"
            )
        )
        pwndbg.commands.telescope.telescope(address=stack_canary, count=1)

    else:
        # Display canaries for all threads
        found_canaries = False
        for proc in pwndbg.procinfo.procs:
            stack_canary = find_canary_for_thread(proc.tid)
            if stack_canary:
                found_canaries = True
                print(
                    message.success(
                        f"Found valid canary on the stack for thread {proc.tid}:"
                    )
                )
                pwndbg.commands.telescope.telescope(
                    address=stack_canary, count=1
                )

        if not found_canaries:
            print(message.warn("No valid canaries found on the stacks."))


def find_canary_for_thread(thread_id):
    for stack in pwndbg.gdblib.stack.stacks.values():
        if stack.thread_id == thread_id:
            rsp = pwndbg.regs.rsp
            canary_address = stack.sp - pwndbg.arch.ptrsize
            if canary_address >= rsp:
                return pwndbg.memory.u(canary_address)

    return None


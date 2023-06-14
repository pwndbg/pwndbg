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
    # masking canary value as canaries on the stack have the last byte = 0
    global_canary &= pwndbg.gdblib.arch.ptrmask ^ 0xFF
    return global_canary, at_random


@pwndbg.commands.ArgparsedCommand(
    "Print out the current stack canary.", category=CommandCategory.STACK
)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.aliases("canary", "canaries")
@pwndbg.commands.bool_argument("--all", "-a", "Display all canaries.", default=False)
def canary(all: bool) -> None:
    global_canary, at_random = canary_value()
    if global_canary is None or at_random is None:
        print(message.error("Couldn't find AT_RANDOM - can't display canary."))
        return

    print(message.notice("AT_RANDOM = %#x # points to (not masked) global canary value" % at_random))
    print(message.notice("Canary    = 0x%x (may be incorrect on != glibc)" % global_canary))

    current_thread = pwndbg.proc.current_thread_id()
    current_rsp = pwndbg.regs.rsp
    stack_canaries = []

    for thread_id, stack in pwndbg.stack.stacks.items():
        stack_start = stack.start
        stack_end = stack.end
        if stack_start <= current_rsp < stack_end:
            stack_canaries.extend(
                pwndbg.search.search(pwndbg.gdblib.arch.pack(global_canary), mappings=[stack])
            )

    if not stack_canaries:
        print(message.warn("No valid canaries found on the current stack."))
        return

    print(message.success(f"Found valid canaries on the current stack (thread {current_thread}):"))

    for stack_canary in stack_canaries:
        offset_from_rsp = stack_canary - current_rsp
        thread_id = pwndbg.stack.thread_id_from_stack(stack_canary)
        if all:
            print(
                message.address(
                    f"Thread {thread_id}: Canary at offset {offset_from_rsp:#x} from RSP: {stack_canary:#x}"
                )
            )
        elif thread_id == current_thread:
            print(
                message.address(
                    f"Canary at offset {offset_from_rsp:#x} from RSP: {stack_canary:#x}"
                )
            )
            pwndbg.commands.telescope.telescope(address=stack_canary, count=1)

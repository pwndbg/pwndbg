from __future__ import annotations

import argparse

import pwndbg.aglib.proc
import pwndbg.aglib.regs_mod
import pwndbg.aglib.symbol
import pwndbg.aglib.vmmap
import pwndbg.commands
import pwndbg.dbg_mod
from pwndbg.color import message

parser = argparse.ArgumentParser(
    description="""
Dumps an instruction trace to disk.

This command will execute consecutive single steps from the current pc, until the end_address is reached or the program exits. 
Saving each pc to a file on disk. If -v is passed the backing file of the memory region will also be saved.
"""
)
parser.add_argument("trace_file", type=str, help="A path to write the trace file.")
parser.add_argument("end_address", type=int, help="The end address to stop tracing.")
parser.add_argument(
    "-v", "--verbose", default=False, action="store_true", help="Flag to dump backing file."
)


async def _step_and_log(
    ec: pwndbg.dbg_mod.ExecutionController,
    file_handle,
    vmmap_object,
    end_address: int | None = None,
) -> None:
    if end_address == 0:
        return
    count = 0
    while pwndbg.aglib.proc.alive():
        current_pc = pwndbg.aglib.regs_mod.regs.pc
        if current_pc == end_address:
            break
        current_symbol = pwndbg.aglib.symbol.resolve_addr(int(current_pc))
        await ec.single_step()
        if vmmap_object != None:
            page_ = vmmap_object.lookup_page(current_pc)

            if page_:
                log_line = f"[{hex(current_pc)}]!{current_symbol} : {page_.objfile:<8}\n"
            else:
                log_line = f"[{hex(current_pc)}]!{current_symbol}\n"
            file_handle.write(log_line)

        else:
            log_line = f"[{hex(current_pc)}]!{current_symbol}\n"
            file_handle.write(log_line)
        count += 1
    print(message.info(f"instr-trace: Dumped {count} instructions"))


@pwndbg.commands.Command(
    parser,
    category=pwndbg.commands.CommandCategory.MISC,
    examples="instr-trace /tmp/trace.txt 0x555555555158 -v",
)
@pwndbg.commands.OnlyWhenRunning
def instr_trace(trace_file: str, end_address: int, verbose: bool) -> None:
    vmmap_object = pwndbg.aglib.vmmap.get_memory_map()

    async def dump_trace_log(ec: pwndbg.dbg_mod.ExecutionController) -> None:
        with open(trace_file, "w+") as f:
            if not verbose:
                await _step_and_log(ec, file_handle=f, vmmap_object=None, end_address=end_address)
            else:
                await _step_and_log(
                    ec, file_handle=f, vmmap_object=vmmap_object, end_address=end_address
                )

    try:
        print(
            message.info(
                f"instr-trace: Dumping instruction trace to {trace_file} until {hex(end_address)}..."
            )
        )
        pwndbg.dbg.selected_inferior().dispatch_execution_controller(dump_trace_log)
        print(message.info("instr-trace: Complete."))
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"instr-trace Error: {e}"))

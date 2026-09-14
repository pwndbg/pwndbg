from __future__ import annotations

import argparse
import io

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
Saving each pc to a file on disk. Multiple formats can be provided such as lighthouse, full and raw.
"""
)
parser.add_argument("trace_file", type=str, help="A path to write the trace file.")
parser.add_argument("end_address", type=int, help="The end address to stop tracing.")
parser.add_argument(
    "format", type=str, choices=["raw", "lighthouse", "full"], help="The type of trace output"
)


async def _step_and_log(
    ec: pwndbg.dbg_mod.ExecutionController,
    file_handle: io.TextIOWrapper,
    vmmap_object: pwndbg.dbg_mod.MemoryMap,
    end_address: int = 0,
    format: str = "raw",
) -> None:
    count = 0
    while pwndbg.aglib.proc.alive():
        current_pc = pwndbg.aglib.regs_mod.regs.pc
        if current_pc == end_address:
            break
        if current_pc is None:
            message.error("instr-trace: Failed to get current PC. Exiting.")
            return

        await ec.single_step()
        page_ = vmmap_object.lookup_page(current_pc)

        # if page not available fallback to raw
        if page_ is None:
            message.error("instr-trace: failed to lookup page falling back to raw format")
            log_line = f"{hex(current_pc)}"
            file_handle.write(log_line)
            count += 1
            continue

        # format line
        match format:
            case "raw":
                # raw format
                log_line = f"{hex(current_pc)}\n"
            case "lighthouse":
                # lighthouse coverage format module+offset https://github.com/gaasedelen/lighthouse
                offset = hex(page_.end - current_pc)
                filename = page_.objfile.split("/")[-1]
                log_line = f"{filename}+{offset}\n"
            case "full":
                # symbols included
                current_symbol = pwndbg.aglib.symbol.resolve_addr(int(current_pc))
                filename = page_.objfile.split("/")[-1]
                log_line = f"{filename}!{current_symbol}\n"
            case _:
                # should never be possible as we assert in command input
                message.error(
                    f"instr-trace: format {format} not in acceptable formats: [lighthouse, raw, full]"
                )
                return
        file_handle.write(log_line)
        count += 1

    print(message.info(f"instr-trace: Dumped {count} instructions"))


@pwndbg.commands.Command(
    parser,
    category=pwndbg.commands.CommandCategory.MISC,
    examples="instr-trace /tmp/trace.txt 0x555555555158 full",
)
@pwndbg.commands.OnlyWhenRunning
def instr_trace(trace_file: str, end_address: int, format: str) -> None:
    vmmap_object = pwndbg.aglib.vmmap.get_memory_map()

    async def dump_trace_log(ec: pwndbg.dbg_mod.ExecutionController) -> None:
        with open(trace_file, "w+") as f:
            await _step_and_log(
                ec, file_handle=f, vmmap_object=vmmap_object, end_address=end_address, format=format
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

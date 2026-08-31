import argparse
import pwndbg.commands
import pwndbg.dbg_mod
import pwndbg.aglib.proc
import pwndbg.aglib.next
import pwndbg.aglib.symbol
import pwndbg.aglib.vmmap
import pwndbg.aglib.regs_mod

parser = argparse.ArgumentParser(description="Command description.")
parser.add_argument("end_address", type=int, help="An example argument.")

async def _step_and_log(
    ec: pwndbg.dbg_mod.ExecutionController,
    file_handle,
    vmmap_object: pwndbg.dbg_mod.MemoryMap,
    end_address : int | None = None,
) -> None:
    if (end_address == 0): return 
    while(pwndbg.aglib.proc.alive()):
        current_pc = pwndbg.aglib.regs_mod.regs.pc
        if (current_pc == end_address): break;
        current_symbol = pwndbg.aglib.symbol.resolve_addr(int(current_pc))
        await ec.single_step()
        page_ = vmmap_object.lookup_page(current_pc)
        if (vmmap_object and page_):
            log_line = f"[{hex(current_pc)}]!{current_symbol} : {page_.objfile:<8}\n"
        else:
            log_line = f"[{hex(current_pc)}]!{current_symbol}\n"
        file_handle.write(log_line)

@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.MISC)
def instr_trace(end_address: int) -> None:
    vmmap_object = pwndbg.aglib.vmmap.get_memory_map()
    with open("/tmp/trace.txt","w+") as f:
        async def dump_trace_log(ec: pwndbg.dbg_mod.ExecutionController) -> None: 
            await _step_and_log(ec, file_handle=f, vmmap_object=vmmap_object,  end_address=end_address)
        try:
          print(f"Argument is {end_address}")
          pwndbg.dbg.selected_inferior().dispatch_execution_controller(dump_trace_log)
        except pwndbg.dbg_mod.Error as e:
          print(f"ERROR: {e}")
        return

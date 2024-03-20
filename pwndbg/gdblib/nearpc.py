from __future__ import annotations

from typing import List

import gdb
from capstone import *  # noqa: F403

import pwndbg.arguments
import pwndbg.color
import pwndbg.color.context as C
import pwndbg.color.disasm as D
import pwndbg.color.theme
import pwndbg.commands.comments
import pwndbg.disasm
import pwndbg.gdblib.config
import pwndbg.gdblib.regs
import pwndbg.gdblib.strings
import pwndbg.gdblib.symbol
import pwndbg.gdblib.vmmap
import pwndbg.ida
import pwndbg.lib.functions
import pwndbg.ui
from pwndbg.color import ColorConfig
from pwndbg.color import ColorParamSpec
from pwndbg.color import message


def ljust_padding(lst):
    longest_len = max(map(len, lst)) if lst else 0
    return [s.ljust(longest_len) for s in lst]


c = ColorConfig(
    "nearpc",
    [
        ColorParamSpec("symbol", "normal", "color for nearpc command (symbol)"),
        ColorParamSpec("address", "normal", "color for nearpc command (address)"),
        ColorParamSpec("prefix", "none", "color for nearpc command (prefix marker)"),
        ColorParamSpec("syscall-name", "red", "color for nearpc command (resolved syscall name)"),
        ColorParamSpec("argument", "bold", "color for nearpc command (target argument)"),
        ColorParamSpec("ida-anterior", "bold", "color for nearpc command (IDA anterior)"),
        ColorParamSpec("branch-marker", "normal", "color for nearpc command (branch marker line)"),
    ],
)

nearpc_branch_marker = pwndbg.color.theme.add_param(
    "nearpc-branch-marker", "    ↓", "branch marker line for nearpc command"
)
nearpc_branch_marker_contiguous = pwndbg.color.theme.add_param(
    "nearpc-branch-marker-contiguous", " ", "contiguous branch marker line for nearpc command"
)
pwndbg.color.theme.add_param("highlight-pc", True, "whether to highlight the current instruction")
pwndbg.color.theme.add_param("nearpc-prefix", "►", "prefix marker for nearpc command")
pwndbg.gdblib.config.add_param("left-pad-disasm", True, "whether to left-pad disassembly")
nearpc_lines = pwndbg.gdblib.config.add_param(
    "nearpc-lines", 10, "number of additional lines to print for the nearpc command"
)
show_args = pwndbg.gdblib.config.add_param(
    "nearpc-show-args", True, "whether to show call arguments below instruction"
)
show_opcode_bytes = pwndbg.gdblib.config.add_param(
    "nearpc-num-opcode-bytes",
    0,
    "number of opcode bytes to print for each instruction",
    param_class=gdb.PARAM_ZUINTEGER,
)
opcode_separator_bytes = pwndbg.gdblib.config.add_param(
    "nearpc-opcode-separator-bytes",
    1,
    "number of spaces between opcode bytes",
    param_class=gdb.PARAM_ZUINTEGER,
)


def nearpc(
    pc: int = None, lines: int = None, emulate=False, repeat=False, use_cache=False, linear=False
) -> List[str]:
    """
    Disassemble near a specified address.

    The `linear` argument specifies if we should disassemble linearly in memory, or take jumps into account
    """

    # Repeating nearpc (pressing enter) makes it show next addresses
    # (writing nearpc explicitly again will reset its state)
    if repeat:
        # TODO: It would be better to do this in the nearpc command itself, but
        # that would require a larger refactor
        pc = nearpc.next_pc

    result: List[str] = []

    if pc is not None:
        pc = gdb.Value(pc).cast(pwndbg.gdblib.typeinfo.pvoid)

    # Fix the case where we only have one argument, and
    # it's a small value.
    if lines is None and (pc is None or int(pc) < 0x100):
        lines = pc
        pc = None

    if pc is None:
        pc = pwndbg.gdblib.regs.pc

    if lines is None:
        lines = nearpc_lines // 2

    pc = int(pc)
    lines = int(lines)

    # Check whether we can even read this address
    if not pwndbg.gdblib.memory.peek(pc):
        result.append(message.error("Invalid address %#x" % pc))

    # # Load source data if it's available
    # pc_to_linenos = collections.defaultdict(lambda: [])
    # lineno_to_src = {}
    # frame = gdb.selected_frame()
    # if frame:
    #     sal = frame.find_sal()
    #     if sal:
    #         symtab = sal.symtab
    #         objfile = symtab.objfile
    #         sourcefilename = symtab.filename
    #         with open(sourcefilename, 'r') as sourcefile:
    #             lineno_to_src = {i:l for i,l in enumerate(sourcefile.readlines())}

    #         for line in symtab.linetable():
    #             pc_to_linenos[line.pc].append(line.line)

    instructions, index_of_pc = pwndbg.disasm.near(
        pc, lines, emulate=emulate, show_prev_insns=not repeat, use_cache=use_cache, linear=linear
    )

    if pwndbg.gdblib.memory.peek(pc) and not instructions:
        result.append(message.error("Invalid instructions at %#x" % pc))

    # In case $pc is in a new map we don't know about,
    # this will trigger an exploratory search.
    pwndbg.gdblib.vmmap.find(pc)

    # Gather all addresses and symbols for each instruction
    # Ex: <main+43>
    symbols = [pwndbg.gdblib.symbol.get(i.address) for i in instructions]
    addresses: List[str] = ["%#x" % i.address for i in instructions]

    nearpc.next_pc = instructions[-1].address + instructions[-1].size if instructions else 0

    # Format the symbol name for each instruction
    symbols = [f"<{sym}> " if sym else "" for sym in symbols]

    # Pad out all of the symbols and addresses
    if pwndbg.gdblib.config.left_pad_disasm and not repeat:
        symbols = ljust_padding(symbols)
        addresses = ljust_padding(addresses)

    assembly_strings = D.instructions_and_padding(instructions)

    prev = None

    # Print out each instruction
    for i, (address_str, symbol, instr, asm) in enumerate(
        zip(addresses, symbols, instructions, assembly_strings)
    ):
        prefix_sign = pwndbg.gdblib.config.nearpc_prefix

        # Show prefix only on the specified address and don't show it while in repeat-mode
        # or when showing current instruction for the second time
        show_prefix = instr.address == pc and not repeat and i == index_of_pc
        prefix = " %s" % (prefix_sign if show_prefix else " " * len(prefix_sign))
        prefix = c.prefix(prefix)

        pre = pwndbg.ida.Anterior(instr.address)
        if pre:
            result.append(c.ida_anterior(pre))

        # Colorize address and symbol if not highlighted
        # symbol is fetched from gdb and it can be e.g. '<main+8>'
        # In case there are duplicate instances of an instruction (tight loop),
        # ones that the instruction pointer is not at stick out a little, to indicate the repetition
        if not pwndbg.gdblib.config.highlight_pc or instr.address != pc or repeat:
            address_str = c.address(address_str)
            symbol = c.symbol(symbol)
        elif pwndbg.gdblib.config.highlight_pc and i == index_of_pc:
            # If this instruction is the one the PC is at.
            # In case of tight loops, with emulation we may display the same instruction multiple times.
            # Only highlight current instance, not past or future times.
            address_str = C.highlight(address_str)
            symbol = C.highlight(symbol)

        # If this instruction performs a memory access operation, we should tell
        # the user anything we can figure out about the memory it's trying to
        # access.
        # mem_access = ""
        if instr.address == pc and False:
            accesses = []
            for operand in instr.operands:
                if operand.type != CS_OP_MEM:
                    continue
                address = operand.mem.disp

                base = operand.mem.base
                if base > 0:
                    address += pwndbg.gdblib.regs[instr.reg_name(base)]

                vmmap = pwndbg.gdblib.vmmap.get()
                page = next((page for page in vmmap if address in page), None)
                if page is None:
                    # This is definetly invalid. Don't even bother checking
                    # any other conditions.
                    accesses.append(f"[X] {address:#x}")
                    continue

                if operand.access == CS_AC_READ and not page.read:
                    # Tried to read from a page we can't read.
                    accesses.append(f"[X] {address:#x}")
                    continue
                if operand.access == CS_AC_WRITE and not page.write:
                    # Tried to write to a page we can't write.
                    accesses.append(f"[X] {address:#x}")
                    continue

                # At this point, we know the operation is legal, but we don't
                # know where it's going yet. It could be going to either memory
                # managed by libc or memory managed by the program itself.

                if not pwndbg.heap.current.is_initialized():
                    # The libc heap hasn't been initialized yet. There's not a
                    # lot that we can say beyond this point.
                    continue
                allocator = pwndbg.heap.current

                heap = pwndbg.heap.ptmalloc.Heap(address)
                chunk = None
                for ch in heap:
                    # Find the chunk in this heap the corresponds to the address
                    # we're trying to access.
                    offset = address - ch.address
                    if offset >= 0 and offset < ch.real_size:
                        chunk = ch
                        break
                if chunk is None:
                    # The memory for this chunk is not managed by libc. We can't
                    # reason about it.
                    accesses.append(f"[?] {address:#x}")
                    continue

                # Scavenge through all of the bins in the current allocator.
                # Bins track free chunks, so, whether or not we can find the
                # chunk we're trying to access in a bin will tells us whether
                # this access is a UAF.
                bins_list = [
                    allocator.fastbins(chunk.arena.address),
                    allocator.smallbins(chunk.arena.address),
                    allocator.largebins(chunk.arena.address),
                    allocator.unsortedbin(chunk.arena.address),
                ]
                if allocator.has_tcache():
                    bins_list.append(allocator.tcachebins(None))

                bins_list = [x for x in bins_list if x is not None]
                for bins in bins_list:
                    if bins.contains_chunk(chunk.real_size, chunk.address):
                        # This chunk is free. This is a UAF.
                        accesses.append(f"[UAF] {address:#x}")
                        continue
            # mem_access = " ".join(accesses)

        opcodes = ""
        if show_opcode_bytes > 0:
            opcodes = (opcode_separator_bytes * " ").join(
                f"{c:02x}" for c in instr.bytes[: int(show_opcode_bytes)]
            )
            # Must add +3 at minimum, due to truncated instructions adding "..."
            align = show_opcode_bytes * 2 + 3
            if opcode_separator_bytes > 0:
                # add the length of the maximum number of separators to the alignment
                align += (show_opcode_bytes - 1) * opcode_separator_bytes  # type: ignore[operator]
            if len(instr.bytes) > show_opcode_bytes:
                opcodes += pwndbg.color.gray("...")
                # the length of gray("...") is 12, so we need to add extra 9 (12-3) alignment length for the invisible characters
                align += 9  # len(pwndbg.color.gray(""))
            opcodes = opcodes.ljust(align)
            if pwndbg.gdblib.config.highlight_pc and i == index_of_pc:
                opcodes = C.highlight(opcodes)

        # Example line:
        # ► 0x7ffff7f1aeb6 0f bd c0    <__strrchr_avx2+70>    bsr    eax, eax
        # prefix        = ►
        # address_str   = 0x555555556030
        # opcodes       = 0f bd c0                  Opcodes are enabled with the 'nearpc-num-opcode-bytes' setting
        # symbol        = <__strrchr_avx2+70>
        # asm           = bsr    eax, eax           (jump target/annotation would go here too)

        # mem_access was on this list, but not used due to the `and False` in the code that sets it above
        line = " ".join(filter(None, (prefix, address_str, opcodes, symbol, asm)))

        # If there was a branch before this instruction which was not
        # contiguous, put in some ellipses.
        if prev and prev.address + prev.size != instr.address:
            result.append(c.branch_marker(f"{nearpc_branch_marker}"))

        # Otherwise if it's a branch and it *is* contiguous, just put
        # and empty line.
        elif prev and any(g in prev.groups for g in (CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET)):
            if nearpc_branch_marker_contiguous:
                result.append("%s" % nearpc_branch_marker_contiguous)

        # For syscall instructions, put the name on the side
        if instr.address == pc:
            syscall_name = pwndbg.arguments.get_syscall_name(instr)
            if syscall_name:
                line += " <%s>" % c.syscall_name("SYS_" + syscall_name)

        # For Comment Function
        try:
            line += " " * 10 + C.comment(
                pwndbg.commands.comments.file_lists[pwndbg.gdblib.proc.exe][hex(instr.address)]
            )
        except Exception:
            pass

        result.append(line)

        # For call instructions, attempt to resolve the target and
        # determine the number of arguments.
        if show_args:
            result.extend(
                "%8s%s" % ("", arg) for arg in pwndbg.arguments.format_args(instruction=instr)
            )

        prev = instr

    return result


nearpc.next_pc = 0

from __future__ import annotations

import argparse
import re
import tempfile
from collections.abc import Iterator

import pwndbg.aglib
import pwndbg.aglib.disasm.disassembly
import pwndbg.aglib.proc
import pwndbg.aglib.vmmap
import pwndbg.color.disasm
import pwndbg.color.memory
import pwndbg.commands
import pwndbg.dbg_mod
import pwndbg.dintegration
import pwndbg.lib.memory
from pwndbg.aglib.disasm.disassembly import get_disassembler
from pwndbg.color import message
from pwndbg.commands import CommandCategory


class RawMemoryBinary:
    def __init__(self, options, start_addr: int):
        self.start_addr = start_addr
        self.__fileName = options.binary
        self.__rawBinary = None
        self.cs = get_disassembler(pwndbg.aglib.arch.get_capstone_constants(pwndbg.aglib.regs.pc))

        with open(self.__fileName, "rb") as fp:
            self.__rawBinary = fp.read()

    def getBinary(self):
        return self

    def getFileName(self):
        return self.__fileName

    def getRawBinary(self):
        return self.__rawBinary

    def getEntryPoint(self):
        raise NotImplementedError()

    def getExecSections(self):
        return [
            {
                "name": "raw",
                "offset": 0,
                "size": len(self.__rawBinary),
                "vaddr": self.start_addr,
                "opcodes": bytes(self.__rawBinary),
            }
        ]

    def getDataSections(self):
        raise NotImplementedError()

    def getArch(self):
        return self.cs.arch

    def getArchMode(self):
        return self.cs.mode

    def getEndian(self):
        # Already returned in `getArchMode` func
        return 0

    def getFormat(self):
        return "Raw"


def _rop(
    file_path: str,
    grep: str | None,
    argument: list[str],
    start_addr: int | None = None,
    symbols: bool = False,
    plain: bool = False,
) -> bool:
    import contextlib
    from io import StringIO

    from ropgadget.args import Args
    from ropgadget.core import Core

    stderr = StringIO()

    with contextlib.redirect_stderr(stderr):
        try:
            args = Args(
                arguments=[
                    "--binary",
                    file_path,
                    *argument,
                ]
            )
        except SystemExit as e:  # ropgadget runs argparse which calls sys.exit
            if e.code == 2:  # invalid args
                full = stderr.getvalue()
                print(
                    message.error(full.splitlines()[-1].removeprefix(": error: "))
                )  # we skip the usage block, and only print the error
            return False

    options = args.getArgs()
    c = Core(options)

    if start_addr is not None:
        # HACK: to load from our class
        c._Core__binary = RawMemoryBinary(options, start_addr=start_addr)
    else:
        c.do_binary(file_path, silent=True)

    # Find gadgets
    c.do_load(0, silent=True)

    if symbols:
        decomp_stack_vars: dict[int, str] = pwndbg.dintegration.manager.get_stack_var_dict_all()
    else:
        decomp_stack_vars = {}

    print("Gadgets information\n============================================================")
    for gadget in c.gadgets():
        insts = gadget.get("gadget", "")
        if not insts:
            continue

        vaddr = gadget["vaddr"]

        n_insts = insts.count(";") + 1
        enhanced_insts = pwndbg.aglib.disasm.disassembly.get(
            vaddr, n_insts, enhance=not plain, padding=0
        )
        insts_str = " ; ".join(ins.asm_string for ins in enhanced_insts)

        if symbols:
            out = f"{pwndbg.color.memory.get_address_and_symbol(vaddr, decomp_stack_vars)}: {insts_str}"
        else:
            out = f"{pwndbg.color.memory.get(vaddr)}: {insts_str}"

        plain_out = pwndbg.color.strip(out)

        if grep:
            # grep search
            if not re.search(grep, insts) and not re.search(grep, plain_out):
                continue

        print(plain_out if plain else out)

    print(f"\nUnique gadgets found: {len(c.gadgets())}")
    return True


def split_range_to_chunks(
    range_start: int, range_end: int, chunk_size: int = 10 * 1024 * 1024
) -> Iterator[tuple[int, int, int, int]]:
    total_parts = ((range_end - range_start) + chunk_size - 1) // chunk_size

    for current_part, range_start_chunk in enumerate(range(range_start, range_end, chunk_size), 1):
        range_end_chunk = min(range_start_chunk + chunk_size, range_end)
        range_size = range_end_chunk - range_start_chunk

        yield (
            range_start_chunk,
            range_size,
            current_part,
            total_parts,
        )


def parse_size(size_str: str) -> int:
    unit_multipliers = {
        "b": 1,
        "kb": 1024,
        "mb": 1024**2,
        "gb": 1024**3,
        "tb": 1024**4,
        "kib": 1024,
        "mib": 1024**2,
        "gib": 1024**3,
        "tib": 1024**4,
    }
    size_str = size_str.strip().lower()

    match = re.match(r"(\d+)\s*(b|kb|mb|gb|tb|kib|mib|gib|tib)", size_str)
    if not match:
        raise ValueError(f"Invalid size string: {size_str}")

    value = int(match.group(1))
    unit = match.group(2)
    return value * unit_multipliers[unit]


def iterate_over_pages(mem_limit: int) -> Iterator[tuple[str, pwndbg.lib.memory.Page | None]]:
    if not pwndbg.aglib.proc.alive():
        yield pwndbg.aglib.proc.exe(), None
        return

    proc = pwndbg.dbg.selected_inferior()
    for page in pwndbg.aglib.vmmap.get_memory_map().ranges():
        if not page.execute:
            continue

        print(message.info(f"Searching in {hex(page.start)} {hex(page.end)} {page.objfile}"))
        if page.memsz > mem_limit:
            print(
                message.hint(
                    "WARNING: The memory page size is too large to dump.\n"
                    "WARNING: Parsing this large memory page might take an excessive amount of time...\n"
                    "WARNING: To process larger pages, increase the `--memlimit` parameter (e.g., `--memlimit 100MB`)."
                )
            )
            continue

        with tempfile.NamedTemporaryFile(mode="a+b") as fmem:
            try:
                for start, size, progress_cur, progress_max in split_range_to_chunks(
                    page.start, page.end
                ):
                    if progress_max > 1:
                        print(message.hint(f"Dumping memory... {progress_cur} / {progress_max}"))

                    mem_data = proc.read_memory(address=start, size=size)
                    fmem.write(mem_data)
            except pwndbg.dbg_mod.Error as e:
                print(message.error(f"WARNING: failed to read page: {e}"))
                continue

            fmem.flush()
            yield fmem.name, page


parser = argparse.ArgumentParser(
    description="Dump ROP gadgets with Jon Salwan's ROPgadget tool.",
)
parser.add_argument("--grep", type=str, help="String to grep the output for")
parser.add_argument(
    "--memlimit", type=str, default="50MB", help="Maximum size of memory pages to scan"
)
parser.add_argument(
    "--symbols", action="store_true", help="Show symbols for/of gadgets (if there are any)"
)
parser.add_argument("--plain", action="store_true", help="Plain output (no highlighting)")
parser.add_argument("arguments", nargs="*", type=str, help="Arguments to pass to ROPgadget")


@pwndbg.commands.Command(
    parser,
    aliases=["ropgadget"],
    category=CommandCategory.INTEGRATIONS,
    examples="""
pwndbg> rop --grep 'pop rdi' -- --nojop
Gadgets information
============================================================
[...]
0x0007dce8 : pop rdi ; or dword ptr [rax], eax ; add rsp, 0x28 ; ret
0x0007d838 : pop rdi ; or dword ptr [rax], eax ; je 0x7d840 ; ret
0x0005b13d : pop rdi ; pop rbp ; ret
0x0001ee23 : pop rdi ; ret

Unique gadgets found: 8514
    """,
)
@pwndbg.commands.OnlyWithFile
def rop(grep: str | None, memlimit: str, symbols: bool, plain: bool, arguments: list[str]) -> None:
    memlimit = parse_size(memlimit)

    for file_path, page in iterate_over_pages(memlimit):
        should_continue = _rop(
            file_path,
            grep,
            arguments,
            start_addr=page.start if page else None,
            symbols=symbols,
            plain=plain,
        )
        if not should_continue:
            break

"""
IPython interactive helpers for pwndbg.

Provides convenient shortcuts for common debugging operations.
"""

from __future__ import annotations

from typing import Any

import pwndbg.aglib.memory
import pwndbg.aglib.vmmap
import pwndbg.hexdump
import pwndbg.search
from pwndbg.lib.tips import color_tip

mr = pwndbg.aglib.memory.read
mw = pwndbg.aglib.memory.write
regs = pwndbg.aglib.regs
rr = pwndbg.aglib.regs.read_reg
rw = pwndbg.aglib.regs.write_reg


def hd(addr: int, count: int = 0x40) -> None:
    """HexDump - Hexdump memory at address

    Args:
        addr: Address to dump
        count: Number of bytes (default: 0x40)

    Example:
        hd(0x400000)
        hd(0x400000, 0x100)
    """
    data = pwndbg.aglib.memory.read(addr, count)
    for line in pwndbg.hexdump.hexdump(bytes(data), address=addr, count=count):
        print(line)


def ms(
    pattern: bytes,
    start: int | None = None,
    end: int | None = None,
    limit: int = 100,
    show: bool = True,
) -> list[int]:
    """Search Memory for byte pattern

    Args:
        pattern: Bytes to search for
        start: Start address (optional)
        end: End address (optional)
        limit: Max results (default: 100)
        show: Print results

    Returns:
        List of addresses where pattern found

    Example:
        ms(b"ELF")
        ms(b"\\x90\\x90", limit=10)
    """
    results = list(pwndbg.search.search(searchfor=pattern, start=start, end=end, limit=limit))

    if show:
        for addr in results:
            print(f"{addr:#x}")

    return results


def vm(show: bool = True) -> tuple[Any, ...]:
    """Virtual memory Map - Show memory mappings.

    Args:
        show: Print formatted output

    Returns:
        Tuple of memory pages

    Example:
        vm()           # Print vmmap
        pages = vm(show=False)  # Get raw data
    """
    pages = pwndbg.aglib.vmmap.get()

    if show:
        print("Address Range          Perms  Size      Offset    File")
        print("-" * 80)
        for page in pages:
            perms = ""
            perms += "r" if page.read else "-"
            perms += "w" if page.write else "-"
            perms += "x" if page.execute else "-"
            size = page.end - page.start
            offset = f"{page.offset:#x}" if page.offset is not None else "-"
            objfile = page.objfile or ""
            print(
                f"{page.start:#018x}-{page.end:#018x} {perms}  {size:#010x}  {offset:8}  {objfile}"
            )

    return pages


def aliases() -> None:
    """Print help for all available shortcuts."""
    help_text = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     Pwndbg IPython Shortcuts Reference                       ║
╚═══════════════════════════════════════════════════════════════════════════════╝

MEMORY OPERATIONS:
  mr(addr, count=0x40)                 Read memory bytes
  mw(addr, data)                       Write memory
  hd(addr, count=0x40)                 Hexdump memory
  ms(pattern, start, end, limit, show) Search memory for bytes

REGISTER OPERATIONS:
  regs.<name>                          Read register value
  rr(name)                             Read register value
  rw(name, value)                      Write register value

VIRTUAL MEMORY:
  vm(show=True)                        Show virtual memory mappings

For more info: type help(function_name), e.g., help(mr)
"""
    print(help_text)


def get_ipi_namespace() -> dict[str, Any]:
    """Get dictionary of all helpers to inject into IPython namespace.

    Returns:
        Dictionary mapping names to helper functions
    """
    return {
        "mr": mr,
        "mw": mw,
        "hd": hd,
        "ms": ms,
        "rr": rr,
        "rw": rw,
        "vm": vm,
        "aliases": aliases,
    }


def get_banner() -> str:
    """Get banner text to display when entering ipi.

    Returns:
        Banner string
    """
    is_dead_warn = "Note: `process is not alive now`\n" if not pwndbg.aglib.proc.alive() else ""
    return color_tip(
        "Shortcuts: read/write regs: `rr(name)`, `rw(name, val)` | memory: `mr(addr, count)`, `wr(addr, count)`\n"
        "           hexdump: `hd(addr, count)`                 | vmmap: `vm()`\n"
        + is_dead_warn
        + "Use `aliases()` for help"
    )

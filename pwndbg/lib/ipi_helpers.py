"""
IPython interactive helpers for pwndbg.

Provides convenient shortcuts for common debugging operations.
"""

from __future__ import annotations

from typing import Any

import pwndbg.aglib.memory
import pwndbg.aglib.regs  # type: ignore[import-untyped]
import pwndbg.aglib.vmmap
import pwndbg.hexdump
import pwndbg.search


def mr(addr: int, count: int = 0x40, show: bool = False) -> bytearray:
    """Memory Read - Read memory from address.

    Args:
        addr: Address to read from
        count: Number of bytes (default: 0x40)
        show: Print hexdump instead of returning data

    Returns:
        bytearray of memory (if show=False)

    Example:
        mr(0x400000)        # Read 0x40 bytes
        mr(0x400000, 0x100) # Read 0x100 bytes
        mr(0x400000, show=True)  # Print hexdump
    """
    data = pwndbg.aglib.memory.read(addr, count)
    if show:
        for line in pwndbg.hexdump.hexdump(bytes(data), address=addr, count=count):
            print(line)
        return bytearray()  # Return empty to avoid double output
    return data


def mw(addr: int, data: bytes | str) -> None:
    """Memory Write - Write data to memory.

    Args:
        addr: Address to write to
        data: Bytes or string to write

    Example:
        mw(0x400000, b"\\x90\\x90")
        mw(0x400000, "hello")
    """
    pwndbg.aglib.memory.write(addr, data)


def hd(addr: int, count: int = 0x40) -> None:
    """HexDump - Print hexdump of memory.

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
    """Memory Search - Search for byte pattern.

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


def rr(name: str) -> int | None:
    """Register Read - Read register value.

    Args:
        name: Register name

    Returns:
        Register value as int

    Example:
        rr("rax")
        rr("rip")
    """
    return pwndbg.aglib.regs.read_reg(name)


def rw(name: str, value: int) -> None:
    """Register Write - Write register value.

    Args:
        name: Register name
        value: Value to write

    Example:
        rw("rax", 0x1234)
    """
    pwndbg.aglib.regs.write_reg(name, value)


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
            objfile = page.objfile if page.objfile else ""
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
  mr(addr, count=0x40, show=False)     Read memory bytes
  mw(addr, data)                       Write memory
  hd(addr, count=0x40)                 Hexdump memory
  ms(pattern, start, end, limit, show) Search memory for bytes

REGISTER OPERATIONS:
  rr(name)                             Read register value
  rw(name, value)                      Write register value

VIRTUAL MEMORY:
  vm(show=True)                        Show memory mappings

EXAMPLES:
  mr(0x400000)              # Read 0x40 bytes from 0x400000
  mr(0x400000, 0x100)       # Read 0x100 bytes
  mr(0x400000, show=True)   # Print hexdump
  mw(0x400000, b"\\x90\\x90") # Write NOP bytes
  hd(0x400000, 0x80)        # Hexdump 0x80 bytes
  ms(b"ELF")                # Search for ELF magic
  rr("rax")                 # Read RAX register
  rw("rip", 0x401000)       # Set RIP register
  vm()                      # Show virtual memory map

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
    return "Shortcuts: mr, mw, hd, ms, rr, rw, vm | Type aliases() for help"

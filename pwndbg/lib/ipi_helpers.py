"""
IPython interactive helpers for pwndbg.

Provides convenient shortcuts and namespace for common debugging operations.
"""

from __future__ import annotations

from typing import Any

import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.aglib.vmmap
import pwndbg.hexdump
import pwndbg.search


class MemNamespace:
    """Memory operations namespace (pwn.mem.*)"""

    @staticmethod
    def read(addr: int, count: int = 0x40, show: bool = False) -> bytearray:
        """Read memory from address.

        Args:
            addr: Address to read from
            count: Number of bytes to read (default: 0x40)
            show: If True, print hexdump instead of returning data

        Returns:
            bytearray of memory contents (if show=False)
        """
        data = pwndbg.aglib.memory.read(addr, count)
        if show:
            for line in pwndbg.hexdump.hexdump(data, address=addr, count=count):
                __builtins__["print"](line)  # type: ignore[index]
            return bytearray()  # Return empty to avoid double output
        return data

    @staticmethod
    def write(addr: int, data: bytes | str) -> None:
        """Write data to memory.

        Args:
            addr: Address to write to
            data: Bytes or string to write
        """
        pwndbg.aglib.memory.write(addr, data)

    @staticmethod
    def hexdump(addr: int, count: int = 0x40) -> None:
        """Print hexdump of memory.

        Args:
            addr: Address to dump
            count: Number of bytes to dump (default: 0x40)
        """
        data = pwndbg.aglib.memory.read(addr, count)
        for line in pwndbg.hexdump.hexdump(data, address=addr, count=count):
            __builtins__["print"](line)  # type: ignore[index]

    @staticmethod
    def search(
        pattern: bytes,
        start: int | None = None,
        end: int | None = None,
        limit: int = 100,
        show: bool = True,
    ) -> list[int]:
        """Search memory for a byte pattern.

        Args:
            pattern: Bytes to search for
            start: Start address (optional)
            end: End address (optional)
            limit: Maximum number of results (default: 100)
            show: If True, print results; if False, return list

        Returns:
            List of addresses where pattern was found
        """
        results = list(pwndbg.search.search(searchfor=pattern, start=start, end=end, limit=limit))

        if show:
            for addr in results:
                __builtins__["print"](f"{addr:#x}")  # type: ignore[index]

        return results


class RegNamespace:
    """Register operations namespace (pwn.reg.*)"""

    @staticmethod
    def get(name: str) -> int | None:
        """Read register value.

        Args:
            name: Register name (e.g. 'rax', 'rip')

        Returns:
            Register value as integer, or None if not available
        """
        return pwndbg.aglib.regs.read_reg(name)

    @staticmethod
    def set(name: str, value: int) -> None:
        """Write register value.

        Args:
            name: Register name (e.g. 'rax', 'rip')
            value: Value to write
        """
        pwndbg.aglib.regs.write_reg(name, value)

    @staticmethod
    def __getattr__(name: str) -> int | None:
        """Allow pwn.reg.rax style access."""
        return pwndbg.aglib.regs.read_reg(name)


class VmNamespace:
    """Virtual memory map namespace (pwn.vm.*)"""

    @staticmethod
    def map(show: bool = True) -> tuple[Any, ...]:
        """Get virtual memory mappings.

        Args:
            show: If True, print formatted vmmap; if False, return raw data

        Returns:
            Tuple of memory pages
        """
        pages = pwndbg.aglib.vmmap.get()

        if show:
            __builtins__["print"]("Address Range          Perms  Size      Offset    File")  # type: ignore[index]
            __builtins__["print"]("-" * 80)  # type: ignore[index]
            for page in pages:
                perms = ""
                perms += "r" if page.read else "-"
                perms += "w" if page.write else "-"
                perms += "x" if page.execute else "-"
                size = page.end - page.start
                offset = f"{page.offset:#x}" if page.offset else "-"
                objfile = page.objfile if page.objfile else ""
                __builtins__["print"](  # type: ignore[index]
                    f"{page.start:#018x}-{page.end:#018x} {perms}  {size:#010x}  {offset:8}  {objfile}"
                )

        return pages


class PwnNamespace:
    """Main namespace for pwndbg IPython helpers (pwn.*)"""

    mem = MemNamespace()
    reg = RegNamespace()
    vm = VmNamespace()


# Create singleton instance
pwn = PwnNamespace()


# Short alias functions
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
    return pwn.mem.read(addr, count, show)


def mw(addr: int, data: bytes | str) -> None:
    """Memory Write - Write data to memory.

    Args:
        addr: Address to write to
        data: Bytes or string to write

    Example:
        mw(0x400000, b"\\x90\\x90")
        mw(0x400000, "hello")
    """
    pwn.mem.write(addr, data)


def hd(addr: int, count: int = 0x40) -> None:
    """HexDump - Print hexdump of memory.

    Args:
        addr: Address to dump
        count: Number of bytes (default: 0x40)

    Example:
        hd(0x400000)
        hd(0x400000, 0x100)
    """
    pwn.mem.hexdump(addr, count)


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
    return pwn.mem.search(pattern, start, end, limit, show)


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
    return pwn.reg.get(name)


def rw(name: str, value: int) -> None:
    """Register Write - Write register value.

    Args:
        name: Register name
        value: Value to write

    Example:
        rw("rax", 0x1234)
    """
    pwn.reg.set(name, value)


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
    return pwn.vm.map(show)


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

NAMESPACE ACCESS:
  pwn.mem.read()    pwn.mem.write()   pwn.mem.hexdump()   pwn.mem.search()
  pwn.reg.get()     pwn.reg.set()
  pwn.vm.map()

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
    __builtins__["print"](help_text)  # type: ignore[index]


def get_ipi_namespace() -> dict[str, Any]:
    """Get dictionary of all helpers to inject into IPython namespace.

    Returns:
        Dictionary mapping names to helper functions/objects
    """
    return {
        "pwn": pwn,
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
    return "Shortcuts: mr, mw, hd, ms, rr, rw, vm | Namespace: pwn.mem/reg/vm | Type aliases() for help"

"""
Command to start an interactive IPython prompt.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager

import gdb

import pwndbg.color.message as M
import pwndbg.commands
import pwndbg.lib.stdio
from pwndbg.commands import CommandCategory


@contextmanager
def switch_to_ipython_env():
    """We need to change stdout/stderr to the default ones, otherwise we can't use tab or autocomplete"""
    # Save GDB's excepthook
    saved_excepthook = sys.excepthook
    # Switch to default stdout/stderr
    with pwndbg.lib.stdio.stdio:
        yield
    # Restore Python's default ps1, ps2, and excepthook for GDB's `pi` command
    sys.ps1 = ">>> "
    sys.ps2 = "... "
    sys.excepthook = saved_excepthook


@pwndbg.commands.Command("Start an interactive IPython prompt.", category=CommandCategory.MISC)
def ipi() -> None:
    with switch_to_ipython_env():
        # Use `gdb.execute` to embed IPython into GDB's variable scope
        try:
            gdb.execute("pi import IPython")
        except gdb.error:
            print(
                M.warn(
                    "Cannot import IPython.\n"
                    "You need to install IPython if you want to use this command.\n"
                    "Maybe you can try `pip install ipython` first."
                )
            )
            return
        code4ipython = """import jedi
import pwn

jedi.Interpreter._allow_descriptor_getattr_default = False

from functools import wraps
from pwndbg.aglib.memory import read, write
import pwndbg.aglib.vmmap as vmmap
from pwndbg.commands.hexdump import hexdump
from pwndbg.commands.search import search


@wraps(read)
def r(addr, length):
    '''
    Wrapper alias for pwndbg.read with input validation.

    Intended for quick memory reads via easy shorthand.

    Args:
        addr (str or int): Memory address as hex string (e.g., '0x4000') or integer.
        length (int): Number of bytes to read.

    Returns:
        bytes: The memory contents, or None if the address is invalid.

    Raises:
        None. Prints error message on invalid addr.
    '''
    try:
        addr_int = int(addr, 16) if isinstance(addr, str) else int(addr)
    except ValueError:
        print(f"Invalid address: {addr!r}. Use hex string or integer.")
        return None
    return read(addr_int, length)


@wraps(write)
def w(addr, data):
    '''
    Wrapper alias for pwndbg.write with input validation.

    Allows writing to memory via shorthand.

    Args:
        addr (str or int): Memory address as a hex string (e.g., '0x4000') or integer.
        data: Data to write (bytes or int depending on context).

    Returns:
        Depends on pwndbg.write, typically number of bytes written or None if invalid.

    Raises:
        None. Invalid address inputs print an error message and return None.
    '''
    try:
        addr_int = int(addr, 16) if isinstance(addr, str) else int(addr)
    except ValueError:
        print(f"Invalid address: {addr!r}. Use hex string or integer.")
        return None
    return write(addr_int, data)


def h(addr, length):
    '''
    Alias for pwndbg's `hexdump` command.
    Displays memory contents in a formatted hexdump view.

    This command reads memory at a specified address (or module name)
    and prints a traditional hexdump with configurable width, grouping,
    and endianness options. It respects global pwndbg configuration
    parameters such as line width, group width, and size limits.

    Args:
        address (int or str): Starting memory address to dump, or a module name.
                              If a module name is given, the first mapped page
                              for that module is used.
                              Defaults to the current stack pointer (`$sp`).
        count (int): Number of bytes to dump. Defaults to the value of
                     `hexdump-bytes` (configurable). May also be interpreted
                     as an end address if larger than the given `address`.

    Returns:
        None. Prints hexdump lines directly.

    Behavior:
        - If `count` exceeds the configured `hexdump-limit-mb`, an error is raised.
        - If `address` exceeds the architecture's maximum pointer value,
          it is truncated to fit.
        - If the same command is repeated (`hexdump.repeat` is set),
          it resumes dumping from the last stored address.
        - Group width defaults to the architecture’s pointer size when set to -1.
        - Endianness within groups is controlled by `hexdump-group-use-big-endian`.

    Raises:
        ValueError: If the requested `count` exceeds the configured maximum limit.
        Prints warnings or errors if the memory cannot be accessed.

    Notes:
        - Results are paged based on pwndbg\'s config options:
          * `hexdump-width`: number of bytes shown per line.
          * `hexdump-group-width`: number of bytes per grouping.
          * `hexdump-group-use-big-endian`: flips group display endianness.
          * `hexdump-limit-mb`: maximum allowed dump size.
        - `hexdump.last_address` and `hexdump.offset` are updated internally
          to support consecutive calls.
    '''
    try:
        addr_int = int(addr, 16) if isinstance(addr, str) else int(addr)
    except ValueError:
        print(f"Invalid address: {addr!r}. Use hex string or integer.")
        return None
    hexdump(addr_int, length)


@wraps(vmmap.get)
def vv():
    '''
    Wrapper alias for pwndbg.vmmap.get.

    Returns the virtual memory map for the current process.

    Returns:
        Typically a list of memory mapping entries as provided by pwndbg.vmmap.get.

    Raises:
        None.
    '''
    return vmmap.get()


def s(
    value,
    type="bytes",
    asmbp=False,
    hex=False,
    executable=False,
    writable=False,
    step=None,
    limit=None,
    aligned=None,
    mapping_name=None,
    save=None,
    next=False,
    trunc_out=False,
):
    '''
    Alias for pwndbg's `search` command.

    Provides a shorthand interface for searching process memory
    for byte sequences, strings, integers, pointers, or assembly
    instructions. This is essentially a passthrough to
    `pwndbg.commands.search.search`, with error handling to avoid
    crashing the REPL when given bad input.

    Args:
        *args: Positional arguments accepted by `pwndbg.commands.search.search`.
               These may include search type, alignment, limits, etc.
        **kwargs: Keyword arguments for finer control. Common examples:
            - type (str): Search target type
                          ('byte', 'word', 'dword', 'qword', 'pointer',
                           'string', 'bytes', 'asm').
            - value (str or int): The value/pattern to search for.
            - mapping_name (str, optional): Restrict search to a named mapping (e.g., 'libc').
            - executable (bool): Limit search to executable segments.
            - writable (bool): Limit search to writable segments.
            - aligned (int): Alignment boundary requirement for results.
            - limit (int): Maximum number of hits before stopping.
            - next (bool): Continue search from previously saved results.
            - save (bool): Save results for later filtering.

    Returns:
        None. Prints results directly, in the same way as `pwndbg search`.

    Raises:
        None. Any exception is caught and reported as an error message.
    '''
    try:
        return search(
            type=type,
            asmbp=asmbp,
            hex=hex,
            executable=executable,
            writable=writable,
            step=step,
            limit=limit,
            aligned=aligned,
            value=value,
            mapping_name=mapping_name,
            save=save,
            next=next,
            trunc_out=trunc_out,
        )
    except Exception as e:
        print(f"Search Error: {e!r}")
        return None


IPython.embed(
    colors="neutral",
    banner1="",
    confirm_exit=False,
    simple_prompt=False,
    user_ns=globals(),
)
"""
        print(M.hint("Shortcuts: r(), w(), vv(), h(), s()"))
        gdb.execute(f"py\n{code4ipython}")

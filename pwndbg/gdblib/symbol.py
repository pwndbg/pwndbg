"""
Looking up addresses for function names / symbols, and
vice-versa.

Uses IDA when available if there isn't sufficient symbol
information available.
"""
import re
from typing import Optional

import gdb

import pwndbg.gdblib.android
import pwndbg.gdblib.arch
import pwndbg.gdblib.elf
import pwndbg.gdblib.events
import pwndbg.gdblib.file
import pwndbg.gdblib.info
import pwndbg.gdblib.memory
import pwndbg.gdblib.qemu
import pwndbg.gdblib.remote
import pwndbg.gdblib.stack
import pwndbg.gdblib.vmmap
import pwndbg.ida
import pwndbg.lib.cache


def _get_debug_file_directory():
    """
    Retrieve the debug file directory path.

    The debug file directory path ('show debug-file-directory') is a comma-
    separated list of directories which GDB will look in to find the binaries
    currently loaded.
    """
    result = gdb.execute("show debug-file-directory", to_string=True, from_tty=False)
    expr = r'The directory where separate debug symbols are searched for is "(.*)".\n'

    match = re.search(expr, result)

    if match:
        return match.group(1)
    return ""


def _set_debug_file_directory(d) -> None:
    gdb.execute(f"set debug-file-directory {d}", to_string=True, from_tty=False)


def _add_debug_file_directory(d) -> None:
    current = _get_debug_file_directory()
    if current:
        _set_debug_file_directory(f"{current}:{d}")
    else:
        _set_debug_file_directory(d)


if "/usr/lib/debug" not in _get_debug_file_directory():
    _add_debug_file_directory("/usr/lib/debug")


@pwndbg.lib.cache.cache_until("objfile")
def get(address: int, gdb_only=False) -> str:
    """
    Retrieve the name for the symbol located at `address` - either from GDB or from IDA sync
    Passing `gdb_only=True`
    """
    # Note: we do not return "" on `address < pwndbg.gdblib.memory.MMAP_MIN_ADDR`
    # because this may be used to find out the symbol name on PIE binaries that weren't started yet
    # and then their symbol addresses can be found by GDB on their (non-rebased) offsets

    # Fast path: GDB's `info symbol` returns 'Numeric constant too large' here
    if address >= ((1 << 64) - 1):
        return ""

    # This sucks, but there's not a GDB API for this.
    result = gdb.execute("info symbol %#x" % int(address), to_string=True, from_tty=False)

    if not gdb_only and result.startswith("No symbol"):
        address = int(address)
        exe = pwndbg.gdblib.elf.exe()
        if exe:
            exe_map = pwndbg.gdblib.vmmap.find(exe.address)
            if exe_map and address in exe_map:
                res = pwndbg.ida.Name(address) or pwndbg.ida.GetFuncOffset(address)
                return res or ""

    # If there are newlines, which means that there are multiple symbols for the address
    # then use the first one (see also #1610)
    result = result[: result.index("\n")]

    # See https://github.com/bminor/binutils-gdb/blob/d1702fea87aa62dff7de465464097dba63cc8c0f/gdb/printcmd.c#L1594-L1624
    # The most often encountered formats looks like this:
    #   "main in section .text of /bin/bash"
    #   "main + 3 in section .text of /bin/bash"
    #   "system + 1 in section .text of /lib/x86_64-linux-gnu/libc.so.6"
    #   "No symbol matches system-1"
    # But there are some others that we have to account for as well
    if " in section " in result:
        loc_string, _ = result.split(" in section ")
    elif " in load address range of " in result:
        loc_string, _ = result.split(" in load address range of ")
    elif " overlay section " in result:
        result, _ = result.split(" overlay section ")
        loc_string, _ = result.split(" in ")
    else:
        loc_string = ""

    # If there is 'main + 87' we want to replace it with 'main+87' etc.
    return loc_string.replace(" + ", "+")


@pwndbg.lib.cache.cache_until("objfile")
def address(symbol: str) -> int:
    """
    Get the address for `symbol`
    """
    try:
        symbol_obj = gdb.lookup_symbol(symbol)[0]
        if symbol_obj:
            return int(symbol_obj.value().address)
    except gdb.error as e:
        # Symbol lookup only throws exceptions on errors, not if it failed to
        # lookup a symbol. We want to raise these errors so we can handle them
        # properly, but there are some we haven't figured out how to fix yet, so
        # we ignore those here
        skipped_exceptions = []

        # This is exception is being thrown by the Go typeinfo tests, we should
        # investigate why this is happening and see if we can explicitly check
        # for it with `gdb.selected_frame()`
        skipped_exceptions.append("No frame selected")

        # If we try to look up a TLS variable when there is no TLS, this
        # exception occurs. Ideally we should come up with a way to check for
        # this case before calling `gdb.lookup_symbol`
        skipped_exceptions.append("Cannot find thread-local")

        if all(x not in str(e) for x in skipped_exceptions):
            raise e

    try:
        # Unfortunately, `gdb.lookup_symbol` does not seem to handle all
        # symbols, so we need to fallback to using `info address`. See
        # https://sourceware.org/pipermail/gdb/2022-October/050362.html
        address = pwndbg.gdblib.info.address(symbol)
        if address is None or not pwndbg.gdblib.vmmap.find(address):
            return None

        return address

    except gdb.error:
        return None

    try:
        # TODO: We should properly check if we have a connection to the IDA server first
        address = pwndbg.ida.LocByName(symbol)
        if address:
            return address
    except Exception:
        pass

    return None


@pwndbg.lib.cache.cache_until("objfile", "thread")
def static_linkage_symbol_address(symbol: str) -> int:
    """
    Get the address for static linkage `symbol`
    """

    try:
        if hasattr(gdb, "lookup_static_symbol"):
            symbol_obj = gdb.lookup_static_symbol(symbol)
        else:
            # GDB < 9.x does not have `gdb.lookup_static_symbol`
            # We will fallback to `gdb.lookup_symbol` here, but the drawback is that we might find incorrect symbol if there is a symbol with the same name which is not static linkage
            # But this is better than just returning None
            # TODO/FIXME: Find a way to get the static linkage symbol's address in GDB < 9.x
            symbol_obj = gdb.lookup_symbol(symbol)[0]
        return int(symbol_obj.value().address) if symbol_obj else None
    except gdb.error:
        return None


@pwndbg.lib.cache.cache_until("stop", "start")
def selected_frame_source_absolute_filename():
    """
    Retrieve the symbol table’s source absolute file name from the selected frame.

    In case of missing symbol table or frame information, None is returned.
    """
    try:
        frame = gdb.selected_frame()
    except gdb.error:
        return None

    if not frame:
        return None

    sal = frame.find_sal()
    if not sal:
        return None

    symtab = sal.symtab
    if not symtab:
        return None

    return symtab.fullname()


def parse_and_eval(expression: str) -> Optional[gdb.Value]:
    """Error handling wrapper for GDBs parse_and_eval function"""
    try:
        return gdb.parse_and_eval(expression)
    except gdb.error:
        return None

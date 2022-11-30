"""
Looking up addresses for function names / symbols, and
vice-versa.

Uses IDA when available if there isn't sufficient symbol
information available.
"""
import os
import re

import elftools.common.exceptions
import elftools.elf.constants
import elftools.elf.elffile
import elftools.elf.segments
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
import pwndbg.lib.memoize


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


def _set_debug_file_directory(d):
    gdb.execute("set debug-file-directory %s" % d, to_string=True, from_tty=False)


def _add_debug_file_directory(d):
    current = _get_debug_file_directory()
    if current:
        _set_debug_file_directory("%s:%s" % (current, d))
    else:
        _set_debug_file_directory(d)


if "/usr/lib/debug" not in _get_debug_file_directory():
    _add_debug_file_directory("/usr/lib/debug")


_remote_files = {}


@pwndbg.gdblib.events.exit
def _reset_remote_files():
    global _remote_files
    _remote_files = {}


@pwndbg.gdblib.events.new_objfile
def _autofetch():
    """
    Automatically downloads ELF files with debug symbols from the remotely debugged system.
    Does not work with QEMU and Android. It also does not work when debugging embedded devices, as they don't even have a filesystem.
    """
    if not pwndbg.gdblib.remote.is_remote():
        return

    if pwndbg.gdblib.remote.is_debug_probe():
        return

    if pwndbg.gdblib.qemu.is_qemu_usermode():
        return

    if pwndbg.gdblib.android.is_android():
        return

    remote_files_dir = pwndbg.gdblib.file.remote_files_dir()
    if remote_files_dir not in _get_debug_file_directory().split(":"):
        _add_debug_file_directory(remote_files_dir)

    for mapping in pwndbg.gdblib.vmmap.get():
        objfile = mapping.objfile

        # Don't attempt to download things like '[stack]' and '[heap]'
        if not objfile.startswith("/"):
            continue

        # Don't re-download things that we have already downloaded
        if not objfile or objfile in _remote_files:
            continue

        msg = "Downloading %r from the remote server" % objfile
        print(msg, end="")

        try:
            data = pwndbg.gdblib.file.get(objfile)
            print("\r" + msg + ": OK")
        except OSError:
            # The file could not be downloaded :(
            print("\r" + msg + ": Failed")
            return

        filename = os.path.basename(objfile)
        local_path = os.path.join(remote_files_dir, filename)

        with open(local_path, "wb+") as f:
            f.write(data)

        _remote_files[objfile] = local_path

        base = None
        for mapping in pwndbg.gdblib.vmmap.get():
            if mapping.objfile != objfile:
                continue

            if base is None or mapping.vaddr < base.vaddr:
                base = mapping

        if not base:
            continue

        base = base.vaddr

        try:
            elf = elftools.elf.elffile.ELFFile(open(local_path, "rb"))
        except elftools.common.exceptions.ELFError:
            continue

        gdb_command = ["add-symbol-file", local_path, hex(int(base))]
        for section in elf.iter_sections():
            name = section.name  # .decode('latin-1')
            section = section.header
            if not section.sh_flags & elftools.elf.constants.SH_FLAGS.SHF_ALLOC:
                continue
            gdb_command += ["-s", name, hex(int(base + section.sh_addr))]

        print(" ".join(gdb_command))
        # gdb.execute(' '.join(gdb_command), from_tty=False, to_string=True)


@pwndbg.lib.memoize.reset_on_objfile
def get(address: int, gdb_only=False) -> str:
    """
    Retrieve the name for the symbol located at `address`
    """
    # Fast path
    if address < pwndbg.gdblib.memory.MMAP_MIN_ADDR or address >= ((1 << 64) - 1):
        return ""

    # Don't look up stack addresses
    if pwndbg.gdblib.stack.find(address):
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

    # Expected format looks like this:
    # main in section .text of /bin/bash
    # main + 3 in section .text of /bin/bash
    # system + 1 in section .text of /lib/x86_64-linux-gnu/libc.so.6
    # No symbol matches system-1.
    a, b, c, _ = result.split(None, 3)

    if b == "+":
        return "%s+%s" % (a, c)
    if b == "in":
        return a

    return ""


@pwndbg.lib.memoize.reset_on_objfile
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


@pwndbg.lib.memoize.reset_on_objfile
@pwndbg.lib.memoize.reset_on_thread
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


@pwndbg.gdblib.events.stop
@pwndbg.lib.memoize.reset_on_start
def _add_main_exe_to_symbols():
    if not pwndbg.gdblib.remote.is_remote():
        return

    if pwndbg.gdblib.android.is_android():
        return

    exe = pwndbg.gdblib.elf.exe()

    if not exe:
        return

    addr = exe.address

    if not addr:
        return

    addr = int(addr)

    mmap = pwndbg.gdblib.vmmap.find(addr)
    if not mmap:
        return

    path = mmap.objfile
    if path and (pwndbg.gdblib.arch.endian == pwndbg.gdblib.arch.native_endian):
        try:
            gdb.execute("add-symbol-file %s" % (path,), from_tty=False, to_string=True)
        except gdb.error:
            pass


@pwndbg.lib.memoize.reset_on_stop
@pwndbg.lib.memoize.reset_on_start
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

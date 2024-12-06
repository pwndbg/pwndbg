"""
Looking up addresses for function names / symbols, and
vice-versa.
"""

from __future__ import annotations

import gdb

from pwndbg.gdblib import gdb_version

# Symbol lookup only throws exceptions on errors, not if it failed to
# look up a symbol. We want to raise these errors so we can handle them
# properly, but there are some we haven't figured out how to fix yet, so
# we ignore those here
skipped_exceptions = (
    # This exception is being thrown by the Go typeinfo tests, we should
    # investigate why this is happening and see if we can explicitly check
    # for it with `gdb.selected_frame()`
    "No frame selected",
    # If we try to look up a TLS variable when there is no TLS, this
    # exception occurs. Ideally we should come up with a way to check for
    # this case before calling `gdb.lookup_symbol`
    "Cannot find thread-local",
)


# TODO: implement in aglib
# address = int(address)
# return pwndbg.integration.provider.get_symbol(address) or ""


def address_to_name(address: int) -> str:
    """
    Retrieve the name for the symbol located at `address`
    Empty string if no symbol
    """
    # We could rewrite this function with gdb.Value+cast:
    #
    # In [17]: hex(gdb.parse_and_eval('&\'malloc\''))
    # Out[17]: '0xf8f7b18065d0'
    #
    # In [18]: str(gdb.Value(0xf8f7b18065d0).cast(gdb.lookup_type("void").pointer()))
    # Out[18]: '0xf8f7b18065d0 <__GI___libc_malloc>'
    #
    # pwndbg> info symbol 0xf8f7b18065d0
    # malloc in section .text of /lib/aarch64-linux-gnu/libc.so.6
    #
    # In [19]: str(gdb.Value(0xf8f7b18065d0+0x15).cast(gdb.lookup_type("void").pointer()))
    # Out[20]: '0xf8f7b18065e5 <__GI___libc_malloc+21>'

    # Note: we do not return "" on `address < pwndbg.aglib.memory.MMAP_MIN_ADDR`
    # because this may be used to find out the symbol name on PIE binaries that weren't started yet
    # and then their symbol addresses can be found by GDB on their (non-rebased) offsets

    # Fast path: GDB's `info symbol` returns 'Numeric constant too large' here
    if address >= ((1 << 64) - 1):
        return ""

    # This sucks, but there's not a GDB API for this.
    # Workaround for a bug with Rust language, see #2094
    try:
        result = gdb.execute(f"info symbol 0x{address:x}", to_string=True, from_tty=False)
    except gdb.error:
        return ""

    if result.startswith("No symbol"):
        return ""

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


def symbol_to_address(
    name: str,
    global_only: bool = False,
    static_only: bool = False,
    domain: int = gdb.SYMBOL_VAR_DOMAIN,
) -> int | None:
    """
    Get the address for `symbol`

    gdb.SYMBOL_VAR_DOMAIN search:
    - variables
    - function names
    - typedef names
    - enum type values
    """

    assert (
        static_only is True and global_only is False
    ), "gdb don't support searching static variables in non global"

    if global_only:
        if static_only:
            if val := _any_global_static_symbol_to_address(name, domain):
                return val
        else:
            if val := _any_global_symbol_to_address(name, domain):
                return val
    else:
        if val := _any_symbol_to_address(name, domain):
            return val

    # fallback, because of bug in gdb for some symbols eg: malloc / __GI___libc_malloc
    return _fallback_any_symbol_to_address(name, global_only)


def _any_global_static_symbol_to_address(name: str, domain: int) -> gdb.Value | None:
    try:
        # gdb.lookup_symbol Search order:
        # - global static in your module
        # - global static in other module
        symbol_obj = gdb.lookup_static_symbol(name, domain=domain)
        if symbol_obj:
            return symbol_obj.value()
    except gdb.error:
        pass
    return None


def _any_global_symbol_to_address(name: str, domain: int) -> gdb.Value | None:
    try:
        # gdb.lookup_symbol Search order:
        # - global in your module
        # - global in other module
        symbol_obj = gdb.lookup_global_symbol(name, domain=domain)
        if symbol_obj:
            return symbol_obj.value()
    except gdb.error:
        pass
    return None


def _any_symbol_to_address(name: str, domain: int) -> gdb.Value | None:
    try:
        # gdb.lookup_symbol Search order:
        # - local scope
        # - global in your module
        # - global static in your module
        # - global in other module
        # - global static in other module
        symbol_obj, _ = gdb.lookup_symbol(name, domain=domain)
        if symbol_obj:
            frame = None
            if symbol_obj.needs_frame:
                frame = gdb.selected_frame()
            return symbol_obj.value(frame)
    except gdb.error as e:
        if all(x not in str(e) for x in skipped_exceptions):
            raise e
    return None


def _fallback_any_symbol_to_address(name: str, global_only: bool = False) -> gdb.Value | None:
    try:
        # Unfortunately, `gdb.lookup_symbol` does not seem to handle all
        # symbols, so we need to fallback to using `gdb.parse_and_eval`. See
        # https://sourceware.org/pipermail/gdb/2022-October/050362.html
        # (We tried parsing the output of the `info address` before, but there were some issues. See #1628 and #1666)
        if "\\" in name:
            # Is it possible that happens? Probably not, but just in case
            raise ValueError(f"Symbol {name!r} contains a backslash")
        sanitized_symbol_name = name.replace("'", "\\'")

        # gdb.parse_and_eval Search order:
        # - local scope
        # - global in your module
        # - global static in your module
        # - global in other module
        # - global static in other module

        # global_context is only supported in GDB14+
        if gdb_version[0] >= 14:
            return gdb.parse_and_eval(f"&'{sanitized_symbol_name}'", global_context=global_only)

        return gdb.parse_and_eval(f"&'{sanitized_symbol_name}'")
    except gdb.error:
        return None

"""
Looking up addresses for function names / symbols, and
vice-versa.
"""

from __future__ import annotations

from enum import Enum

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


def resolve_addr(address: int) -> str:
    """
    Retrieve the name for the symbol located at `address`
    Empty string if no symbol
    """
    # We could rewrite this function with gdb.Value+cast:
    # Or with `maint print msymbols`
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


def _global_static_symbol_to_address(
    obj: gdb.Objfile | None, name: str, domain: Domain
) -> gdb.Value | None:
    try:
        # gdb.lookup_static_symbol Search order:
        # - global static in your module
        # - global static in other module
        symbol_obj = (obj or gdb).lookup_static_symbol(name, domain=DOMAIN_MAPPING[domain])
        if symbol_obj and domain.validate(symbol_obj):
            return symbol_obj.value().address
    except gdb.error:
        pass
    return None


def _global_exported_symbol_to_address(
    obj: gdb.Objfile | None, name: str, domain: Domain
) -> gdb.Value | None:
    try:
        # gdb.lookup_global_symbol Search order:
        # - global in your module
        # - global in other module
        symbol_obj = (obj or gdb).lookup_global_symbol(name, domain=DOMAIN_MAPPING[domain])
        if symbol_obj and domain.validate(symbol_obj):
            return symbol_obj.value().address
    except gdb.error:
        pass
    return None


def _frame_any_symbol_to_address(name: str, domain: Domain) -> gdb.Value | None:
    try:
        # gdb.lookup_symbol Search order:
        # - local scope
        # - global in your module
        # - global static in your module
        # - global in other module
        # - global static in other module
        symbol_obj, _ = gdb.lookup_symbol(name, domain=DOMAIN_MAPPING[domain])
        if symbol_obj and domain.validate(symbol_obj):
            if symbol_obj.needs_frame:
                return symbol_obj.value(gdb.selected_frame()).address
            return symbol_obj.value().address
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
            return gdb.parse_and_eval(f"&'{sanitized_symbol_name}'", global_context=global_only)  # type: ignore[call-arg]

        return gdb.parse_and_eval(f"&'{sanitized_symbol_name}'")
    except gdb.error:
        return None


class Domain(Enum):
    ANY = 1
    VARIABLE = 2
    FUNCTION = 3

    def validate(self, sym: gdb.Symbol) -> bool:
        if self == Domain.FUNCTION and gdb_version[0] < 15:
            return sym.is_function

        elif self == Domain.VARIABLE:
            # For 'VARIABLE' we need manually filter out
            # We have to check for `is_function`, because TLS variables will return False in `is_variable`
            if sym.is_function:
                return False
        return True


# SYMBOL_FUNCTION_DOMAIN is supported since GDB15+
if gdb_version[0] < 15:
    gdb.SYMBOL_FUNCTION_DOMAIN = gdb.SYMBOL_VAR_DOMAIN  # type: ignore[attr-defined]

DOMAIN_MAPPING = {
    # Gdb supported types:
    # https://github.com/bminor/binutils-gdb/blob/e998ba604f8b1498c8ad43f2c19fee097b6131ef/gdb/sym-domains.def
    Domain.ANY: gdb.SYMBOL_VAR_DOMAIN,
    # gdb.SYMBOL_VAR_DOMAIN search (due to historical reasons in GDB) includes:
    # - variables
    # - function names
    # - typedef names (!sic, this is not symbol)
    # - enum type values (!sic, this is not symbol)
    # Note: This queries SYMBOL_VAR_DOMAIN, SYMBOL_TYPE_DOMAIN, and SYMBOL_FUNCTION_DOMAIN.
    Domain.VARIABLE: gdb.SYMBOL_VAR_DOMAIN,
    # Specifically for variables. Requires manual filtering to exclude other types.
    Domain.FUNCTION: gdb.SYMBOL_FUNCTION_DOMAIN,  # type: ignore[attr-defined]
    # Specifically for functions.
}

order_prefs = {
    True: (_global_static_symbol_to_address, _global_exported_symbol_to_address),
    False: (_global_exported_symbol_to_address, _global_static_symbol_to_address),
}


def lookup_symbol(
    name: str,
    *,
    prefer_static: bool = False,
    domain: Domain = Domain.ANY,
    objfile_endswith: str | None = None,
) -> gdb.Value | None:
    """
    Get the address for `symbol`
    """

    objfile: gdb.Objfile | None = None
    if objfile_endswith is not None:
        for obj in gdb.selected_inferior().progspace.objfiles():
            if obj.filename.endswith(objfile_endswith):
                objfile = obj
                break
        if objfile is None:
            raise gdb.GdbError(f"Objfile '{objfile_endswith}' not found")

    for func in order_prefs[prefer_static]:
        if (val := func(objfile, name, domain)) is not None:
            return val

    # FIXME: Due to a bug in GDB, some symbols (e.g., malloc / __GI___libc_malloc)
    #   may return WRONG-ADDRESS when queried.
    #   For more details, see: https://github.com/pwndbg/pwndbg/issues/2613
    #   Can be fixed by using GdbMinimalSymbols: `maint print msymbols`
    return _fallback_any_symbol_to_address(name, global_only=True)


def lookup_frame_symbol(
    name: str,
    *,
    domain: Domain = Domain.ANY,
) -> gdb.Value | None:
    """
    Get the address for local `symbol` from frame, in most time you don't need it
    """

    if (val := _frame_any_symbol_to_address(name, domain)) is not None:
        return val

    # fallback, because of bug in gdb for some symbols eg: malloc / __GI___libc_malloc
    return _fallback_any_symbol_to_address(name, global_only=False)

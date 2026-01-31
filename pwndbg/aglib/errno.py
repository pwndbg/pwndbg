from __future__ import annotations

import pwndbg
import pwndbg.aglib
import pwndbg.aglib.symbol
import pwndbg.dbg_mod
import pwndbg.libc


def get() -> tuple[int, str]:
    """
    Gets the integer errno value.

    Returns:
        (errno, err_str): If err_str is "", errno is returned as an integer.
        Otherwise, the errno value could not be returned and err_str contains
        the error message.
    """
    # errno is a thread local variable provided by the libc, so we ask the libc where it is.
    # We intentionally avoid expression evaluation because it is not available in corefiles (see #3672).

    # NOTE: Maybe this should be moved to pwndbg.libc

    # The definition of errno in glibc is like this:
    # # define errno (*__errno_location ())
    # https://elixir.bootlin.com/glibc/glibc-2.41/source/stdlib/errno.h#L38
    # int *
    # __errno_location (void)
    # {
    #     return &errno;
    # }
    # https://elixir.bootlin.com/glibc/glibc-2.41/source/csu/errno-loc.c#L24
    # #   define errno __libc_errno
    # https://elixir.bootlin.com/glibc/glibc-2.41/source/include/errno.h#L27
    # extern __thread int __libc_errno __attribute__ ((alias ("errno")))
    # https://elixir.bootlin.com/glibc/glibc-2.41/source/csu/errno.c#L32
    # In glibc, errno is always available as a thread local variable (it is an exported/dynamic
    # symbol).

    # The definition of errno in musl is like this:
    # #define errno (*__errno_location())
    # https://elixir.bootlin.com/musl/v1.2.5/source/include/errno.h#L16
    # int *__errno_location(void)
    # {
    # 	return &__pthread_self()->errno_val;
    # }
    # https://elixir.bootlin.com/musl/v1.2.5/source/src/errno/__errno_location.c#L4
    # In musl, there is no errno symbol, but __errno_location() is an exported/dynamic
    # function symbol.

    err_str: str = ""
    try:
        maybe_errno: int | None = pwndbg.aglib.symbol.lookup_symbol_value(
            "errno",
            type=pwndbg.dbg_mod.SymbolLookupType.VARIABLE,
            objfile_endswith=str(pwndbg.libc.filepath()),
        )
        if maybe_errno is not None:
            return maybe_errno, ""

        err_str = "TLS variable `errno` not found in the libc symbol table."
    except pwndbg.dbg_mod.Error as e:
        err_str = str(e)

    # We don't really need to do this, but we do it for a better diagnostic.
    errno_location: pwndbg.dbg_mod.Value | None = pwndbg.aglib.symbol.lookup_symbol(
        "__errno_location",
        type=pwndbg.dbg_mod.SymbolLookupType.FUNCTION,
        objfile_endswith=str(pwndbg.libc.filepath()),
    )
    if errno_location is None:
        err_str += "\nFunction `__errno_location` not found in the libc mapping."
        return -1, err_str

    # If we are a corefile we cannot execute expressions.
    if pwndbg.dbg.selected_inferior().is_core_file():
        err_str += (
            "\nFunction `__errno_location` found, but we cannot execute it as the target is a\n"
        )
        err_str += "corefile. You may look at the assembly `x/10i __errno_location` and figure out the TLS\n"
        err_str += "offset manually. Then `x/wx $fs_base + offset`."
        return -1, err_str

    # Try executing __errno_location().
    frame = pwndbg.dbg.selected_frame()
    try:
        if frame is not None:
            return int(
                frame.evaluate_expression(
                    "*((int *(*) (void)) __errno_location) ()", lock_scheduler=True
                )
            ), ""
        return int(
            pwndbg.dbg.selected_inferior().evaluate_expression(
                "*((int *(*) (void)) __errno_location) ()"
            )
        ), ""
    except pwndbg.dbg_mod.Error as e:
        err_str += f"\nFailed executing __errno_location(): {e}"
        return -1, err_str

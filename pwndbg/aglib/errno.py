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

    # The definition of errno in musl is like this:
    # #define errno (*__errno_location())
    # https://elixir.bootlin.com/musl/v1.2.5/source/include/errno.h#L16
    # int *__errno_location(void)
    # {
    # 	return &__pthread_self()->errno_val;
    # }
    # https://elixir.bootlin.com/musl/v1.2.5/source/src/errno/__errno_location.c#L4


    try:
        maybe_errno: int | None = pwndbg.aglib.symbol.lookup_symbol_value(
            "errno", objfile_endswith=str(pwndbg.libc.filepath())
        )
        if maybe_errno is None:
            return -1, "Libc does not contain the errno symbol?"
        return maybe_errno, ""
    except pwndbg.dbg_mod.Error as e:
        return -1, str(e)

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
    try:
        maybe_errno: int | None = pwndbg.aglib.symbol.lookup_symbol_value(
            "errno", objfile_endswith=str(pwndbg.libc.filepath())
        )
        if maybe_errno is None:
            return -1, "Libc does not contain the errno symbol?"
        return maybe_errno, ""
    except pwndbg.dbg_mod.Error as e:
        return -1, str(e)

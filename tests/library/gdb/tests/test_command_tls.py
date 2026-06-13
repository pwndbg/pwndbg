from __future__ import annotations

from collections.abc import Callable

import gdb

from . import get_binary

# TLS binary already has the break_here function and reads fsbase into tls_address
TLS_BINARY = get_binary("tls.x86-64.out")


def test_tls_region_labeled_in_vmmap(start_binary: Callable[[str], None]) -> None:
    start_binary(TLS_BINARY)

    # break_here is called after fsbase is read, TLS is fully initialized at this point
    gdb.execute("break break_here")
    gdb.execute("run")

    vmmap_output = gdb.execute("vmmap", to_string=True)

    # the TLS region should now show as [tls] instead of [anon_...]
    assert "[tls]" in vmmap_output

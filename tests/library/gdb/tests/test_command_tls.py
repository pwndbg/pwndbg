from __future__ import annotations

import gdb

from . import get_binary

TLS_BINARY = get_binary("tls.x86-64.out")


def test_tls_region_labeled_in_vmmap(start_binary):  # type: ignore[no-untyped-def]
    start_binary(TLS_BINARY)

    gdb.execute("break break_here")
    gdb.execute("run")

    vmmap_output = gdb.execute("vmmap", to_string=True)

    assert "[tls]" in vmmap_output

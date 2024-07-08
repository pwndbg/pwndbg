from __future__ import annotations

import gdb
import user

import pwndbg.gdblib.symbol

REFERENCE_BINARY = user.binaries.get("reference-binary.aarch64.out")


def test_aarch64_reference(qemu_start_binary):
    qemu_start_binary(REFERENCE_BINARY, "aarch64")
    gdb.execute("break break_here")
    assert pwndbg.gdblib.symbol.address("main") is not None
    gdb.execute("continue")

    gdb.execute("argv", to_string=True)
    assert gdb.execute("argc", to_string=True).strip() == "1"
    gdb.execute("auxv", to_string=True)
    assert (
        gdb.execute("cpsr", to_string=True, from_tty=False).strip()
        == "cpsr 0x60000000 [ n Z C v q pan il d a i f el:0 sp ]"
    )
    gdb.execute("context", to_string=True)
    gdb.execute("hexdump", to_string=True)
    gdb.execute("telescope", to_string=True)

    # TODO: Broken
    gdb.execute("retaddr", to_string=True)

    # Broken
    gdb.execute("procinfo", to_string=True)

    # Broken
    gdb.execute("vmmap", to_string=True)

    gdb.execute("piebase", to_string=True)

    gdb.execute("nextret", to_string=True)

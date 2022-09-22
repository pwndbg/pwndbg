import gdb

import pwndbg.gdblib.regs
import tests

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")


def test_command_nextproginstr_binary_not_running():
    out = gdb.execute("nextproginstr", to_string=True)
    assert out == "nextproginstr: The program is not being run.\n"


def test_command_nextproginstr(start_binary):
    start_binary(REFERENCE_BINARY)

    gdb.execute("break main")
    gdb.execute("continue")

    out = gdb.execute("nextproginstr", to_string=True)
    assert out == "The pc is already at the binary objfile code. Not stepping.\n"

    # Sanity check
    exec_bin_pages = [p for p in pwndbg.vmmap.get() if p.objfile == pwndbg.proc.exe and p.execute]
    assert any(pwndbg.gdblib.regs.pc in p for p in exec_bin_pages)
    main_page = pwndbg.vmmap.find(pwndbg.gdblib.regs.pc)

    gdb.execute("break puts")
    gdb.execute("continue")

    # Sanity check that we are in libc
    libc = "libc.so.6"
    assert pwndbg.vmmap.find(pwndbg.gdblib.regs.rip).objfile.endswith(libc)

    # Execute nextproginstr and see if we came back to the same vmmap page
    gdb.execute("nextproginstr")
    assert pwndbg.gdblib.regs.pc in main_page

    # Ensure that nextproginstr won't jump now
    out = gdb.execute("nextproginstr", to_string=True)
    assert out == "The pc is already at the binary objfile code. Not stepping.\n"

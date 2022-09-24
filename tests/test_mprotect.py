import gdb

import pwndbg
import tests

MPROTECT_BINARY = tests.binaries.get("mprotect.out")


def test_mprotect(start_binary):
    """
    Tests mprotect command
    It will mark some memory as executable, then this binary will print "mprotect_ok"
    """
    start_binary(MPROTECT_BINARY)

    gdb.execute("starti")
    # get addr of func
    addr = int(gdb.parse_and_eval("&func"))
    addr_aligned = pwndbg.lib.memory.page_align(addr)

    # sizeof
    size = int(gdb.parse_and_eval("sizeof(func)"))
    size_aligned = pwndbg.lib.memory.page_align(size)

    vmmaps_before = gdb.execute("vmmap -x", to_string=True).splitlines()

    # mark memory as executable
    gdb.execute(
        "mprotect {} {} PROT_EXEC|PROT_READ|PROT_WRITE".format(
            hex(addr_aligned), pwndbg.lib.memory.PAGE_SIZE
        )
    )

    vmmaps_after = gdb.execute("vmmap -x", to_string=True).splitlines()

    # expect vmmaps_after to be one element longer than vmmaps_before
    assert len(vmmaps_after) == len(vmmaps_before) + 1

    # get the changed vmmap entry
    vmmap_entry = [x for x in vmmaps_after if x not in vmmaps_before][0]

    assert vmmap_entry.split()[2] == "rwxp"

    # continue execution
    gdb.execute("continue")


def test_cannot_run_mprotect_when_not_running(start_binary):

    # expect error message
    assert "mprotect: The program is not being run.\n" == gdb.execute(
        "mprotect 0x0 0x1000 PROT_EXEC|PROT_READ|PROT_WRITE", to_string=True
    )

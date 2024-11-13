from __future__ import annotations

import gdb

import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.vmmap
import pwndbg.lib.memory
import tests

USE_FDS_BINARY = tests.binaries.get("use-fds.out")


def test_mmap_executes_properly(start_binary):
    """
    Tests the mmap command
    """
    start_binary(USE_FDS_BINARY)

    page_size = pwndbg.lib.memory.PAGE_SIZE

    # Checks for an mmap(2) error.
    #
    # mmap(2) is documented to only return a (void*) -1 on failure, but we are a
    # little stricter and consider any value on the last page to be a mapping
    # error. While technically we don't need to do this, we make the assumption
    # that any mapping landing in the last page during a test should warrant
    # manual investigation.
    def is_mmap_error(ptr):
        err = ((1 << pwndbg.aglib.arch.ptrsize) - 1) & pwndbg.lib.memory.PAGE_MASK
        return ptr & pwndbg.lib.memory.PAGE_MASK == err

    # Checks whether permissions match.
    def has_correct_perms(ptr, perm):
        page = pwndbg.aglib.vmmap.find(ptr)
        return (
            not (page.read ^ ("r" in perm))
            and not (page.write ^ ("w" in perm))
            and not (page.execute ^ ("x" in perm))
        )

    # Check basic private+anonymous page mmap.
    output = gdb.execute(f"mmap 0x0 {page_size}", to_string=True)
    assert output.startswith("mmap syscall returned ")
    ptr = int(output.split(" returned ")[1].rstrip(), 16)
    assert not is_mmap_error(ptr)
    assert has_correct_perms(ptr, "rwx")

    # Check basic fixed mapping.
    base_addr = 0xDEADBEEF & pwndbg.lib.memory.PAGE_MASK
    while True:
        page = pwndbg.aglib.vmmap.find(base_addr)
        if page is None:
            break
        base_addr = page.end
    output = gdb.execute(
        f"mmap {base_addr:#x} {page_size} 7 MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE", to_string=True
    )
    assert output.startswith("mmap syscall returned ")
    ptr = int(output.split(" returned ")[1].rstrip(), 16)
    assert not is_mmap_error(ptr)
    assert has_correct_perms(ptr, "rwx")
    assert ptr == base_addr

    # Continue the program until just before close(2) is called.
    gdb.execute("break use-fds.c:16")
    gdb.execute("continue")

    # Retrieve the file descriptor number and map it to memory.
    fd_num = int(gdb.newest_frame().read_var("fd"))
    output = gdb.execute(f"mmap 0x0 16 PROT_READ MAP_PRIVATE {fd_num} 0", to_string=True)
    assert output.startswith("mmap syscall returned ")
    ptr = int(output.split(" returned ")[1].rstrip(), 16)
    assert not is_mmap_error(ptr)
    assert has_correct_perms(ptr, "r")

    # Load the 16 bytes read in by the read() call in the program, as well as
    # the first 16 bytes present in our newly created memory map, and compare
    # them.
    data_ptr = int(gdb.newest_frame().read_var("buf").address)
    data_local = pwndbg.aglib.memory.read(data_ptr, 16)
    data_mapped = pwndbg.aglib.memory.read(ptr, 16)
    assert data_local == data_mapped


def test_cannot_run_mmap_when_not_running(start_binary):
    # expect error message
    assert "mmap: The program is not being run.\n" == gdb.execute("mmap 0x0 0x1000", to_string=True)

from __future__ import annotations

import gdb

import pwndbg
import tests

SMALL_BINARY = tests.binaries.get("crash_simple.out.hardcoded")


def test_mmap_executes_properly(start_binary):
    """
    Tests the mprotect command
    """
    start_binary(SMALL_BINARY)

    pc = pwndbg.gdblib.regs.pc
    page_size = pwndbg.lib.memory.PAGE_SIZE

    # Checks for an mmap(2) error.
    #
    # mmap(2) is documented to only return a (void*) -1 on failure, but we are a
    # little stricter and consider any value on the last page to be a mapping
    # error. While technically we don't need to do this, we make the assumption
    # that any mapping landing in the last page during a test should warrant
    # manual investigation.
    def is_mmap_error(ptr):
        err = ((1 << pwndbg.gdblib.arch.ptrsize) - 1) & pwndbg.lib.memory.PAGE_MASK
        return ptr & pwndbg.lib.memory.PAGE_MASK == err

    # Checks whether permissions match.
    def has_correct_perms(ptr, perm):
        page = pwndbg.gdblib.vmmap.find(ptr)
        return (
            not (page.read ^ ("r" in perm))
            and not (page.write ^ ("w" in perm))
            and not (page.execute ^ ("x" in perm))
        )

    # Check basic private+anonymous page mmap.
    ptr = int(gdb.execute(f"mmap 0x0 {page_size}", to_string=True), 0)
    print(f"{ptr:#x}")
    assert not is_mmap_error(ptr)
    assert has_correct_perms(ptr, "rwx")

    # Check basic fixed mapping.
    base_addr = 0xDEADBEEF & pwndbg.lib.memory.PAGE_MASK
    while True:
        page = pwndbg.gdblib.vmmap.find(base_addr)
        if page is None:
            break
        base_addr = page.end
    ptr = int(
        gdb.execute(
            f"mmap {base_addr:#x} {page_size} 7 MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE", to_string=True
        ),
        0,
    )
    print(f"{ptr:#x}")
    assert not is_mmap_error(ptr)
    assert has_correct_perms(ptr, "rwx")
    assert ptr == base_addr


def test_cannot_run_mmap_when_not_running(start_binary):
    # expect error message
    assert "mmap: The program is not being run.\n" == gdb.execute("mmap 0x0 0x1000", to_string=True)

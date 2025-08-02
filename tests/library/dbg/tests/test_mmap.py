from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import pwndbg_test

USE_FDS_BINARY = get_binary("use-fds.out")


@pwndbg_test
async def test_mmap_executes_properly(ctrl: Controller) -> None:
    """
    Tests the mmap command
    """
    import pwndbg.aglib.arch
    import pwndbg.aglib.memory
    import pwndbg.aglib.vmmap
    import pwndbg.lib.memory

    await ctrl.launch(USE_FDS_BINARY)

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
    output = await ctrl.execute_and_capture(f"mmap 0x0 {page_size}")
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
    output = await ctrl.execute_and_capture(
        f"mmap {base_addr:#x} {page_size} 7 MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE"
    )
    assert output.startswith("mmap syscall returned ")
    ptr = int(output.split(" returned ")[1].rstrip(), 16)
    assert not is_mmap_error(ptr)
    assert has_correct_perms(ptr, "rwx")
    assert ptr == base_addr

    # Continue the program until just before close(2) is called.
    await ctrl.execute("b use-fds.c:16")
    await ctrl.cont()

    # Retrieve the file descriptor number and map it to memory.
    fd_num = int(pwndbg.dbg.selected_frame().evaluate_expression("fd"))
    output = await ctrl.execute_and_capture(f"mmap 0x0 16 PROT_READ MAP_PRIVATE {fd_num} 0")
    assert output.startswith("mmap syscall returned ")
    ptr = int(output.split(" returned ")[1].rstrip(), 16)
    assert not is_mmap_error(ptr)
    assert has_correct_perms(ptr, "r")

    # Load the 16 bytes read in by the read() call in the program, as well as
    # the first 16 bytes present in our newly created memory map, and compare
    # them.
    data_ptr = int(pwndbg.dbg.selected_frame().evaluate_expression("buf").address)
    data_local = pwndbg.aglib.memory.read(data_ptr, 16)
    data_mapped = pwndbg.aglib.memory.read(ptr, 16)
    assert data_local == data_mapped

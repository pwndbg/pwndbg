from __future__ import annotations

import tempfile

import gdb
import pytest

import pwndbg.aglib.proc
import tests

GAPS_MAP_BINARY = tests.binaries.get("mmap_gaps.out")
CRASH_SIMPLE_BINARY = tests.binaries.get("crash_simple.out.hardcoded")
BINARY_ISSUE_1565 = tests.binaries.get("issue_1565.out")


def get_proc_maps():
    """
        Example info proc mappings:

    pwndbg> info proc mappings
    process 26781
    Mapped address spaces:

              Start Addr           End Addr       Size     Offset objfile
                0x400000           0x401000     0x1000        0x0 /opt/pwndbg/tests/gdb-tests/tests/binaries/crash_simple.out
          0x7ffff7ffa000     0x7ffff7ffd000     0x3000        0x0 [vvar]
          0x7ffff7ffd000     0x7ffff7fff000     0x2000        0x0 [vdso]
          0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]
      0xffffffffff600000 0xffffffffff601000     0x1000        0x0 [vsyscall]
    """
    maps = []

    # Note: info proc mappings may not have permissions information,
    # so we get it here and fill from `perms`
    with open("/proc/%d/maps" % pwndbg.aglib.proc.pid) as f:
        for line in f.read().splitlines():
            addrs, perms, offset, _inode, size, objfile = line.split(maxsplit=6)
            start, end = (int(v, 16) for v in addrs.split("-"))
            offset = offset.lstrip("0") or "0"
            size = end - start
            maps.append([hex(start), hex(end), perms, hex(size)[2:], offset, objfile])

    maps.sort()

    return maps


@pytest.mark.parametrize("unload_file", (False, True))
def test_command_vmmap_on_coredump_on_crash_simple_binary(start_binary, unload_file):
    """
    Example vmmap when debugging binary:
        LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
                  0x400000           0x401000 r-xp     1000 0      /opt/pwndbg/tests/gdb-tests/tests/binaries/crash_simple.out
            0x7ffff7ffa000     0x7ffff7ffd000 r--p     3000 0      [vvar]
            0x7ffff7ffd000     0x7ffff7fff000 r-xp     2000 0      [vdso]
            0x7ffffffde000     0x7ffffffff000 rwxp    21000 0      [stack]
        0xffffffffff600000 0xffffffffff601000 r-xp     1000 0      [vsyscall]

    The same vmmap when debugging coredump:
        LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
                  0x400000           0x401000 r-xp     1000 0      /opt/pwndbg/tests/gdb-tests/tests/binaries/crash_simple.out
            0x7ffff7ffd000     0x7ffff7fff000 r-xp     2000 1158   load2
            0x7ffffffde000     0x7ffffffff000 rwxp    21000 3158   [stack]
        0xffffffffff600000 0xffffffffff601000 r-xp     1000 24158  [vsyscall]

    Note that for a core-file, we display the [vdso] page as load2 and we are missing the [vvar] page.
    This is... how it is. It just seems that core files (at least those I met) have no info about
    the vvar page and also GDB can't access the [vvar] memory with its x/ command during core debugging.
    """
    start_binary(CRASH_SIMPLE_BINARY)

    # Trigger binary crash
    gdb.execute("continue")

    expected_maps = get_proc_maps()

    gdb.execute("set vmmap-prefer-relpaths off")
    vmmaps = gdb.execute("vmmap", to_string=True).splitlines()

    # Basic asserts
    assert len(vmmaps) == len(expected_maps) + 2  # +2 for header and legend
    assert vmmaps[0] == "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA"

    # Split vmmaps
    vmmaps = [i.split() for i in vmmaps[2:]]

    # Assert that vmmap output matches expected one
    assert vmmaps == expected_maps

    # Now, generate core file, so we can then test coredump vmmap
    core = tempfile.mktemp()
    gdb.execute(f"generate-core-file {core}")

    # The test should work fine even if we unload the original binary
    if unload_file:
        gdb.execute("file")

    #### TEST COREDUMP VMMAP
    # Now, let's load the generated core file
    gdb.execute(f"core-file {core}")

    old_len_vmmaps = len(vmmaps)
    vmmaps = gdb.execute("vmmap", to_string=True).splitlines()

    # Note: we will now see one less vmmap page as [vvar] will be missing
    assert vmmaps[0] == "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA"
    vmmaps = [i.split() for i in vmmaps[2:]]

    has_proc_maps = "warning: unable to find mappings in core file" not in gdb.execute(
        "info proc mappings", to_string=True
    )

    if has_proc_maps:
        assert len(vmmaps) == old_len_vmmaps - 1
    else:
        # E.g. on Debian 10 with GDB 8.2.1 the core dump does not contain mappings info
        # (note: we don't support Debian 10 anymore, so this code may be removed in the future)
        assert len(vmmaps) == old_len_vmmaps - 2
        binary_map = next(i for i in expected_maps if CRASH_SIMPLE_BINARY in i[-1])
        expected_maps.remove(binary_map)

    # Fix up expected maps
    next(i for i in expected_maps if i[-1] == "[vdso]")[-1] = "load2"

    vdso_map = next(i for i in expected_maps if i[-1] == "[vvar]")
    expected_maps.remove(vdso_map)

    def assert_maps():
        for vmmap, expected_map in zip(vmmaps, expected_maps):
            # On different Ubuntu versions, we end up with different results
            # Ubuntu 18.04*: vmmap.objfile for binary vmmap has binary file path
            # Ubuntu 22.04: the same vmmap is named as 'loadX'
            # The difference comes from the fact that the `info proc mappings`
            # command returns different results on the two.
            # It may be a result of different test binary compilation or
            # just a difference between GDB versions
            #
            # Another difference may occur for the vsyscall memory page:
            # on Ubuntu 22.04, while vsyscall is ---xp during debugging
            # it becomes r-xp and can be readable when we target the coredump
            # Likely, this is because on x86/x64 you can't set memory to be
            # eXecute only, and maybe generate-core-file was able to dump it?
            #
            # *NOTE: Ubuntu 18.04 is not supported anymore; leaving this code here
            # but feel free to remove it in the future if it is not needed anymore
            # for future versions
            if vmmap[-1] == expected_map[-1] == "[vsyscall]":
                assert vmmap[:2] == expected_map[:2]  # start, end
                assert vmmap[3] == expected_map[3] or vmmap[3] in ("r-xp", "--xp")
                assert vmmap[4:] == expected_map[4:]
                continue

            assert vmmap[:-1] == expected_map[:-1]
            if vmmap[-1].startswith("load"):
                continue
            assert vmmap[-1] == expected_map[-1]

    assert_maps()

    # Now also make sure that everything works fine if we remove
    # file symbols information from GDB; during writing this test
    # a bug with this popped out, so I am double checking it here
    gdb.execute("file")

    vmmaps = gdb.execute("vmmap", to_string=True).splitlines()
    vmmaps = [i.split() for i in vmmaps[2:]]

    assert_maps()


def test_vmmap_issue_1565(start_binary):
    """
    https://github.com/pwndbg/pwndbg/issues/1565

    In tests this bug is reported as:
    >       gdb.execute("context")
    E       gdb.error: Error occurred in Python: maximum recursion depth exceeded in comparison

    In a normal GDB session this is reported as:
        Exception occurred: context: maximum recursion depth exceeded while calling a Python object (<class 'RecursionError'>)
    """
    gdb.execute(f"file {BINARY_ISSUE_1565}")
    gdb.execute("break thread_function")
    gdb.execute("run")
    gdb.execute("next")
    gdb.execute("context")


def test_vmmap_gaps_option(start_binary):
    start_binary(GAPS_MAP_BINARY)

    gdb.execute("break break_here")
    gdb.execute("continue")

    # Test vmmap with gap option
    vmmaps = gdb.execute("vmmap --gaps", to_string=True).splitlines()
    seen_gap = False
    seen_adjacent = False
    seen_guard = False
    # Skip the first line since the legend has gard and
    for line in vmmaps[1:]:
        if "GAP" in line:
            seen_gap = True
        if "ADJACENT" in line:
            seen_adjacent = True
        if "GUARD" in line:
            seen_guard = True
    assert seen_gap
    assert seen_adjacent
    assert seen_guard

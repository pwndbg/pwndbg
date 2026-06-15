from __future__ import annotations

import tempfile

import gdb
import pytest

import pwndbg.aglib.proc

from . import get_binary

GAPS_MAP_BINARY = get_binary("mmap_gaps.native.out")
CRASH_SIMPLE_BINARY = get_binary("crash_simple.native.out")
BINARY_ISSUE_1565 = get_binary("issue_1565.native.out")


def get_proc_maps():
    """
    Example info proc mappings:

    pwndbg> info proc mappings
    process 26781
    Mapped address spaces:

    Start Addr         End Addr           Size      Offset Perms  File
    0x0000000001000000 0x0000000001001000 0x1000    0x0    r--p   /pwndbg/tests/binaries/host/crash_simple.native.out
    0x0000000001001000 0x0000000001002000 0x1000    0x0    r-xp   /pwndbg/tests/binaries/host/crash_simple.native.out
    0x00007ffff7ff7000 0x00007ffff7ffb000 0x4000    0x0    r--p   [vvar]
    0x00007ffff7ffb000 0x00007ffff7ffd000 0x2000    0x0    r--p   [vvar_vclock]
    0x00007ffff7ffd000 0x00007ffff7fff000 0x2000    0x0    r-xp   [vdso]
    0x00007ffffffde000 0x00007ffffffff000 0x21000   0x0    rw-p   [stack]
    0xffffffffff600000 0xffffffffff601000 0x1000    0x0    --xp   [vsyscall]

    Example `cat /proc/<pid>/maps`:

    01000000-01001000 r--p 00000000 103:05 61869998          /pwndbg/tests/binaries/host/crash_simple.native.out
    01001000-01002000 r-xp 00000000 103:05 61869998          /pwndbg/tests/binaries/host/crash_simple.native.out
    7ffff7ff7000-7ffff7ffb000 r--p 00000000 00:00 0          [vvar]
    7ffff7ffb000-7ffff7ffd000 r--p 00000000 00:00 0          [vvar_vclock]
    7ffff7ffd000-7ffff7fff000 r-xp 00000000 00:00 0          [vdso]
    7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0          [stack]
    ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0  [vsyscall]
    """
    maps = []

    # Note: info proc mappings may not have permissions information,
    # so we get it here and fill from `perms`
    with open(f"/proc/{pwndbg.aglib.proc.pid()}/maps") as f:
        for line in f.read().splitlines():
            addrs, perms, offset, _inode, size, objfile = line.split(maxsplit=6)
            start, end = (int(v, 16) for v in addrs.split("-"))
            offset = offset.lstrip("0") or "0"
            size = end - start
            maps.append([hex(start), hex(end), perms, f"{size:x}", offset, objfile])

    maps.sort()

    return maps


@pytest.mark.parametrize("unload_file", (False, True))
def test_command_vmmap_on_coredump_on_crash_simple_binary(start_binary, unload_file):
    """
    Example vmmap when debugging binary:
        LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
                  0x400000           0x401000 r-xp     1000 0      /opt/pwndbg/tests/binaries/host/crash_simple.out
            0x7ffff7ff7000     0x7ffff7ffb000 r--p     4000 0      [vvar]
            0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000 0      [vvar_vclock]
            0x7ffff7ffd000     0x7ffff7fff000 r-xp     2000 0      [vdso]
            0x7ffffffde000     0x7ffffffff000 rwxp    21000 0      [stack]
        0xffffffffff600000 0xffffffffff601000 r-xp     1000 0      [vsyscall]

    The same vmmap when debugging coredump:
        LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
                  0x400000           0x401000 r-xp     1000 0      /opt/pwndbg/tests/binaries/host/crash_simple.out
            0x7ffff7ffd000     0x7ffff7fff000 r-xp     2000 0      [vdso]
            0x7ffffffde000     0x7ffffffff000 rwxp    21000 3158   [stack]
        0xffffffffff600000 0xffffffffff601000 r-xp     1000 24158  [vsyscall]

    Note that a generated core-file does not contain a handful of mappings that exist at runtime, such as [vvar] or
    [vvar_vclock] page ([vvar_vclock] was introduced in a recent kernel version that distributions have picked up,
    funnily enough searching it online returns no results at the moment).
    "[vdso]" used to show up as "load2" for coredumps on older versions of GDB.

    This is... how it is. It just seems that core files (at least those I met) have no info about
    the vvar page and also GDB can't access the [vvar] memory with its x/ command during core debugging.
    """

    # Although these may exist at runtime, they won't show up in the coredump
    MAPPINGS_NOT_IN_CORE_DUMP = ["[vvar]", "[vvar_vclock]"]

    start_binary(CRASH_SIMPLE_BINARY)

    # Trigger binary crash
    gdb.execute("continue")

    expected_maps = get_proc_maps()

    count_of_non_coredump_mappings = sum(
        1 for line in expected_maps if line[-1] in MAPPINGS_NOT_IN_CORE_DUMP
    )

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
        assert len(vmmaps) == old_len_vmmaps - count_of_non_coredump_mappings
    else:
        # E.g. on Debian 10 with GDB 8.2.1 the core dump does not contain mappings info
        # (note: we don't support Debian 10 anymore, so this code may be removed in the future)
        assert len(vmmaps) == old_len_vmmaps - (count_of_non_coredump_mappings + 1)
        binary_map = next(i for i in expected_maps if CRASH_SIMPLE_BINARY in i[-1])
        expected_maps.remove(binary_map)

    # Remove mappings that aren't in the coredump
    expected_maps = [
        mapping for mapping in expected_maps if mapping[-1] not in MAPPINGS_NOT_IN_CORE_DUMP
    ]

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

    assert_maps()

    # Now also make sure that everything works fine if we remove
    # file symbols information from GDB; during writing this test
    # a bug with this popped out, so I am double checking it here
    gdb.execute("file")

    vmmaps1: list[str] = gdb.execute("vmmap", to_string=True).splitlines()
    vmmaps = [i.split() for i in vmmaps1[2:]]

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

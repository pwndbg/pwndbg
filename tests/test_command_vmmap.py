import gdb

import pwndbg
import tests

CRASH_SIMPLE_BINARY = tests.binaries.get("crash_simple.out.hardcoded")


def get_proc_maps():
    """
        Example info proc mappings:

    pwndbg> info proc mappings
    process 26781
    Mapped address spaces:

              Start Addr           End Addr       Size     Offset objfile
                0x400000           0x401000     0x1000        0x0 /opt/pwndbg/tests/binaries/crash_simple.out
          0x7ffff7ffa000     0x7ffff7ffd000     0x3000        0x0 [vvar]
          0x7ffff7ffd000     0x7ffff7fff000     0x2000        0x0 [vdso]
          0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]
      0xffffffffff600000 0xffffffffff601000     0x1000        0x0 [vsyscall]
    """
    maps = []

    # Note: info proc mappings may not have permissions information,
    # so we get it here and fill from `perms`
    with open("/proc/%d/maps" % pwndbg.gdblib.proc.pid, "r") as f:
        for line in f.read().splitlines():
            addrs, perms, offset, _inode, size, objfile = line.split(maxsplit=6)
            start, end = map(lambda v: int(v, 16), addrs.split("-"))
            offset = offset.lstrip("0") or "0"
            size = end - start
            maps.append([hex(start), hex(end), perms, hex(size)[2:], offset, objfile])

    maps.sort()

    return maps


def test_command_vmmap_on_coredump_on_crash_simple_binary(start_binary):
    """
    Example vmmap when debugging binary:
        LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
                  0x400000           0x401000 r-xp     1000 0      /opt/pwndbg/tests/binaries/crash_simple.out
            0x7ffff7ffa000     0x7ffff7ffd000 r--p     3000 0      [vvar]
            0x7ffff7ffd000     0x7ffff7fff000 r-xp     2000 0      [vdso]
            0x7ffffffde000     0x7ffffffff000 rwxp    21000 0      [stack]
        0xffffffffff600000 0xffffffffff601000 r-xp     1000 0      [vsyscall]

    The same vmmap when debugging coredump:
        LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
                  0x400000           0x401000 r-xp     1000 0      /opt/pwndbg/tests/binaries/crash_simple.out
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

    vmmaps = gdb.execute("vmmap", to_string=True).splitlines()

    # Basic asserts
    assert len(vmmaps) == len(expected_maps) + 1
    assert vmmaps[0] == "LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA"

    # Split vmmaps
    vmmaps = [i.split() for i in vmmaps[1:]]

    # Assert that vmmap output matches expected one
    assert vmmaps == expected_maps

    # Now, generate core file, so we can then test coredump vmmap
    core = "/tmp/test_command_vmmap_on_coredump_on_crash_simple_binary"
    gdb.execute("generate-core-file %s" % core)

    #### TEST COREDUMP VMMAP
    # Now, let's load the generated core file
    gdb.execute("core-file %s" % core)

    old_len_vmmaps = len(vmmaps)
    vmmaps = gdb.execute("vmmap", to_string=True).splitlines()

    # Note: we will now see one less vmmap page as [vvar] will be missing
    assert vmmaps[0] == "LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA"
    vmmaps = [i.split() for i in vmmaps[1:]]
    assert len(vmmaps) == old_len_vmmaps - 1

    # Fix up expected maps
    next(i for i in expected_maps if i[-1] == "[vdso]")[-1] = "load2"

    vdso_map = next(i for i in expected_maps if i[-1] == "[vvar]")
    expected_maps.remove(vdso_map)

    def assert_maps():
        for vmmap, expected_map in zip(vmmaps, expected_maps):
            # On different Ubuntu versions, we end up with different results
            # Ubuntu 18.04: vmmap.objfile for binary vmmap has binary file path
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
    vmmaps = [i.split() for i in vmmaps[1:]]

    assert_maps()

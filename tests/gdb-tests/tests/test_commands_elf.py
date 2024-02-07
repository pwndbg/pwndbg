from __future__ import annotations

import re
from pathlib import Path

import gdb
import pytest

import tests

NO_SECTS_BINARY = tests.binaries.get("gosample.x86")
PIE_BINARY_WITH_PLT = "reference_bin_pie.out"
NOPIE_BINARY_WITH_PLT = "reference_bin_nopie.out"
NOPIE_I386_BINARY_WITH_PLT = "reference_bin_nopie.i386.out"


def test_commands_plt_gotplt_got_when_no_sections(start_binary):
    start_binary(NO_SECTS_BINARY)

    # elf.py commands
    assert gdb.execute("plt", to_string=True) == "Could not find section .plt\n"
    assert gdb.execute("gotplt", to_string=True) == "Could not find section .got.plt\n"

    # got.py command
    out = gdb.execute("got", to_string=True).splitlines()
    assert len(out) == 4
    assert out[0] == "Filtering out read-only entries (display them with -r or --show-readonly)"
    assert out[1] == ""
    assert out[2] == f"State of the GOT of {Path.cwd() / NO_SECTS_BINARY}:"
    assert out[3] == "GOT protection: No RELRO | Found 0 GOT entries passing the filter"


@pytest.mark.parametrize(
    "binary_name,is_pie", ((PIE_BINARY_WITH_PLT, True), (NOPIE_BINARY_WITH_PLT, False))
)
def test_command_plt(binary_name, is_pie):
    binary = tests.binaries.get(binary_name)
    gdb.execute(f"file {binary}")

    out = gdb.execute("plt", to_string=True).splitlines()

    assert len(out) == 2
    assert re.match(r"Section \.plt 0x[0-9a-f]+-0x[0-9a-f]+:", out[0])
    assert re.match(r"0x[0-9a-f]+: puts@plt", out[1])

    gdb.execute("starti")

    out2 = gdb.execute("plt", to_string=True).splitlines()

    if is_pie:
        assert out != out2
    else:
        assert out == out2

    assert len(out2) == 2
    assert re.match(r"Section \.plt 0x[0-9a-f]+-0x[0-9a-f]+:", out2[0])
    assert re.match(r"0x[0-9a-f]+: puts@plt", out2[1])


@pytest.mark.parametrize(
    "binary_name,is_pie", ((PIE_BINARY_WITH_PLT, True), (NOPIE_BINARY_WITH_PLT, False))
)
def test_command_got_for_target_binary(binary_name, is_pie):
    binary = tests.binaries.get(binary_name)
    gdb.execute(f"file {binary}")

    out = gdb.execute("got", to_string=True).splitlines()

    assert out == ["got: The program is not being run."]

    gdb.execute("break main")
    gdb.execute("starti")

    out = gdb.execute("got", to_string=True).splitlines()

    # TODO/FIXME: We need to verify the addresses are correct or not

    # Before resolving symbols' addresses, .got and .got.plt are writable
    assert len(out) == 7
    assert out[0] == "Filtering out read-only entries (display them with -r or --show-readonly)"
    assert out[1] == ""
    assert out[2] == f"State of the GOT of {Path.cwd() / binary}:"
    assert out[3] == "GOT protection: Full RELRO | Found 3 GOT entries passing the filter"
    assert re.match(r"\[0x[0-9a-f]+\] __libc_start_main@GLIBC_[0-9.]+ -> .*", out[4])
    assert re.match(r"\[0x[0-9a-f]+\] __gmon_start__ -> .*", out[5])
    assert re.match(r"\[0x[0-9a-f]+\] puts@GLIBC_[0-9.]+ -> .*", out[6])

    gdb.execute("continue")

    # After resolving symbols' addresses, .got and .got.plt are read-only
    out = gdb.execute("got -r", to_string=True).splitlines()
    assert len(out) == 5
    assert out[0] == f"State of the GOT of {Path.cwd() / binary}:"
    assert out[1] == "GOT protection: Full RELRO | Found 3 GOT entries passing the filter"
    assert re.match(r"\[0x[0-9a-f]+\] __libc_start_main@GLIBC_[0-9.]+ -> .*", out[2])
    assert re.match(r"\[0x[0-9a-f]+\] __gmon_start__ -> .*", out[3])
    assert re.match(r"\[0x[0-9a-f]+\] puts@GLIBC_[0-9.]+ -> .*", out[4])

    # Try filtering out entries with "puts"
    out = gdb.execute("got -r puts", to_string=True).splitlines()
    assert len(out) == 5
    assert out[0] == "Filtering by symbol name: puts"
    assert out[1] == ""
    assert out[2] == f"State of the GOT of {Path.cwd() / binary}:"
    assert out[3] == "GOT protection: Full RELRO | Found 1 GOT entries passing the filter"
    assert re.match(r"\[0x[0-9a-f]+\] puts@GLIBC_[0-9.]+ -> .*", out[4])


@pytest.mark.parametrize(
    "binary_name", (NOPIE_BINARY_WITH_PLT, NOPIE_I386_BINARY_WITH_PLT), ids=["x86-64", "i386"]
)
def test_command_got_for_target_binary_and_loaded_library(binary_name):
    binary = tests.binaries.get(binary_name)
    gdb.execute(f"file {binary}")

    gdb.execute("break main")
    try:
        gdb.execute("starti")
    except gdb.error:
        pytest.skip("Test not supported on this platform.")

    # Before loading libc, we can't find .got.plt of libc
    out = gdb.execute("got -p libc", to_string=True).splitlines()
    assert len(out) == 6
    assert out[0] == "Filtering by lib/objfile path: libc"
    assert out[1] == "Filtering out read-only entries (display them with -r or --show-readonly)"
    assert out[2] == ""
    assert out[3] == "No shared library matching the path filter found."
    assert out[4] == "Available shared libraries:"
    assert out[5].endswith(("/ld-linux-x86-64.so.2", "/ld-linux.so.2"))

    gdb.execute("continue")

    # TODO/FIXME: We need to verify the addresses are correct or not

    # After loading libc, we can find .got.plt of libc
    out = gdb.execute("got -p libc", to_string=True).splitlines()
    assert out[0] == "Filtering by lib/objfile path: libc"
    assert out[1] == "Filtering out read-only entries (display them with -r or --show-readonly)"
    assert out[2] == ""
    assert re.match(r"State of the GOT of .*/libc.so.6:", out[3])
    m = re.match(
        r"GOT protection: (?:Partial|Full) RELRO \| Found (\d+) GOT entries passing the filter",
        out[4],
    )
    got_entries_count = int(m.group(1))
    # The count may be 0 on Arch Linux: it has bind now in glibc
    assert got_entries_count >= 0
    assert len(out) == (5 + got_entries_count)
    for i in range(got_entries_count):
        assert re.match(r"\[0x[0-9a-f]+\] .* -> .*", out[5 + i])

    # Try showing read-only entries of libc also
    out = gdb.execute("got -p libc -r", to_string=True).splitlines()
    assert out[0] == "Filtering by lib/objfile path: libc"
    assert out[1] == ""
    assert re.match(r"State of the GOT of .*/libc.so.6:", out[2])
    m = re.match(
        r"GOT protection: (?:Partial|Full) RELRO \| Found (\d+) GOT entries passing the filter",
        out[3],
    )
    assert int(m.group(1)) > got_entries_count  # We should have more entries now
    got_entries_count = int(m.group(1))
    assert len(out) == (4 + got_entries_count)
    for i in range(got_entries_count):
        assert re.match(r"\[0x[0-9a-f]+\] .* -> .*", out[4 + i])

    # Try filtering out libc's entries with "ABS"
    out = gdb.execute("got -p libc ABS", to_string=True).splitlines()
    assert out[0] == "Filtering by lib/objfile path: libc"
    assert out[1] == "Filtering by symbol name: ABS"
    assert out[2] == "Filtering out read-only entries (display them with -r or --show-readonly)"
    assert out[3] == ""
    assert re.match(r"State of the GOT of .*/libc.so.6:", out[4])
    m = re.match(
        r"GOT protection: (?:Partial|Full) RELRO \| Found (\d+) GOT entries passing the filter",
        out[5],
    )
    got_entries_count = int(m.group(1))
    assert len(out) == (6 + got_entries_count)
    for i in range(got_entries_count):
        assert re.match(r"\[0x[0-9a-f]+\] .*ABS.* -> .*", out[6 + i])

    # Try filtering out path with "l", which should match every library
    # First should be ld-linux(-x86-64)?.so.2
    out = gdb.execute("got -p l", to_string=True).splitlines()
    assert out[0] == "Filtering by lib/objfile path: l"
    assert out[1] == "Filtering out read-only entries (display them with -r or --show-readonly)"
    assert out[2] == ""
    assert re.match(r"State of the GOT of .*/ld-linux(-x86-64)?.so.2:", out[3])
    m = re.match(
        r"GOT protection: (?:Partial|Full) RELRO \| Found (\d+) GOT entries passing the filter",
        out[4],
    )
    got_entries_count = int(m.group(1))
    for i in range(got_entries_count):
        assert re.match(r"\[0x[0-9a-f]+\] .* -> .*", out[5 + i])
    assert out[5 + got_entries_count] == ""

    # Second should be libc.so.6
    out = out[5 + got_entries_count + 1 :]
    assert re.match(r"State of the GOT of .*/libc.so.6:", out[0])
    m = re.match(
        r"GOT protection: (?:Partial|Full) RELRO \| Found (\d+) GOT entries passing the filter",
        out[1],
    )
    got_entries_count = int(m.group(1))
    assert len(out) == (2 + got_entries_count)
    for i in range(got_entries_count):
        assert re.match(r"\[0x[0-9a-f]+\] .* -> .*", out[2 + i])

    # Check -a option list target binary's GOT also all loaded libraries' GOT
    # First should be target binary
    out = gdb.execute("got -a", to_string=True).splitlines()
    assert out[0] == "Filtering out read-only entries (display them with -r or --show-readonly)"
    assert out[1] == ""
    assert out[2] == f"State of the GOT of {Path.cwd() / binary}:"
    assert out[3] == "GOT protection: Full RELRO | Found 0 GOT entries passing the filter"
    assert out[4] == ""
    out = out[5:]

    # Second should be ld-linux(-x86-64)?.so.2
    assert re.match(r"State of the GOT of .*/ld-linux(-x86-64)?.so.2:", out[0])
    m = re.match(
        r"GOT protection: (?:Partial|Full) RELRO \| Found (\d+) GOT entries passing the filter",
        out[1],
    )
    got_entries_count = int(m.group(1))
    for i in range(got_entries_count):
        assert re.match(r"\[0x[0-9a-f]+\] .* -> .*", out[2 + i])
    assert out[2 + got_entries_count] == ""
    out = out[2 + got_entries_count + 1 :]

    # Third should be libc.so.6
    assert re.match(r"State of the GOT of .*/libc.so.6:", out[0])
    m = re.match(
        r"GOT protection: (?:Partial|Full) RELRO \| Found (\d+) GOT entries passing the filter",
        out[1],
    )
    got_entries_count = int(m.group(1))
    assert len(out) == (2 + got_entries_count)
    for i in range(got_entries_count):
        assert re.match(r"\[0x[0-9a-f]+\] .* -> .*", out[2 + i])

    # Check got -a -r puts can show the puts entry in target binary's GOT
    out = gdb.execute("got -a -r puts", to_string=True).splitlines()
    assert out[0] == "Filtering by symbol name: puts"
    assert out[1] == ""
    assert out[2] == f"State of the GOT of {Path.cwd() / binary}:"
    assert out[3] == "GOT protection: Full RELRO | Found 1 GOT entries passing the filter"
    assert re.match(r"\[0x[0-9a-f]+\] puts@GLIBC_[0-9.]+ -> .*", out[4])
    assert out[5] == ""
    assert re.match(r"State of the GOT of .*/ld-linux(-x86-64)?.so.2:", out[6])
    assert re.match(
        r"GOT protection: (?:Partial|Full) RELRO \| Found 0 GOT entries passing the filter", out[7]
    )
    assert out[8] == ""
    assert re.match(r"State of the GOT of .*/libc.so.6:", out[9])
    assert re.match(
        r"GOT protection: (?:Partial|Full) RELRO \| Found 0 GOT entries passing the filter", out[10]
    )
    assert len(out) == 11

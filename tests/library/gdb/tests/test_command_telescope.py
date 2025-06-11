from __future__ import annotations

import re

import gdb

import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.aglib.regs
import pwndbg.aglib.vmmap
import tests

TELESCOPE_BINARY = tests.binaries.get("telescope_binary.out")


def test_command_telescope(start_binary):
    """
    Tests simple telescope
    """
    start_binary(TELESCOPE_BINARY)

    gdb.execute("break break_here")
    gdb.execute("run")
    gdb.execute("up")

    expected_str = gdb.execute("print a", to_string=True)
    expected_lines = expected_str.split("\n")

    result_str = gdb.execute("telescope &a", to_string=True)
    result_lines = result_str.split("\n")

    for i in range(4):
        expected_addr = expected_lines[i + 1].split(" ")[4].strip(',"')
        assert expected_addr in result_lines[i]


def test_command_telescope_reverse(start_binary):
    """
    Tests reversed telescope
    """
    start_binary(TELESCOPE_BINARY)

    gdb.execute("break break_here")
    gdb.execute("run")
    gdb.execute("up")

    expected_str = gdb.execute("print a", to_string=True)
    expected_lines = expected_str.split("\n")

    result_str = gdb.execute("telescope ((uint8_t*)&a)+0x38 -r", to_string=True)
    result_lines = result_str.split("\n")

    for i in range(4):
        expected_addr = expected_lines[i + 1].split(" ")[4].strip(',"')
        assert expected_addr in result_lines[i]


def test_command_telescope_n_records(start_binary):
    """
    Tests telescope defined number of records
    """
    start_binary(TELESCOPE_BINARY)

    n = 3
    gdb.execute("entry")
    result = gdb.execute(f"telescope $rsp {n}", to_string=True).strip().splitlines()
    assert len(result) == n


def test_telescope_command_with_address_as_count(start_binary):
    start_binary(TELESCOPE_BINARY)

    out = gdb.execute("telescope 2", to_string=True).splitlines()
    rsp = pwndbg.aglib.regs.rsp

    assert len(out) == 2
    assert out[0] == "00:0000│ rsp %#x ◂— 1" % rsp

    expected = rf"01:0008│     {rsp + 8:#x} —▸ 0x[0-9a-f]+ ◂— '{pwndbg.aglib.proc.exe}'"
    assert re.search(expected, out[1])


def test_telescope_command_with_address_as_count_and_reversed_flag(start_binary):
    start_binary(TELESCOPE_BINARY)

    out = gdb.execute("telescope -r 2", to_string=True).splitlines()
    rsp = pwndbg.aglib.regs.rsp

    assert out == ["00:0000│     %#x ◂— 0" % (rsp - 8), "01:0008│ rsp %#x ◂— 1" % rsp]


def test_command_telescope_reverse_skipped_records_shows_input_address(start_binary):
    """
    Tests reversed telescope with skipped records shows input address
    """
    start_binary(TELESCOPE_BINARY)

    gdb.execute("break break_here")
    gdb.execute("run")
    gdb.execute("up")
    pwndbg.aglib.memory.write(pwndbg.aglib.regs.rsp - 8 * 3, b"\x00" * 8 * 4)

    expected_value = hex(pwndbg.aglib.regs.rsp)
    result_str = gdb.execute("telescope -r $rsp", to_string=True)
    result_lines = result_str.strip("\n").split("\n")

    assert expected_value in result_lines[-1]


def test_command_telescope_frame(start_binary):
    """
    Tests telescope --frame
    """
    start_binary(TELESCOPE_BINARY)

    gdb.execute("break break_here")
    gdb.execute("run")

    rsp = hex(pwndbg.aglib.regs.sp)
    rbp = hex(pwndbg.aglib.regs[pwndbg.aglib.regs.frame])

    result_str = gdb.execute("telescope --frame", to_string=True)
    result_lines = result_str.strip().split("\n")

    assert rsp in result_lines[0]
    assert rbp in result_lines[-2]


def test_command_telescope_frame_bp_below_sp(start_binary):
    """
    Tests telescope --frame when base pointer is below stack pointer
    """
    start_binary(TELESCOPE_BINARY)

    gdb.execute("break break_here")
    gdb.execute("run")
    gdb.execute("memoize")  # turn off cache

    pwndbg.aglib.regs.sp = pwndbg.aglib.regs[pwndbg.aglib.regs.frame] + 1

    result_str = gdb.execute("telescope --frame", to_string=True)

    assert "Cannot display stack frame because base pointer is below stack pointer" in result_str


def test_command_telescope_frame_bp_sp_different_vmmaps(start_binary):
    """
    Tests telescope --frame when base pointer and stack pointer are on different vmmap pages
    """
    start_binary(TELESCOPE_BINARY)

    gdb.execute("break break_here")
    gdb.execute("run")
    gdb.execute("memoize")  # turn off cache

    pages = pwndbg.aglib.vmmap.get()

    pwndbg.aglib.regs.sp = pages[0].start
    pwndbg.aglib.regs.bp = pages[1].start

    result_str = gdb.execute("telescope --frame", to_string=True)

    assert (
        "Cannot display stack frame because base pointer is not on the same page with stack pointer"
        in result_str
    )

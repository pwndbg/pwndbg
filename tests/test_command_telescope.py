import re

import gdb

import pwndbg.gdblib
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
    result = gdb.execute("telescope $rsp {}".format(n), to_string=True).strip().splitlines()
    assert len(result) == n


def test_telescope_command_with_address_as_count(start_binary):
    start_binary(TELESCOPE_BINARY)

    out = gdb.execute("telescope 2", to_string=True).splitlines()
    rsp = pwndbg.gdblib.regs.rsp

    assert len(out) == 2
    assert out[0] == "00:0000│ rsp %#x ◂— 0x1" % rsp

    expected = r"01:0008│     %#x —▸ 0x[0-9a-f]+ ◂— '%s'" % (rsp + 8, pwndbg.gdblib.proc.exe)
    assert re.search(expected, out[1])


def test_telescope_command_with_address_as_count_and_reversed_flag(start_binary):
    start_binary(TELESCOPE_BINARY)

    out = gdb.execute("telescope -r 2", to_string=True).splitlines()
    rsp = pwndbg.gdblib.regs.rsp

    assert out == ["00:0000│     %#x ◂— 0x0" % (rsp - 8), "01:0008│ rsp %#x ◂— 0x1" % rsp]

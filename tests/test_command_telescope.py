import gdb

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
    result_str = gdb.execute("telescope $rsp {}".format(n), to_string=True)
    assert len(result_str.strip("\n").split("\n")) == n

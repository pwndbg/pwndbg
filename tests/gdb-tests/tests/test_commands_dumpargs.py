import gdb

import tests

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")


def test_commands_dumpargs(start_binary):
    start_binary(REFERENCE_BINARY)

    gdb.execute("entry")

    dumpargs_output = gdb.execute("dumpargs", to_string=True)
    dumpargs_alias_ouptut = gdb.execute("args", to_string=True)
    assert dumpargs_output == dumpargs_alias_ouptut

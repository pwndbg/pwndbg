from __future__ import annotations

import re

import gdb


def test_config():
    gdb.execute("set context-disasm-lines 8")
    assert "8 (10)" in gdb.execute("config", to_string=True)

    gdb.execute("set banner-separator #")
    # \u2500 is ─
    assert "'#' ('\u2500')" in gdb.execute("theme", to_string=True)

    gdb.execute("set global-max-fast 0x80")
    assert "'0x80' ('0')" in gdb.execute("heap-config", to_string=True)


def test_config_filtering():
    out = gdb.execute("config context-disasm-lines", to_string=True).splitlines()

    assert re.match(r"Name\s+Documentation\s+Value\s+\(Default\)", out[0])
    assert re.match(r"-+", out[1])
    assert re.match(
        r"context-disasm-lines\s+number of additional lines to print in the disasm context\s+10",
        out[2],
    )
    assert (
        out[3]
        == "You can set a config variable with `set <config-var> <value>`, and read more about it with `help set <config-var>`."
    )
    assert (
        out[4]
        == "You can generate a configuration file using `configfile` - then put it in your .gdbinit after initializing pwndbg."
    )


def test_config_filtering_missing():
    out = gdb.execute("config asdasdasdasd", to_string=True)
    assert out == 'No config parameter found with filter "asdasdasdasd"\n'

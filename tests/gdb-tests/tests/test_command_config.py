import re

import gdb


def test_config():
    gdb.execute("set context-code-lines 8")
    assert "8 (10)" in gdb.execute("config", to_string=True)

    gdb.execute("set banner-separator #")
    # \u2500 is ─
    assert "'#' ('\u2500')" in gdb.execute("theme", to_string=True)

    gdb.execute("set global-max-fast 0x80")
    assert "'0x80' ('0')" in gdb.execute("heap_config", to_string=True)


def test_config_filtering():
    out = gdb.execute("config context-code-lines", to_string=True).splitlines()

    assert re.match(r"Name\s+Value\s+\(Def\)\s+Documentation", out[0])
    assert re.match(r"-+", out[1])
    assert re.match(
        r"context-code-lines\s+10\s+number of additional lines to print in the code context", out[2]
    )
    assert out[3] == "You can set config variable with `set <config-var> <value>`"
    assert (
        out[4]
        == "You can generate configuration file using `configfile` - then put it in your .gdbinit after initializing pwndbg"
    )


def test_config_filtering_missing():
    out = gdb.execute("config asdasdasdasd", to_string=True)
    assert out == 'No config parameter found with filter "asdasdasdasd"\n'

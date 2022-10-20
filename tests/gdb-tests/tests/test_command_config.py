import gdb


def test_config():
    gdb.execute("set context-code-lines 8")
    assert "8 (10)" in gdb.execute("config", to_string=True)

    gdb.execute("set banner-separator #")
    # \u2500 is ─
    assert "'#' ('\u2500')" in gdb.execute("theme", to_string=True)

    gdb.execute("set global-max-fast 0x80")
    assert "'0x80' ('0')" in gdb.execute("heap_config", to_string=True)

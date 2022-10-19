import gdb


def test_config():
    gdb.execute("set context-code-lines 8")
    assert "8 (10)" in gdb.execute("config", to_string=True)

    gdb.execute("set banner-separator #")
    # \u2500 is ─
    assert "'#' ('\u2500')" in gdb.execute("theme", to_string=True)

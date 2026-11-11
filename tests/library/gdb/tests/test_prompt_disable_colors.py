from __future__ import annotations

import gdb


def test_prompt_trailing_space_when_colors_disabled() -> None:
    """
    With colors disabled the prompt is set to a plain string ending in a
    space. gdb.execute() strips trailing whitespace from the command string
    (upstream GDB quirk, see #3353), so pwndbg protects the trailing space
    with readline markers. Check that the space survives.
    """
    gdb.execute("set disable-colors on")

    result = gdb.execute("show prompt", to_string=True)
    print(f"Result ---> {result!r}")
    assert result.startswith("Gdb's prompt is \"pwndbg> "), result

    gdb.execute("set disable-colors off")

from __future__ import annotations

import re

from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.out")


@pwndbg_test
async def test_config(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY)

    await ctrl.execute("set context-disasm-lines 8")
    assert "8 (10)" in (await ctrl.execute_and_capture("config"))

    await ctrl.execute("set banner-separator #")
    # \u2500 is ─
    assert "'#' ('\u2500')" in (await ctrl.execute_and_capture("theme"))

    await ctrl.execute("set global-max-fast 0x80")
    assert "'0x80' ('0')" in (await ctrl.execute_and_capture("heap-config"))


@pwndbg_test
async def test_config_filtering(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY)

    out = (await ctrl.execute_and_capture("config context-disasm-lines")).splitlines()

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


@pwndbg_test
async def test_config_filtering_missing(ctrl: Controller):
    await ctrl.launch(REFERENCE_BINARY)

    out = await ctrl.execute_and_capture("config asdasdasdasd")
    assert out == 'No config parameter found with filter "asdasdasdasd"\n'

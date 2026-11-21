from __future__ import annotations

from collections.abc import Callable

import gdb

import pwndbg.aglib.vmmap

from . import get_binary

REFERENCE_BINARY = get_binary("reference-binary.native.out")


def _basename(objfile: str) -> str:
    return objfile.rsplit("/", 1)[-1]


def _lowest_mapping(matches: Callable[[str], bool]) -> int | None:
    starts = [page.start for page in pwndbg.aglib.vmmap.get() if matches(page.objfile)]
    return min(starts) if starts else None


def _run_to_main() -> None:
    gdb.execute("break main")
    gdb.execute("continue")


def test_convenience_vars_unset_until_mapping_exists(start_binary: Callable[..., None]) -> None:
    # `starti` stops before the dynamic loader mapped libc.
    start_binary(REFERENCE_BINARY)

    assert gdb.convenience_variable("stack") is not None
    assert gdb.convenience_variable("ld") is not None
    assert gdb.convenience_variable("libc") is None

    _run_to_main()

    assert gdb.convenience_variable("libc") is not None


def test_convenience_vars_match_vmmap(start_binary: Callable[..., None]) -> None:
    start_binary(REFERENCE_BINARY)
    _run_to_main()

    expected = {
        "stack": _lowest_mapping(lambda objfile: objfile == "[stack]"),
        "heap": _lowest_mapping(lambda objfile: objfile == "[heap]"),
        "vdso": _lowest_mapping(lambda objfile: objfile == "[vdso]"),
        "vvar": _lowest_mapping(lambda objfile: objfile == "[vvar]"),
        "libc": _lowest_mapping(lambda objfile: _basename(objfile).startswith("libc.")),
        "ld": _lowest_mapping(lambda objfile: _basename(objfile).startswith("ld-linux")),
    }

    # These always exist for a dynamically linked binary stopped in main, so a
    # lookup that silently found nothing would not pass this test.
    assert expected["stack"] is not None
    assert expected["libc"] is not None
    assert expected["ld"] is not None

    for name, address in expected.items():
        # [heap], [vdso] and [vvar] are not guaranteed to be mapped everywhere.
        if address is None:
            continue
        assert int(gdb.parse_and_eval(f"${name}")) == address, f"${name}"


def test_convenience_vars_support_arithmetic(start_binary: Callable[..., None]) -> None:
    start_binary(REFERENCE_BINARY)
    _run_to_main()

    libc = int(gdb.parse_and_eval("$libc"))
    assert int(gdb.parse_and_eval("$libc + 0x10")) == libc + 0x10
    assert int(gdb.parse_and_eval("$stack - 8")) == int(gdb.parse_and_eval("$stack")) - 8
    assert int(gdb.parse_and_eval('$libc == $base("libc")')) == 1


def test_convenience_vars_are_cleared_when_the_process_exits(
    start_binary: Callable[..., None],
) -> None:
    start_binary(REFERENCE_BINARY)
    _run_to_main()
    assert gdb.convenience_variable("libc") is not None

    gdb.execute("delete")
    gdb.execute("continue")

    for name in ("stack", "heap", "libc", "ld", "vdso", "vvar"):
        assert gdb.convenience_variable(name) is None, f"${name}"

    # Nothing stale is visible when the program is started again.
    gdb.execute("starti")
    assert gdb.convenience_variable("libc") is None
    assert gdb.convenience_variable("stack") is not None

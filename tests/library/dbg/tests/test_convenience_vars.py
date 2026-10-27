from __future__ import annotations

from collections.abc import Callable

from ....host import Controller
from . import get_binary
from . import get_expr
from . import launch_to
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.native.out")


def _basename(objfile: str) -> str:
    return objfile.rsplit("/", 1)[-1]


def _lowest_mapping(matches: Callable[[str], bool]) -> int | None:
    import pwndbg.aglib.vmmap

    starts = [page.start for page in pwndbg.aglib.vmmap.get() if matches(page.objfile)]
    return min(starts) if starts else None


@pwndbg_test
async def test_convenience_vars_match_vmmap(ctrl: Controller) -> None:
    await launch_to(ctrl, REFERENCE_BINARY, "main")

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
        assert int(get_expr(f"${name}")) == address, f"${name}"


@pwndbg_test
async def test_convenience_vars_support_arithmetic(ctrl: Controller) -> None:
    await launch_to(ctrl, REFERENCE_BINARY, "main")

    libc = int(get_expr("$libc"))
    assert int(get_expr("$libc + 0x10")) == libc + 0x10
    assert int(get_expr("$stack - 8")) == int(get_expr("$stack")) - 8

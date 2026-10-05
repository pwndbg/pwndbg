from __future__ import annotations

import functools
import os
import re
from collections.abc import Callable
from collections.abc import Coroutine
from inspect import signature
from pathlib import Path
from typing import Any
from typing import Concatenate
from typing import ParamSpec

import pytest

from .... import host
from ....host import Controller

BINARIES_PATH = os.environ.get("TEST_BINARIES_ROOT", "/")

T = ParamSpec("T")


def pwndbg_test(
    test: Callable[Concatenate[Controller, T], Coroutine[Any, Any, None]],
) -> Callable[T, None]:
    @functools.wraps(test)
    def inner_test(*args: T.args, **kwargs: T.kwargs) -> None:
        async def _test(controller: Controller) -> None:
            await test(controller, *args, **kwargs)

        print(f"[+] Launching test {test.__name__} asynchronously")
        host.start(_test)

    # Remove the controller from the signature, as seen by Pytest.
    sig = signature(inner_test)
    sig = sig.replace(parameters=tuple(sig.parameters.values())[1:])
    inner_test.__signature__ = sig  # type: ignore[attr-defined]

    return inner_test


def get_binary(name: str) -> Path:
    return Path(BINARIES_PATH) / name


def _dockerfile_versions(libc: str) -> list[str]:
    dockerfile = Path(__file__).resolve().parents[4] / f"Dockerfile.{libc}-test-libs"
    return re.findall(r"(?m)^FROM base-builder AS build-([0-9][0-9.]*)", dockerfile.read_text())


def glibc_test_versions() -> list[str]:
    return _dockerfile_versions("glibc")


def musl_test_versions() -> list[str]:
    return _dockerfile_versions("musl")


def glibc_version_binaries(
    stem: str, *, suffix: str = "", include_system: bool = True
) -> list[tuple[str, Path]]:
    """(id, path) for each expected build of `stem`; id is "system" or a glibc version.

    e.g. stem="heap_malloc_chunk" -> [("system", heap_malloc_chunk.native.out),
    ("2.35", heap_malloc_chunk.glibc-2.35.out), ..., ("2.43", heap_malloc_chunk.glibc-2.43.out)].

    suffix goes before .out (e.g. "-nodebug"); include_system=False drops the system glibc build.
    """
    assert not (suffix and include_system), "suffix builds have no system variant"
    targets: list[tuple[str, Path]] = []
    if include_system:
        targets.append(("system", get_binary(f"{stem}.native.out")))
    for ver in glibc_test_versions():
        targets.append((ver, get_binary(f"{stem}.glibc-{ver}{suffix}.out")))
    return targets


def glibc_version_params(
    binaries: list[tuple[str, Path]],
    xfails: dict[str, str] | None = None,
    *,
    with_version: bool = False,
) -> pytest.MarkDecorator:
    """Build a pytest parametrization decorator for glibc test binaries.

    By default, each test case receives `binary`. Set `with_version=True`
    to also pass `glibc_version`. `xfails` maps version IDs to xfail reasons.
    """
    xfails = xfails or {}
    params = []
    for ident, b in binaries:
        marks = [pytest.mark.xfail(reason=xfails[ident], strict=False)] if ident in xfails else []
        if not b.exists():
            marks.append(pytest.mark.skip(reason=f"glibc {ident} test binary not available"))
        values = (ident, b) if with_version else (b,)
        params.append(pytest.param(*values, id=ident, marks=marks))
    return pytest.mark.parametrize("glibc_version,binary" if with_version else "binary", params)


def break_at_sym(sym: str) -> None:
    import pwndbg
    from pwndbg.dbg_mod import BreakpointLocation

    inf = pwndbg.dbg.selected_inferior()
    addr = inf.lookup_symbol(sym)
    assert addr is not None
    inf.break_at(BreakpointLocation(int(addr)))


async def launch_to(ctrl: Controller, target: Path, sym: str) -> None:
    import pwndbg
    import pwndbg.aglib
    from pwndbg.dbg_mod import BreakpointLocation

    await ctrl.launch(target)

    inf = pwndbg.dbg.selected_inferior()
    addr = inf.lookup_symbol(sym)
    assert addr is not None
    if pwndbg.aglib.regs.pc != int(addr):
        inf.break_at(BreakpointLocation(int(addr)))
        await ctrl.cont()


def get_expr(expr: str):
    import pwndbg

    ctx = pwndbg.dbg.selected_frame() or pwndbg.dbg.selected_inferior()
    return ctx.evaluate_expression(expr)


class mock_for_heuristic:
    def __init__(self, mock_symbols: list[str] | None = None, mock_all: bool = False) -> None:
        """
        Arguments:
            mock_symbols: Every symbol's address in the list will be mocked to `None`
            mock_all: All symbols will be mocked to `None`.

        """
        import pwndbg

        if mock_all:
            assert mock_symbols is None

        self.mock_symbols: list[str] | None = mock_symbols
        self.mock_all: bool = mock_all
        # Save `selected_inferior` before mocking
        self.saved_func = pwndbg.dbg.selected_inferior

    def __enter__(self) -> None:
        import pwndbg

        def mock_lookup_symbol(original):
            def _mock(symbol, *args, **kwargs):
                if self.mock_all:
                    return None
                assert self.mock_symbols
                for s in self.mock_symbols:
                    if s == symbol:
                        return None
                return original(symbol, *args, **kwargs)

            return _mock

        def mock_interior(original):
            def _mock(*args, **kwargs):
                inst = original(*args, **kwargs)
                inst.lookup_symbol = mock_lookup_symbol(inst.lookup_symbol)
                return inst

            return _mock

        # Mock `symbol_address_from_name` from `selected_inferior`
        pwndbg.dbg.selected_inferior = mock_interior(pwndbg.dbg.selected_inferior)

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        import pwndbg

        # Restore `selected_inferior`
        pwndbg.dbg.selected_inferior = self.saved_func

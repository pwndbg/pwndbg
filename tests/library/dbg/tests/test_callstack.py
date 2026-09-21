from __future__ import annotations

import inspect
import itertools

from ....host import Controller
from . import get_binary
from . import launch_to
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.native.out")


def _symbol_names(pairs: list[tuple[int, str | None]]) -> list[str]:
    """
    Strip the `+offset` suffix off resolved symbols, dropping unresolved ones.
    """
    return [symbol.split("+")[0] for _, symbol in pairs if symbol is not None]


@pwndbg_test
async def test_callstack_readable(ctrl: Controller) -> None:
    import pwndbg.aglib.memory
    import pwndbg.aglib.stack

    await launch_to(ctrl, REFERENCE_BINARY, "break_here")

    addresses = pwndbg.aglib.stack.callstack()

    assert len(addresses) > 0
    assert all(pwndbg.aglib.memory.is_readable_address(address) for address in addresses)


@pwndbg_test
async def test_callstack_symbols(ctrl: Controller) -> None:
    import pwndbg.aglib.stack

    await launch_to(ctrl, REFERENCE_BINARY, "break_here")

    pairs = list(pwndbg.aglib.stack.callstack_symbols_iter())
    names = _symbol_names(pairs)

    # The binary calls break_here() from main(), so both must show up, innermost first.
    assert names[0] == "break_here"
    assert "main" in names
    assert names.index("main") > names.index("break_here")

    # The addresses must be the ones callstack() reports, in the same order.
    assert [address for address, _ in pairs] == pwndbg.aglib.stack.callstack()


@pwndbg_test
async def test_callstack_iter_matches_callstack(ctrl: Controller) -> None:
    import pwndbg.aglib.stack

    await launch_to(ctrl, REFERENCE_BINARY, "break_here")

    assert list(pwndbg.aglib.stack.callstack_iter()) == pwndbg.aglib.stack.callstack()


@pwndbg_test
async def test_callstack_iter_is_lazy(ctrl: Controller) -> None:
    import pwndbg.aglib.stack

    await launch_to(ctrl, REFERENCE_BINARY, "break_here")

    # There is more than one frame, so a partial consumer must be able to stop early.
    assert len(pwndbg.aglib.stack.callstack()) > 1

    frames = pwndbg.aglib.stack.callstack_iter()
    assert inspect.isgenerator(frames)

    first = list(itertools.islice(frames, 1))

    assert first == pwndbg.aglib.stack.callstack()[:1]
    # The generator is only suspended, not exhausted: the outer frames were never walked.
    assert inspect.getgeneratorstate(frames) == inspect.GEN_SUSPENDED

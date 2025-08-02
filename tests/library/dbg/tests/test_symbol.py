from __future__ import annotations

from ....host import Controller
from . import break_at_sym
from . import get_binary
from . import pwndbg_test

MANGLING_BINARY = get_binary("symbol_1600_and_752.out")


@pwndbg_test
async def test_symbol_get(ctrl: Controller) -> None:
    import pwndbg

    await ctrl.launch(MANGLING_BINARY)
    break_at_sym("break_here")

    async def get_next_ptr():
        await ctrl.cont()

        # To fetch the value of 'p' it must be set first
        # and it will be set by the program copying from register to the stack
        # (we pass `to_string=True` to suppress the context output)
        await ctrl.execute_and_capture("nextret")
        p = int(pwndbg.dbg.selected_frame().evaluate_expression("p"))
        return pwndbg.dbg.selected_inferior().symbol_name_at_address(p)

    assert (await get_next_ptr()) == "main"

    assert (await get_next_ptr()) == "break_here(void*)"

    # Test for the bug https://github.com/pwndbg/pwndbg/issues/1600
    assert (await get_next_ptr()) == "A::foo(int, int)"

    assert (await get_next_ptr()) == "A::call_foo()"

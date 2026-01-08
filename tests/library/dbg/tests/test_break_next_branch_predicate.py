import pytest
import pwndbg.aglib.next


@pytest.mark.asyncio
async def test_break_next_branch_predicate_false(ctrl):
    async def predicate():
        return False

    ins = await pwndbg.aglib.next.break_next_branch(ctrl, predicate=predicate)
    assert ins is None

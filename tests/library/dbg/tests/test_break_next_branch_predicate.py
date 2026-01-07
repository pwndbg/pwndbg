from pwndbg.aglib.next import break_next_branch

class DummyEC:
    async def cont(self, *args, **kwargs):
        return

def test_break_next_branch_predicate_false(monkeypatch):
    async def fake_next_branch(address=None, including_current=False):
        class Ins:
            address = 0xdeadbeef
        return Ins()

    # Mock next_branch to always return a fake instruction
    monkeypatch.setattr("pwndbg.aglib.next.next_branch", fake_next_branch)
    monkeypatch.setattr("pwndbg.aglib.regs.pc", 0x0)

    # Predicate blocks the instruction
    def pred():
        return False

    ec = DummyEC()

    # Run coroutine
    result = None
    async def runner():
        nonlocal result
        result = await break_next_branch(ec, including_current=True, predicate=pred)

    import asyncio
    asyncio.get_event_loop().run_until_complete(runner())

    assert result is None

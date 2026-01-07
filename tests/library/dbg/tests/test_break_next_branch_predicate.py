from pwndbg.aglib.next import break_next_branch

class DummyEC:
    async def cont(self, *args, **kwargs):
        return

def test_break_next_branch_predicate_false(monkeypatch):
    async def fake_next_branch(address=None, including_current=False):
        class Ins:
            address = 0xdeadbeef
        return Ins()

    monkeypatch.setattr("pwndbg.aglib.next.next_branch", fake_next_branch)
    monkeypatch.setattr("pwndbg.aglib.regs.pc", 0x0)

    def pred():
        return False

    ec = DummyEC()

    import asyncio
    result = asyncio.run(break_next_branch(ec, including_current=True, predicate=pred))

    assert result is None

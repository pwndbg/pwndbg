import asyncio
import types

from pwndbg.aglib.next import break_next_branch


class DummyEC:
    async def cont(self, *args, **kwargs):
        return


def test_break_next_branch_predicate_false(monkeypatch):
    class DummyIns:
        address = 0xdeadbeef

    async def fake_next_branch(address=None, including_current=False):
        return DummyIns()

    # Fake regs object
    fake_regs = types.SimpleNamespace(pc=0x0, reg_write=lambda *a, **k: None)

    monkeypatch.setattr("pwndbg.aglib.next.next_branch", fake_next_branch)
    monkeypatch.setattr("pwndbg.aglib.regs", fake_regs)

    # Predicate blocks the instruction
    def pred():
        return False

    ec = DummyEC()
    result = asyncio.run(break_next_branch(ec, including_current=True, predicate=pred))

    assert result is None

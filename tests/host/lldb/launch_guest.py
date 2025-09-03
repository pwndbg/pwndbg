from __future__ import annotations

import os
import shlex
import sys
from enum import Enum
from pathlib import Path
from typing import Any
from typing import Callable
from typing import Coroutine
from typing import Dict
from typing import List


async def _run(ctrl: Any, outer: Callable[..., Coroutine[Any, Any, None]]) -> None:
    # We only import this here, as pwndbg-lldb is responsible for setting Pwndbg
    # up on our behalf.
    from pwndbg.dbg.lldb.repl import PwndbgController

    from ...host import Controller

    assert isinstance(ctrl, PwndbgController)

    # Idealy we'd define this in an outer scope, but doing it in here gains us
    # proper access to type names.
    class _LLDBController(Controller):
        def __init__(self, pc: PwndbgController):
            self.pc = pc

        async def launch(
            self, binary: Path, args: List[str] = [], env: Dict[str, str] = {}
        ) -> None:
            await self.pc.execute("set context-reserve-lines never")
            await self.pc.execute(f"target create {binary}")
            env_args = " ".join((f"-E{k}={v}" for k, v in env.items()))
            await self.pc.execute(
                f"process launch -A true {env_args} -s -- "
                + " ".join(shlex.quote(arg) for arg in args)
            )

        async def cont(self) -> None:
            await self.pc.execute("continue")

        async def execute(self, command: str) -> None:
            await self.pc.execute(command)

        async def execute_and_capture(self, command: str) -> str:
            return (await self.pc.execute_and_capture(command)).decode(
                "utf-8", errors="surrogateescape"
            )

        async def step_instruction(self) -> None:
            await self.pc.execute("thread step-inst")

        async def finish(self) -> None:
            await self.pc.execute("thread step-out")

        async def select_thread(self, tid: int) -> None:
            await self.pc.execute(f"thread select {tid}")

    await outer(_LLDBController(ctrl))


def run(pytest_args: List[str], pytest_plugins: List[Any] | None) -> int:
    # The import path is set up before this function is called.
    os.environ["NO_COLOR"] = "1"

    from pwndbginit import pwndbg_lldb

    from ... import host
    from ...host import Controller

    # Replace host.start with a proper implementation of the start command.
    def _start(outer: Callable[[Controller], Coroutine[Any, Any, None]]) -> None:
        pwndbg_lldb.launch(_run, outer, debug=False)

    host.start = _start

    # Run Pytest.
    import pytest

    return pytest.main(pytest_args, plugins=pytest_plugins)


class Operation(Enum):
    RUN_TEST = "RUN-TEST"
    COLLECT = "COLLECT"

    def __str__(self) -> str:
        return self._value_


class CollectTestFunctionNames:
    "See https://github.com/pytest-dev/pytest/issues/2039#issuecomment-257753269"

    def __init__(self):
        self.collected = []

    def pytest_collection_modifyitems(self, items):
        for item in items:
            self.collected.append(item.nodeid)


if __name__ == "__main__":
    sys._pwndbg_unittest_run = True  # type: ignore[attr-defined]

    # Prepare the requested operation.
    op = Operation(os.environ["TEST_OPERATION"])
    match op:
        case Operation.COLLECT:
            pytest_home = Path(os.environ["TEST_PYTEST_ROOT"])
            assert pytest_home.exists()
            assert pytest_home.is_dir()

            pytest_args = ["--collect-only", str(pytest_home)]
            pytest_plugins = [CollectTestFunctionNames()]
        case Operation.RUN_TEST:
            test_name = os.environ["TEST_NAME"]

            # Ideally, we'd check that the test name is both valid and only
            # matches a single test in the library, but checking that it is at
            # least not empty should be good enough, provided the test host
            # is careful.
            assert test_name

            pytest_args = [test_name, "-vvv", "-s", "--showlocals", "--color=yes"]
            if os.environ["TEST_PDB_ON_FAIL"] == "1":
                pytest_args.append("--pdb")

            pytest_plugins = None

    # Start the test, proper.
    status = run(pytest_args, pytest_plugins)

    if op == Operation.COLLECT:
        for nodeid in pytest_plugins[0].collected:
            print(nodeid)

    sys.exit(status)

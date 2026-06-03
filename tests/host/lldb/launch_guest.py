from __future__ import annotations

import os
import shlex
import sys
from collections.abc import Callable
from collections.abc import Coroutine
from enum import Enum
from pathlib import Path
from typing import Any

import pytest


async def _run(ctrl: Any, outer: Callable[..., Coroutine[Any, Any, None]]) -> None:
    # We only import this here, as pwndbg-lldb is responsible for setting Pwndbg
    # up on our behalf.
    from pwndbg.dbg_mod.lldb.repl import PwndbgController

    from ...host import Controller

    assert isinstance(ctrl, PwndbgController)

    # Idealy we'd define this in an outer scope, but doing it in here gains us
    # proper access to type names.
    class _LLDBController(Controller):
        def __init__(self, pc: PwndbgController):
            self.pc = pc

        async def launch(
            self, binary: Path, args: list[str] = [], env: dict[str, str] = {}
        ) -> None:
            if not os.path.exists(binary):
                pytest.skip(f"{os.path.basename(binary)} does not exist. Platform not supported.")

            await self.pc.execute("set context-reserve-lines never")
            # Disable debuginfod globally for LLDB tests: a partial/laggy
            # download triggers `LLVM ERROR: CachedFileStream was not committed`
            # which aborts the whole process and makes CI flaky (commonly seen
            # on the fedora43 image, which ships LLDB 21 + system-wide
            # debuginfod URLs). See https://github.com/llvm/llvm-project/issues/184728
            await self.pc.execute("settings clear plugin.symbol-locator.debuginfod.server-urls")
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
            # Since LLDB 21+, `step-inst` will stop on breakpoints too.. so `step-instr` will not move forward
            # See: https://github.com/llvm/llvm-project/issues/160219
            await self.pc.execute("break disable")
            await self.pc.execute("thread step-inst")
            await self.pc.execute("break enable")

        async def finish(self) -> None:
            await self.pc.execute("thread step-out")

        async def select_thread(self, tid: int) -> None:
            await self.pc.execute(f"thread select {tid}")

        async def disable_debuginfod(self) -> None:
            # Could also consider disabling `symbols.enable-external-lookup`
            await self.pc.execute("settings clear plugin.symbol-locator.debuginfod.server-urls")

        async def generate_core_file(self, path: Path) -> None:
            await self.pc.execute(f"process save-core {path}")
            await self.pc.execute("target delete")
            await self.pc.execute(f"target create --core {path}")

    await outer(_LLDBController(ctrl))


def run(pytest_args: list[str], pytest_plugins: list[Any] | None) -> int:
    # The import path is set up before this function is called.
    os.environ.setdefault("NO_COLOR", "1")

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

            # pytest_args = [test_name, "-vvv", "-s", "--showlocals", "--color=yes"]
            color = "no" if os.environ.get("NO_COLOR") == "1" else "yes"
            pytest_args = [test_name, "-vvv", "-s", "--showlocals", f"--color={color}"]
            if os.environ["TEST_PDB_ON_FAIL"] == "1":
                pytest_args.append("--pdb")

            pytest_plugins = None

    # Start the test, proper.
    status = run(pytest_args, pytest_plugins)

    if op == Operation.COLLECT:
        for nodeid in pytest_plugins[0].collected:
            print(nodeid)

    sys.exit(status)

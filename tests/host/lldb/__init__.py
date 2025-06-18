from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List

from host import TestHost
from host import TestResult
from host import _collection_from_pytest
from host import _result_from_pytest


class LLDBTestHost(TestHost):
    def __init__(self, pwndbg_root: Path, lldbinit_dir: Path, pytest_root: Path):
        assert pwndbg_root.exists()
        assert pwndbg_root.is_dir()

        assert lldbinit_dir.exists()
        assert lldbinit_dir.is_dir()

        assert pytest_root.exists()
        assert pytest_root.is_dir()

        self._pwndbg_root = pwndbg_root
        self._lldbinit_dir = lldbinit_dir
        self._pytest_root = pytest_root

    def _launch(
        self, op: str, test_name: str | None, capture: bool
    ) -> subprocess.CompletedProcess[str]:
        target = self._pwndbg_root / "tests" / "host" / "lldb" / "launch-guest.py"

        assert target.exists()
        assert target.is_file()

        assert op in ("RUN-TEST", "COLLECT")
        assert op != "RUN-TEST" or test_name is not None

        interpreter = Path(sys.executable)

        assert interpreter.exists()
        assert interpreter.is_file()

        env = os.environ.copy()
        env["TEST_OPERATION"] = op
        env["TEST_PYTEST_HOME"] = str(self._pytest_root)
        env["TEST_PWNDBG_HOME"] = str(self._pwndbg_root)
        env["PWNDBG_LLDBINIT_DIR"] = str(self._lldbinit_dir)
        if test_name is not None:
            env["TEST_NAME"] = test_name

        return subprocess.run(
            [interpreter, str(target)], capture_output=capture, text=True, env=env
        )

    def collect(self) -> List[str]:
        result = self._launch("COLLECT", None, True)
        return _collection_from_pytest(result, self._pwndbg_root, self._pytest_root)

    def run(self, case: str, coverage_out: Path | None, interactive: bool) -> TestResult:
        beg = time.monotonic_ns()
        result = self._launch("RUN-TEST", case, not interactive)
        end = time.monotonic_ns()

        return _result_from_pytest(result, end - beg)

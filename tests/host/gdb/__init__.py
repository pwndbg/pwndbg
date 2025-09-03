from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from subprocess import CompletedProcess
from typing import List

from ...host import TestHost
from ...host import TestResult
from ...host import _collection_from_pytest
from ...host import _result_from_pytest


class GDBTestHost(TestHost):
    def __init__(
        self,
        pwndbg_root: Path,
        pytest_root: Path,
        binaries_root: Path,
        gdb_path: Path,
    ):
        self._pwndbg_root = pwndbg_root
        self._pytest_root = pytest_root
        self._binaries_root = binaries_root
        self._gdb_path = gdb_path

    def _run_gdb(
        self,
        target: str,
        gdb_args_before: List[str] = [],
        env=None,
        capture_output=True,
    ) -> CompletedProcess[str]:
        env = os.environ if env is None else env

        # Prepare the GDB command line.
        gdb_args = ["-ex", f"py import sys,os; sys.path.insert(0, os.getcwd()); import {target}"]

        return subprocess.run(
            [str(self._gdb_path), "--silent", "--nx"]
            + gdb_args_before
            + gdb_args
            + ["--eval-command", "quit"],
            env=env,
            capture_output=capture_output,
            text=True,
            cwd=self._pwndbg_root,
        )

    def run(
        self,
        case: str,
        coverage_out: Path | None,
        interactive: bool,
    ) -> TestResult:
        gdb_args_before = []
        if coverage_out is not None:
            gdb_args_before = [
                "-ex",
                "py import coverage;coverage.process_startup();",
            ]

        # We pass parameters to `pytests_launcher` through environment variables.
        env = os.environ.copy()
        env["LANG"] = "en_US.UTF-8"
        env["SRC_DIR"] = str(self._pwndbg_root)
        env["COVERAGE_FILE"] = str(coverage_out)
        env["COVERAGE_PROCESS_START"] = str(self._pwndbg_root / "pyproject.toml")
        env["PWNDBG_LAUNCH_TEST"] = case
        env["NO_COLOR"] = "1"
        env["GDB_BIN_PATH"] = str(self._gdb_path)
        env["TEST_BINARIES_ROOT"] = str(self._binaries_root)
        if interactive:
            env["USE_PDB"] = "1"

        # Run the test to completion and time it.
        started_at = time.monotonic_ns()

        # The test itself runs under GDB, spawned by this process, and prepared
        # by the `pytests_launcher` script.
        result = self._run_gdb(
            "tests.host.gdb.pytests_launcher",
            gdb_args_before=gdb_args_before,
            env=env,
            capture_output=not interactive,
        )
        duration = time.monotonic_ns() - started_at

        return _result_from_pytest(result, duration)

    def collect(self) -> List[str]:
        # NOTE: We run tests under GDB sessions and because of some cleanup/tests dependencies problems
        # we decided to run each test in a separate GDB session

        env = os.environ.copy()
        env["TEST_BINARIES_ROOT"] = str(self._binaries_root)
        env["TESTS_PATH"] = str(self._pytest_root)

        result = self._run_gdb("tests.host.gdb.pytests_collect", env=env)
        names = _collection_from_pytest(result, self._pwndbg_root, self._pytest_root)

        # We execute from Pwndbg root, so we need to prepend tests/ to the names.
        return [f"tests/{name}" for name in names]

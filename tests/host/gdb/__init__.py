from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path
from subprocess import CompletedProcess
from typing import List

from host import TestHost
from host import TestResult
from host import TestStatus
from typing_extensions import override


class GDBTestHost(TestHost):
    def __init__(self, pwndbg_root: Path, pytest_root: Path, gdb_path: Path, use_gdbinit: bool):
        self._pwndbg_root = pwndbg_root
        self._pytest_root = pytest_root
        self._gdb_path = gdb_path
        self._use_gdbinit = use_gdbinit

    def _run_gdb(
        self,
        target: Path,
        gdb_args_before: List[str] = [],
        env=None,
        capture_output=True,
    ) -> CompletedProcess[str]:
        env = os.environ if env is None else env

        # Prepare the GDB command line.
        gdb_args = ["--command", str(target)]
        if self._use_gdbinit:
            gdb_args.extend(["--init-command", str(self._pwndbg_root / "gdbinit.py")])

        return subprocess.run(
            [str(self._gdb_path), "--silent", "--nx", "--nh"]
            + gdb_args_before
            + gdb_args
            + ["--eval-command", "quit"],
            env=env,
            capture_output=capture_output,
            text=True,
        )

    @override
    def run(
        self,
        case: str,
        coverage_out: Path | None,
        interactive: bool,
    ) -> TestResult:
        # The test itself runs under GDB, spawned by this process, and prepared
        # by the `pytests_launcher` script.
        target = self._pwndbg_root / "tests" / "host" / "gdb" / "pytests_launcher.py"

        gdb_args_before = []
        if coverage_out is not None:
            gdb_args_before = [
                "-ex",
                "py import sys;print(sys.path);import coverage;coverage.process_startup();",
            ]

        # We pass parameters to `pytests_launcher` through environment variables.
        env = os.environ.copy()
        env["LANG"] = "en_US.UTF-8"
        env["SRC_DIR"] = str(self._pwndbg_root)
        env["COVERAGE_FILE"] = str(coverage_out)
        env["COVERAGE_PROCESS_START"] = str(self._pwndbg_root / "pyproject.toml")
        env["PWNDBG_LAUNCH_TEST"] = case
        env["PWNDBG_DISABLE_COLORS"] = "1"
        env["GDB_INIT_PATH"] = str(self._pwndbg_root / "gdbinit.py")
        env["GDB_BIN_PATH"] = str(self._gdb_path)
        if interactive:
            env["USE_PDB"] = "1"

        # Run the test to completion and time it.
        started_at = time.monotonic_ns()
        result = self._run_gdb(
            target, gdb_args_before=gdb_args_before, env=env, capture_output=not interactive
        )
        duration = time.monotonic_ns() - started_at

        # Determine low-granularity status from process return code.
        status = TestStatus.PASSED if result.returncode == 0 else TestStatus.FAILED

        # Determine high-granularity status from process output, if possible.
        stdout_status = None
        if not interactive:
            entries = re.search(
                r"(\x1b\[3.m(PASSED|FAILED|SKIPPED|XPASS|XFAIL)\x1b\[0m)",
                result.stdout,
                re.MULTILINE,
            )
            if entries:
                stdout_status = entries[0]

        # If possible, augment the status with the high-granularity output.
        if stdout_status is not None:
            # Check the consistency between the values.
            if status == TestStatus.FAILED and stdout_status != "FAILED":
                # They disagree.
                #
                # In this case, we should believe the more accurate but
                # lower-granularity status value. This may happen if the output
                # of the test includes any of the words we match against.
                pass
            else:
                match stdout_status:
                    case "PASSED":
                        status = TestStatus.PASSED
                    case "SKIPPED":
                        status = TestStatus.SKIPPED
                    case "XPASS":
                        status = TestStatus.XPASS
                    case "XFAIL":
                        status = TestStatus.XFAIL
                    case _:
                        # Also a disegreement. Keep the low-granularity status.
                        pass

        return TestResult(status, duration, result.stdout, result.stderr)

    @override
    def collect(self) -> List[str]:
        # NOTE: We run tests under GDB sessions and because of some cleanup/tests dependencies problems
        # we decided to run each test in a separate GDB session
        target = self._pwndbg_root / "tests" / "host" / "gdb" / "pytests_collect.py"

        env = os.environ.copy()
        env["TESTS_PATH"] = self._pytest_root

        result = self._run_gdb(target, env=env)
        tests_collect_output = result.stdout

        if result.returncode != 0:
            raise RuntimeError(f"collection command failed: {result.stderr}")

        # Extract the test names from the output using regex
        pattern = re.compile(rf"{str(self._pytest_root)}.*::.*")
        matches = pattern.findall(tests_collect_output)
        return list(matches)

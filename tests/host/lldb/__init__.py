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


class LLDBTestHost(TestHost):
    def __init__(
        self,
        pwndbg_root: Path,
        pytest_root: Path,
        binaries_root: Path,
        lldb_path: Path,
        use_lldbinit: bool,
    ):
        self._pwndbg_root = pwndbg_root
        self._pytest_root = pytest_root
        self._binaries_root = binaries_root
        self._lldb_path = lldb_path
        self._use_lldbinit = use_lldbinit

    def _run_lldb(
            self,
            target: Path,
            lldb_args_before: List[str] = [],
            env=None,
            capture_output=True,
    ) -> CompletedProcess[str]:
        env = os.environ if env is None else env

        # Prepare the LLDB command line.
        lldb_args = ["--source", str(target)]
        if self._use_lldbinit:
            lldb_args.extend(["--source", str(self._pwndbg_root / "lldbinit.py")])
        return subprocess.run(
            [str(self._lldb_path), "--batch"]
            + lldb_args_before
            + lldb_args
            + ["--one-line", "quit"],
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
        # The test itself runs under LLDB, spawned by this process, and prepared
        # by the `pytests_launcher` script.
        target = self._pwndbg_root / "tests" / "host" / "lldb" / "pytests_launcher.py"

        lldb_args_before = []
        if coverage_out is not None:
            lldb_args_before = [
                "--one-line", "script import sys;print(sys.path);import coverage;coverage.process_startup();",
            ]

        # We pass parameters to `pytests_launcher` through environment variables.
        env = os.environ.copy()
        env["LANG"] = "en_US.UTF-8"
        env["SRC_DIR"] = str(self._pwndbg_root)
        env["COVERAGE_FILE"] = str(coverage_out)
        env["COVERAGE_PROCESS_START"] = str(self._pwndbg_root / "pyproject.toml")
        env["PWNDBG_LAUNCH_TEST"] = case
        env["PWNDBG_DISABLE_COLORS"] = "1"
        env["LLDB_INIT_PATH"] = str(self._pwndbg_root / "lldbinit.py")
        env["LLDB_BIN_PATH"] = str(self._lldb_path)
        env["TEST_BINARIES_ROOT"] = str(self._binaries_root)
        env["TEST_USE_LLDBINIT"] = "1" if self._use_lldbinit else "0"
        if interactive:
            env["USE_PDB"] = "1"

        started_at = time.monotonic_ns()
        result = self._run_lldb(
            target, lldb_args_before=lldb_args_before, env=env, capture_output=not interactive
        )
        duration = time.monotonic_ns() - started_at

        # Determine low-granularity status from process return code.
        status = TestStatus.PASSED if result.returncode == 0 else TestStatus.FAILED

        # Determine high-granularity status from process output, if possible.
        stdout_status = None
        stdout_context = None
        if not interactive:
            entries = re.search(
                r"(\x1b\[3.m(PASSED|FAILED|SKIPPED|XPASS|XFAIL)\x1b\[0m)( .*::.* -)?( (.*))?",
                result.stdout,
                re.MULTILINE,
            )
            if entries:
                stdout_status = entries[2]
                stdout_context = entries[5]

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

        return TestResult(status, duration, result.stdout, result.stderr, stdout_context)

    def collect(self) -> List[str]:
        # NOTE: We run tests under LLDB sessions and because of some cleanup/tests dependencies problems
        # we decided to run each test in a separate LLDB session
        target = self._pwndbg_root / "tests" / "host" / "lldb" / "pytests_collect.py"

        env = os.environ.copy()
        env["TEST_BINARIES_ROOT"] = str(self._binaries_root)
        env["TESTS_PATH"] = str(self._pytest_root)

        result = self._run_lldb(target, env=env)
        tests_collect_output = result.stdout

        if result.returncode != 0:
            raise RuntimeError(f"collection command failed: {result.stderr} {result.stdout}")

        # Extract the test names from the output using regex
        #
        # _run_lldb executes it in the current working directory, and so paths
        # printed by pytest are relative to it.
        path_spec = self._pytest_root.resolve().relative_to(self._pwndbg_root)
        pattern = re.compile(rf"{path_spec}.*::.*")
        matches = pattern.findall(tests_collect_output)
        return list(matches)
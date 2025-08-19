from __future__ import annotations

import re
from enum import Enum
from pathlib import Path
from subprocess import CompletedProcess
from typing import Any
from typing import Awaitable
from typing import Callable
from typing import Coroutine
from typing import Dict
from typing import List


def _collection_from_pytest(
    result: CompletedProcess[str], pwndbg_root: Path, pytest_root: Path
) -> List[str]:
    """
    Given the output of a completed Pytest collection, return a list of tests.
    """
    tests_collect_output = result.stdout

    if result.returncode != 0:
        raise RuntimeError(f"collection command failed: {result.stderr} {result.stdout}")

    # Extract the test names from the output using regex
    #
    # _run_gdb executes it in the current working directory, and so paths
    # printed by pytest are relative to it.
    path_spec = pytest_root.resolve().relative_to(pwndbg_root / "tests")
    pattern = re.compile(rf"{path_spec}.*::.*")
    matches = pattern.findall(tests_collect_output)

    return list(matches)


def _result_from_pytest(result: CompletedProcess[str], duration_ns: int) -> TestResult:
    """
    Given the output of a completed test, return a `TestResult`.
    """

    # Determine low-granularity status from process return code.
    status = TestStatus.PASSED if result.returncode == 0 else TestStatus.FAILED

    # Determine high-granularity status from process output, if possible.
    stdout_status = None
    stdout_context = None
    if result.stdout is not None:
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

    return TestResult(status, duration_ns, result.stdout, result.stderr, stdout_context)


class TestStatus(Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    XPASS = "XPASS"
    XFAIL = "XFAIL"
    SKIPPED = "SKIPPED"

    def __str__(self):
        return self._value_


class TestResult:
    status: TestStatus
    "Status result of the test."
    duration_ns: int
    "Duration of the test, as a whole number of nanoseconds."
    stdout: str | None
    "Standard Output of the test, if captured, `None` otherwise."
    stderr: str | None
    "Standard Error of the test, if captured, `None` otherwise."
    context: str | None
    "Extra context for the result, given as a human-readable textual description."

    def __init__(
        self,
        status: TestStatus,
        duration_ns: int,
        stdout: str | None,
        stderr: str | None,
        context: str | None,
    ):
        assert (stdout is None and stderr is None) or (
            stdout is not None and stderr is not None
        ), "either both stderr and stdout are captured, or neither is"

        self.status = status
        self.duration_ns = duration_ns
        self.stdout = stdout
        self.stderr = stderr
        self.context = context


class TestHost:
    def run(self, case: str, coverage_out: Path | None, interactive: bool) -> TestResult:
        """
        Runs a single test case of given name.

        The name of the test case is given in `case`, and it must match one of
        the names in the list returned by the `collect()` method.

        Tests may be run interactively by specifying `interactive=True`. When
        running interactively, the I/O of the test is attached to the I/O of the
        test and the Python Debugger (PDB) is automatically invoked for failing
        tests.

        Collection of code coverage data may be enabled for the test by
        specifying a coverage file path in `coverage_out`.
        """
        raise NotImplementedError()

    def collect(self) -> List[str]:
        """
        Collect the names of all the tests available to this host.
        """
        raise NotImplementedError()


class Controller:
    def launch(
        self, binary: Path, args: List[str] = [], env: Dict[str, str] = {}
    ) -> Awaitable[None]:
        """
        Launch the binary with the given path, relative to the binaries folder
        for the calling test.
        """
        raise NotImplementedError()

    def execute_and_capture(self, command: str) -> Awaitable[str]:
        """
        Execute the given command and capture its output.

        While this method is capable of executing any command supported by the
        debugger, in with keeping tests debugger-agnostic, is should only ever
        be used to invoke Pwndbg commands.
        """
        raise NotImplementedError()

    def execute(self, command: str) -> Awaitable[None]:
        """
        Execute the given command.

        While this method is capable of executing any command supported by the
        debugger, in with keeping tests debugger-agnostic, is should only ever
        be used to invoke Pwndbg commands.
        """
        raise NotImplementedError()

    def cont(self) -> Awaitable[None]:
        """
        Resume execution until the next stop event.
        """
        raise NotImplementedError()

    def step_instruction(self) -> Awaitable[None]:
        """
        Perform a step in the scope of a single instruction.
        """
        raise NotImplementedError()

    def finish(self) -> Awaitable[None]:
        """
        Resume execution; stop after the current function returns.
        """
        raise NotImplementedError()

    def select_thread(self, tid: int) -> Awaitable[None]:
        """
        Select the thread with the given ID.
        """
        raise NotImplementedError()


def start(controller: Callable[[Controller], Coroutine[Any, Any, None]]) -> None:
    """
    The start function.

    Both the testing hosts and the tests themselves share this module, and this
    function is used by the test piping to start the async debugger runtime.

    This function must be replaced in the test.
    """
    raise AssertionError(
        "either called host.start() from the testing host, or testing code did not replace it"
    )

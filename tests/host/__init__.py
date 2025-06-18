from __future__ import annotations

import argparse
import concurrent.futures
import multiprocessing
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from enum import Enum
from pathlib import Path
from subprocess import CompletedProcess
from typing import Any
from typing import Awaitable
from typing import Callable
from typing import Coroutine
from typing import List
from typing import Tuple


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
    path_spec = pytest_root.resolve().relative_to(pwndbg_root)
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


def run_tests_and_print_stats(
    host: TestHost,
    regex_filter: str | None,
    pdb: bool,
    serial: bool,
    verbose: bool,
    coverage_out: Path | None,
):
    """
    Runs all the tests made available by a given test host.
    """
    stats = TestStats()
    start = time.monotonic_ns()

    # PDB tests always run in sequence.
    if pdb and not serial:
        print("WARNING: Python Debugger (PDB) requires serial execution, but the user has")
        print("         requested parallel execution. Tests will *not* run in parallel.")
        serial = True

    tests_list = host.collect()
    if regex_filter is not None:
        # Filter test names if required.
        tests_list = [case for case in tests_list if re.search(regex_filter, case)]

    if serial:
        print("\nRunning tests in series")
        for test in tests_list:
            result = host.run(test, coverage_out, pdb)
            stats.handle_test_result(test, result, verbose)
    else:
        print("\nRunning tests in parallel")
        with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            for test in tests_list:
                executor.submit(host.run, test, coverage_out, pdb).add_done_callback(
                    # `test=test` forces the variable to bind early. This will
                    # change the type of the lambda, however, so we have to
                    # assure MyPy we know what we're doing.
                    lambda future, test=test: stats.handle_test_result(  # type: ignore[misc]
                        test, future.result(), verbose
                    )
                )

        # Return SIGINT to the default behavior.
        signal.signal(signal.SIGINT, signal.SIG_DFL)

    end = time.monotonic_ns()
    duration = end - start
    print("")
    print("*********************************")
    print("********* TESTS SUMMARY *********")
    print("*********************************")
    print(
        f"Time Spent   : {duration / 1000000000:.2f}s (cumulative: {stats.total_duration / 1000000000:.2f}s)"
    )
    print(f"Tests Passed : {stats.pass_tests}")
    print(f"Tests Skipped: {stats.skip_tests}")
    print(f"Tests Failed : {stats.fail_tests}")

    if stats.fail_tests != 0:
        print("\nFailing tests:")
        for test_case in stats.fail_tests_names:
            print(f"- {test_case}")
        sys.exit(1)


def get_gdb_host(args: argparse.Namespace, local_pwndbg_root: Path) -> TestHost:
    """
    Build a GDB-based test host.
    """
    if args.nix:
        # Use pwndbg, as build by nix.
        gdb_path = local_pwndbg_root / "result" / "bin" / "pwndbg"

        if not gdb_path.exists():
            print("ERROR: No nix-compatible pwndbg found. Run nix build .#pwndbg-dev")
            sys.exit(1)
    elif args.group == Group.CROSS_ARCH_USER:
        # Some systems don't ship 'gdb-multiarch', but support multiple
        # architectures in their regular binaries. Try the regular GDB.
        supports_arches = "py import os; archs = ['i386', 'aarch64', 'arm', 'mips', 'riscv', 'sparc']; os._exit(3) if len([arch for arch in archs if arch in gdb.architecture_names()]) == len(archs) else os._exit(2)"

        gdb_path_str = shutil.which("pwndbg")
        if gdb_path_str is None:
            print("ERROR: No 'pwndbg' executables in path")
            sys.exit(1)

        result = subprocess.run([gdb_path_str, "-nx", "-ex", supports_arches], capture_output=True)
        # GDB supports cross architecture targets
        if result.returncode == 3:
            gdb_path = Path(gdb_path_str)
        else:
            print("ERROR: 'pwndbg' does not support cross architecture targets")
            sys.exit(1)
    else:
        # Use the regular system GDB.
        gdb_path_str = shutil.which("pwndbg")
        if gdb_path_str is None:
            print("ERROR: No 'gdb' executable in path")
            sys.exit(1)
        gdb_path = Path(gdb_path_str)

    from host.gdb import GDBTestHost

    return GDBTestHost(
        local_pwndbg_root,
        local_pwndbg_root / args.group.library(),
        local_pwndbg_root / args.group.binary_dir(),
        gdb_path,
    )


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
    def launch(self, binary: Path) -> Awaitable[None]:
        """
        Launch the binary with the given path, relative to the binaries folder
        for the calling test.
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

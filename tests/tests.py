#!/usr/bin/env python3
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

import ziglang

from .host import TestHost
from .host import TestResult
from .host import TestStatus


def main():
    args = parse_args()
    coverage_out = None
    if args.cov:
        print("Will run codecov")
        coverage_out = Path(".cov/coverage")
    if args.pdb:
        print("Will run tests in serial and with Python debugger")
        args.serial = True

    local_pwndbg_root = (Path(os.path.dirname(__file__)) / "../").resolve()
    print(f"[*] Local Pwndbg root: {local_pwndbg_root}")

    # Build the binaries for the test group.
    #
    # As the nix store is read-only, we always use the local Pwndbg root for
    # building tests, even if the user has requested a nix-compatible test.
    #
    # Ideally, however, we would build the test targets as part of `nix verify`.
    make_all(local_pwndbg_root / args.group.binary_dir())

    if not args.driver.can_run(args.group):
        print(
            f"ERROR: Driver '{args.driver}' can't run test group '{args.group}'. Use another driver."
        )
        sys.exit(1)

    force_serial = False
    match args.driver:
        case Driver.GDB:
            host = get_gdb_host(args, local_pwndbg_root)
        case Driver.LLDB:
            host = get_lldb_host(args, local_pwndbg_root)

            # LLDB does not properly support having its tests run in parallel,
            # so we forcibly disable it, for now.
            print(
                "WARNING: LLDB tests always run in series, even when parallel execution is requested."
            )
            force_serial = True

    # Handle the case in which the user only wants the collection to run.
    if args.collect_only:
        for test in host.collect():
            print(test)
        sys.exit(0)

    # Actually run the tests.
    run_tests_and_print_stats(
        host,
        args.test_name_filter,
        args.pdb,
        force_serial or args.serial,
        args.verbose,
        coverage_out,
    )


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
        gdb_path = local_pwndbg_root / "result/bin/pwndbg"

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

    from .host.gdb import GDBTestHost

    return GDBTestHost(
        local_pwndbg_root,
        local_pwndbg_root / args.group.library(),
        local_pwndbg_root / args.group.binary_dir(),
        gdb_path,
    )


def get_lldb_host(args: argparse.Namespace, local_pwndbg_root: Path) -> TestHost:
    """
    Build an LLDB-based test host.
    """
    if args.nix:
        print("ERROR: Nix is currently not supported with driver LLDB")
        sys.exit(1)

    from .host.lldb import LLDBTestHost

    return LLDBTestHost(
        local_pwndbg_root,
        local_pwndbg_root / args.group.library(),
        local_pwndbg_root / args.group.binary_dir(),
    )


class Group(Enum):
    """
    Tests are divided into multiple groups.
    """

    GDB = "gdb"
    LLDB = "lldb"
    DBG = "dbg"
    CROSS_ARCH_USER = "cross-arch-user"

    def __str__(self):
        return self._value_

    def library(self) -> Path:
        """
        Subdirectory relative to the Pwndbg root containing the tests.
        """
        match self:
            case Group.GDB:
                return Path("tests/library/gdb/")
            case Group.LLDB:
                return Path("tests/library/lldb/")
            case Group.DBG:
                return Path("tests/library/dbg/")
            case Group.CROSS_ARCH_USER:
                return Path("tests/library/qemu_user/")
            case other:
                raise AssertionError(f"group {other} is unaccounted for")

    def binary_dir(self) -> Path:
        """
        Subdirectory relative to the Pwndbg root containing the required
        binaries for a given test group.
        """
        match self:
            case Group.GDB | Group.LLDB | Group.DBG:
                return Path("tests/binaries/host/")
            case Group.CROSS_ARCH_USER:
                return Path("tests/binaries/qemu_user/")
            case other:
                raise AssertionError(f"group {other} is unaccounted for")


class Driver(Enum):
    GDB = "gdb"
    LLDB = "lldb"

    def __str__(self):
        return self._value_

    def can_run(self, grp: Group) -> bool:
        """
        Whether a given driver can run a given test group.
        """
        match self:
            case Driver.GDB:
                match grp:
                    case Group.GDB:
                        return True
                    case Group.LLDB:
                        return False
                    case Group.DBG:
                        return True
                    case Group.CROSS_ARCH_USER:
                        return True
            case Driver.LLDB:
                match grp:
                    case Group.GDB:
                        return False
                    case Group.LLDB:
                        return True
                    case Group.DBG:
                        return True
                    case Group.CROSS_ARCH_USER:
                        return False
        raise AssertionError(f"unaccounted for combination of driver '{self}' and group '{grp}'")


def parse_args():
    parser = argparse.ArgumentParser(description="Run tests.")
    parser.add_argument("-g", "--group", choices=list(Group), type=Group, required=True)
    parser.add_argument(
        "-d",
        "--driver",
        choices=list(Driver),
        type=Driver,
        required=True,
    )
    parser.add_argument(
        "-p",
        "--pdb",
        action="store_true",
        help="enable pdb (Python debugger) post mortem debugger on failed tests",
    )
    parser.add_argument("-c", "--cov", action="store_true", help="enable codecov")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="display all test output instead of just failing test output",
    )
    parser.add_argument(
        "-s", "--serial", action="store_true", help="run tests one at a time instead of in parallel"
    )
    parser.add_argument(
        "--nix",
        action="store_true",
        help="run tests using built for nix environment",
    )
    parser.add_argument(
        "--collect-only",
        action="store_true",
        help="only show the output of test collection, don't run any tests",
    )
    parser.add_argument(
        "test_name_filter", nargs="?", help="run only tests that match the regex", default=".*"
    )
    return parser.parse_args()


def make_all(path: Path, jobs: int = multiprocessing.cpu_count()):
    """
    Build the binaries for a given test group.
    """
    if not path.exists():
        raise ValueError(f"given non-existent path {path}")

    print(f"[+] make -C {path} -j{jobs} all")
    try:
        subprocess.check_call(
            [
                "make",
                f"-j{jobs}",
                "ZIGCC=" + os.path.join(os.path.dirname(ziglang.__file__), "zig") + " cc",
                "all",
            ],
            cwd=str(path),
        )
    except subprocess.CalledProcessError:
        sys.exit(1)


class TestStats:
    def __init__(self):
        self.total_duration = 0
        self.fail_tests = 0
        self.pass_tests = 0
        self.skip_tests = 0
        self.fail_tests_names = []

    def handle_test_result(self, case: str, test_result: TestResult, verbose: bool):
        match test_result.status:
            case TestStatus.FAILED:
                self.fail_tests += 1
                self.fail_tests_names.append(case)
            case TestStatus.PASSED | TestStatus.XFAIL:
                self.pass_tests += 1
            case TestStatus.XPASS:
                # Technically this is a failure, but Pwndbg does not consider it so.
                self.pass_tests += 1
            case TestStatus.SKIPPED:
                self.skip_tests += 1
                # skip_reason = " " + (
                #    process.stdout.split(test_status)[1].split("\n\n\x1b[33m")[0].replace("\n", "")
                # )

        self.total_duration += test_result.duration_ns

        print(
            f"{case:<100} {test_result.status} {test_result.duration_ns / 1000000000:.2f}s {test_result.context if test_result.context else ''}"
        )

        # Only show the output of failed tests unless the verbose flag was used
        if verbose or test_result.status == TestStatus.FAILED:
            print("")
            print(test_result.stderr)
            print(test_result.stdout)


if __name__ == "__main__":
    main()

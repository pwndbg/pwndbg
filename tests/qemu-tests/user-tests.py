from __future__ import annotations

import argparse
import concurrent.futures
import os
import re
import subprocess
import sys
import time
from subprocess import CompletedProcess
from typing import List
from typing import Tuple

root_dir = os.path.realpath("../../")

def run_gdb(gdb_args: List[str], env=None, capture_output=True) -> CompletedProcess[str]:
    env = os.environ if env is None else env
    return subprocess.run(
        ["gdb-multiarch", "--silent", "--nx", "--nh"] + gdb_args + ["--eval-command", "quit"],
        env=env,
        capture_output=capture_output,
        text=True,
    )


def getTestsList(collect_only: bool, test_name_filter: str, gdbinit_path: str) -> List[str]:
    # NOTE: We run tests under GDB sessions and because of some cleanup/tests dependencies problems
    # we decided to run each test in a separate GDB session
    gdb_args = ["--init-command", gdbinit_path, "--command", "pytests_collect.py"]

    result = run_gdb(gdb_args)
    tests_collect_output = result.stdout

    if result.returncode == 1:
        print(tests_collect_output)
        exit(1)
    elif collect_only == 1:
        print(tests_collect_output)
        exit(0)

    # Extract the test names from the output using regex
    pattern = re.compile(r"tests/.*::.*")
    matches = pattern.findall(tests_collect_output)
    tests_list = [match for match in matches if re.search(test_name_filter, match)]
    return tests_list


def run_test(
    test_case: str, args: argparse.Namespace, gdbinit_path: str
) -> Tuple[CompletedProcess[str], str]:
    gdb_args = ["--init-command", gdbinit_path, "--command", "pytests_launcher.py"]
    if args.cov:
        print("Running with coverage")
        gdb_args = [
            "-ex",
            "py import sys;print(sys.path);import coverage;coverage.process_startup();",
        ] + gdb_args
    env = os.environ.copy()
    env["LC_ALL"] = "C.UTF-8"
    env["LANG"] = "C.UTF-8"
    env["LC_CTYPE"] = "C.UTF-8"
    env["SRC_DIR"] = root_dir
    env["COVERAGE_FILE"] = os.path.join(root_dir, ".cov/coverage")
    env["COVERAGE_PROCESS_START"] = os.path.join(root_dir, "pyproject.toml")
    if args.pdb:
        env["USE_PDB"] = "1"
    env["PWNDBG_LAUNCH_TEST"] = test_case
    env["PWNDBG_DISABLE_COLORS"] = "1"
    env["QEMU_PORT"] = "1234"
    result = run_gdb(gdb_args, env=env, capture_output=not args.serial)
    return (result, test_case)


def run_tests_and_print_stats(tests_list: List[str], args: argparse.Namespace, gdbinit_path: str):
    start = time.time()
    test_results: List[Tuple[CompletedProcess[str], str]] = []

    def handle_parallel_test_result(test_result: Tuple[CompletedProcess[str], str]):
        test_results.append(test_result)
        (process, _) = test_result
        content = process.stdout

        # Extract the test name and result using regex
        testname = re.search(r"^(tests/[^ ]+)", content, re.MULTILINE)[0]
        result = re.search(
            r"(\x1b\[3.m(PASSED|FAILED|SKIPPED|XPASS|XFAIL)\x1b\[0m)", content, re.MULTILINE
        )[0]

        (_, testname) = testname.split("::")
        print(f"{testname:<70} {result}")

        # Only show the output of failed tests unless the verbose flag was used
        if args.verbose or "FAIL" in result:
            print("")
            print(content)

    if args.serial:
        test_results = [run_test(test, args, gdbinit_path) for test in tests_list]
    else:
        print("")
        print("Running tests in parallel")
        with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            for test in tests_list:
                executor.submit(run_test, test, args, gdbinit_path).add_done_callback(
                    lambda future: handle_parallel_test_result(future.result())
                )

    end = time.time()
    seconds = int(end - start)
    print(f"Tests completed in {seconds} seconds")

    failed_tests = [(process, _) for (process, _) in test_results if process.returncode != 0]
    num_tests_failed = len(failed_tests)
    num_tests_passed_or_skipped = len(tests_list) - num_tests_failed

    print("")
    print("*********************************")
    print("********* TESTS SUMMARY *********")
    print("*********************************")
    print(f"Tests passed or skipped: {num_tests_passed_or_skipped}")
    print(f"Tests failed: {num_tests_failed}")

    if num_tests_failed != 0:
        print("")
        print(
            f"Failing tests: {' '.join([failed_test_name for _, failed_test_name in failed_tests])}"
        )
        exit(1)


def parse_args():
    parser = argparse.ArgumentParser(description="Run tests.")
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
        help="run tests using gdbinit.py built for nix environment",
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


if __name__ == "__main__":
    args = parse_args()
    if args.cov:
        print("Will run codecov")
    if args.pdb:
        print("Will run tests in serial and with Python debugger")
        args.serial = True
    if args.nix:
        gdbinit_path = os.path.join(root_dir, "result/share/pwndbg/gdbinit.py")
        if not os.path.exists(gdbinit_path):
            print("ERROR: No nix-compatible gdbinit.py found. Run nix build .#pwndbg-dev")
            sys.exit(1)
        os.environ["GDB_INIT_PATH"] = gdbinit_path
    else:
        gdbinit_path = os.path.join(root_dir, "gdbinit.py")

    tests: List[str] = getTestsList(args.collect_only, args.test_name_filter, gdbinit_path)
    run_tests_and_print_stats(tests, args, gdbinit_path)

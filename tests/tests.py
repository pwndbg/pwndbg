from __future__ import annotations

import argparse
import concurrent.futures
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from subprocess import CompletedProcess
from typing import List
from typing import Tuple

root_dir = os.path.realpath("../")


def reserve_port(ip="127.0.0.1", port=0):
    """
    https://github.com/Yelp/ephemeral-port-reserve/blob/master/ephemeral_port_reserve.py

    Bind to an ephemeral port, force it into the TIME_WAIT state, and unbind it.

    This means that further ephemeral port alloctions won't pick this "reserved" port,
    but subprocesses can still bind to it explicitly, given that they use SO_REUSEADDR.
    By default on linux you have a grace period of 60 seconds to reuse this port.
    To check your own particular value:
    $ cat /proc/sys/net/ipv4/tcp_fin_timeout
    60

    By default, the port will be reserved for localhost (aka 127.0.0.1).
    To reserve a port for a different ip, provide the ip as the first argument.
    Note that IP 0.0.0.0 is interpreted as localhost.
    """
    import contextlib
    import errno
    from socket import SO_REUSEADDR
    from socket import SOL_SOCKET
    from socket import error as SocketError
    from socket import socket

    port = int(port)
    with contextlib.closing(socket()) as s:
        s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        try:
            s.bind((ip, port))
        except SocketError as e:
            # socket.error: EADDRINUSE Address already in use
            if e.errno == errno.EADDRINUSE and port != 0:
                s.bind((ip, 0))
            else:
                raise

        # the connect below deadlocks on kernel >= 4.4.0 unless this arg is greater than zero
        s.listen(1)

        sockname = s.getsockname()

        # these three are necessary just to get the port into a TIME_WAIT state
        with contextlib.closing(socket()) as s2:
            s2.connect(sockname)
            sock, _ = s.accept()
            with contextlib.closing(sock):
                return sockname[1]


def ensure_zig_path():
    if "ZIGPATH" not in os.environ:
        # If ZIGPATH is not set, set it to $pwd/.zig
        # In Docker environment this should by default be set to /opt/zig
        os.environ["ZIGPATH"] = os.path.join(root_dir, ".zig")
    print(f'ZIGPATH set to {os.environ["ZIGPATH"]}')


def make_binaries(test_dir: str):
    dir_binaries = Path(test_dir) / "binaries"
    if not dir_binaries.exists():
        return

    try:
        subprocess.check_call(["make", "all"], cwd=str(dir_binaries))
    except subprocess.CalledProcessError:
        sys.exit(1)


def run_gdb(
    gdb_path: str, gdb_args: List[str], env=None, capture_output=True
) -> CompletedProcess[str]:
    env = os.environ if env is None else env
    return subprocess.run(
        [gdb_path, "--silent", "--nx", "--nh"] + gdb_args + ["--eval-command", "quit"],
        env=env,
        capture_output=capture_output,
        text=True,
    )


def get_tests_list(
    collect_only: bool,
    test_name_filter: str,
    gdb_path: str,
    gdbinit_path: str,
    test_dir_path: str,
) -> List[str]:
    # NOTE: We run tests under GDB sessions and because of some cleanup/tests dependencies problems
    # we decided to run each test in a separate GDB session
    gdb_args = ["--command", "pytests_collect.py"]
    if gdbinit_path:
        gdb_args.extend(["--init-command", gdbinit_path])

    env = os.environ.copy()
    env["TESTS_PATH"] = os.path.join(os.path.dirname(os.path.realpath(__file__)), test_dir_path)

    result = run_gdb(gdb_path, gdb_args, env=env)
    tests_collect_output = result.stdout

    if result.returncode == 1:
        print(tests_collect_output)
        print(result.stderr)
        sys.exit(1)
    elif collect_only == 1:
        print(tests_collect_output)
        sys.exit(0)

    # Extract the test names from the output using regex
    pattern = re.compile(rf"{test_dir_path}.*::.*")
    matches = pattern.findall(tests_collect_output)
    tests_list = [match for match in matches if re.search(test_name_filter, match)]
    return tests_list


TEST_RETURN_TYPE = Tuple[CompletedProcess[str], str, float]


def run_test(
    test_case: str, args: argparse.Namespace, gdb_path: str, gdbinit_path: str, port: int = None
) -> TEST_RETURN_TYPE:
    gdb_args = ["--command", "pytests_launcher.py"]
    if gdbinit_path:
        gdb_args.extend(["--init-command", gdbinit_path])

    if args.cov:
        print("Running with coverage")
        gdb_args = [
            "-ex",
            "py import sys;print(sys.path);import coverage;coverage.process_startup();",
        ] + gdb_args
    env = os.environ.copy()
    env["LANG"] = "en_US.UTF-8"
    env["SRC_DIR"] = root_dir
    env["COVERAGE_FILE"] = os.path.join(root_dir, ".cov/coverage")
    env["COVERAGE_PROCESS_START"] = os.path.join(root_dir, "pyproject.toml")
    if args.pdb:
        env["USE_PDB"] = "1"
    env["PWNDBG_LAUNCH_TEST"] = test_case
    env["PWNDBG_DISABLE_COLORS"] = "1"
    if port is not None:
        env["QEMU_PORT"] = str(port)

    started_at = time.time()
    result = run_gdb(gdb_path, gdb_args, env=env, capture_output=not args.serial)
    duration = time.time() - started_at
    return result, test_case, duration


class TestStats:
    def __init__(self):
        self.fail_tests = 0
        self.pass_tests = 0
        self.skip_tests = 0
        self.fail_tests_names = []

    def handle_test_result(self, test_result: TEST_RETURN_TYPE, args, test_dir_path):
        (process, test_case, duration) = test_result
        if args.serial:
            # Serial mode does not capture stdout, so it's not possible to check the result
            return

        test_status = "FAIL"
        if process.returncode == 0:
            result = re.search(
                r"(\x1b\[3.m(PASSED|FAILED|SKIPPED|XPASS|XFAIL)\x1b\[0m)",
                process.stdout,
                re.MULTILINE,
            )
            if result:
                test_status = result[0]

        if "FAIL" in test_status:
            self.fail_tests += 1
            self.fail_tests_names.append(test_case)
        elif "PASS" in test_status:
            self.pass_tests += 1
        elif "SKIP" in test_status:
            self.skip_tests += 1
        print(f"{test_case:<70} {test_status} {duration:.2f}s")

        # Only show the output of failed tests unless the verbose flag was used
        if args.verbose or "FAIL" in test_status:
            print("")
            print(process.stderr)
            print(process.stdout)


def run_tests_and_print_stats(
    tests_list: List[str],
    args: argparse.Namespace,
    gdb_path: str,
    gdbinit_path: str,
    test_dir_path: str,
):
    start = time.time()
    stats = TestStats()

    if args.serial:
        for test in tests_list:
            result = run_test(test, args, gdb_path, gdbinit_path, reserve_port())
            stats.handle_test_result(result, args, test_dir_path)
    else:
        print("")
        print("Running tests in parallel")
        with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            for test in tests_list:
                executor.submit(
                    run_test, test, args, gdb_path, gdbinit_path, reserve_port()
                ).add_done_callback(
                    lambda future: stats.handle_test_result(future.result(), args, test_dir_path)
                )

    end = time.time()
    seconds = int(end - start)
    print(f"Tests completed in {seconds} seconds")
    print("")
    print("*********************************")
    print("********* TESTS SUMMARY *********")
    print("*********************************")
    print(f"Tests Passed: {stats.pass_tests}")
    print(f"Tests Skipped: {stats.skip_tests}")
    print(f"Tests Failed: {stats.fail_tests}")

    if stats.fail_tests != 0:
        print("\nFailing tests:")
        for test_case in stats.fail_tests_names:
            print(f"- {test_case}")
        sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(description="Run tests.")
    parser.add_argument("-t", "--type", dest="type", choices=["gdb", "cross-arch"], default="gdb")

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


TEST_FOLDER_NAME = {
    "gdb": "gdb-tests/tests",
    "cross-arch": "qemu-tests/tests/user",
}


def main():
    args = parse_args()
    if args.cov:
        print("Will run codecov")
    if args.pdb:
        print("Will run tests in serial and with Python debugger")
        args.serial = True

    if args.nix:
        gdbinit_path = ""
        gdb_path = os.path.join(root_dir, "result/bin/pwndbg")
        if not os.path.exists(gdb_path):
            print("ERROR: No nix-compatible pwndbg found. Run nix build .#pwndbg-dev")
            sys.exit(1)
    else:
        gdbinit_path = os.path.join(root_dir, "gdbinit.py")
        if args.type == "gdb":
            gdb_path = shutil.which("gdb")
        elif args.type == "cross-arch":
            if (gdb_multiarch := shutil.which("gdb-multiarch")) is not None:
                gdb_path = gdb_multiarch
            else:
                supports_arches = "py import os; archs = ['i386', 'aarch64', 'arm', 'mips', 'riscv', 'sparc']; os._exit(3) if len([arch for arch in archs if arch in gdb.architecture_names()]) == len(archs) else os._exit(2)"

                result = run_gdb("gdb", ["-ex", supports_arches])
                # GDB supports cross architecture targets
                if result.returncode == 3:
                    gdb_path = shutil.which("gdb")
                else:
                    raise Exception(
                        "gdb-multiarch not found, and gdb does not support cross architecture targets"
                    )

    os.environ["GDB_INIT_PATH"] = gdbinit_path
    os.environ["GDB_BIN_PATH"] = gdb_path

    test_dir_path = TEST_FOLDER_NAME[args.type]

    ensure_zig_path()

    if args.type in ("gdb", "cross-arch"):
        make_binaries(test_dir_path)
    else:
        raise NotImplementedError(args.type)

    tests_list = get_tests_list(
        args.collect_only, args.test_name_filter, gdb_path, gdbinit_path, test_dir_path
    )
    run_tests_and_print_stats(tests_list, args, gdb_path, gdbinit_path, test_dir_path)


if __name__ == "__main__":
    main()

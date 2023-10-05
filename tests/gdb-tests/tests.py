from __future__ import annotations

import argparse
import os
import re
import subprocess
from subprocess import CompletedProcess
import time
import multiprocessing
from typing import Tuple


ROOT_DIR = os.path.realpath('../../')
GDB_INIT_PATH = os.path.join(ROOT_DIR, 'gdbinit.py')
COVERAGERC_PATH = os.path.join(ROOT_DIR, 'pyproject.toml')

def ensureZigPath():
    if 'ZIGPATH' not in os.environ:
        # If ZIGPATH is not set, set it to $pwd/.zig
        # In Docker environment this should by default be set to /opt/zig
        os.environ['ZIGPATH'] = os.path.join(ROOT_DIR, '.zig')
    print(f'ZIGPATH set to {os.environ["ZIGPATH"]}')

def makeBinaries():
    try:
        subprocess.check_call(['make', 'all'], cwd='./tests/binaries')
    except subprocess.CalledProcessError:
        exit(1)


def run_gdb(gdb_args : list[str], env=None, capture_output=True) -> CompletedProcess[str]:
    # print("Running gdb with args: " + str(args))
    env = os.environ if env is None else env
    # subprocess.run(['gdb', '--batch', '-ex', 'py import coverage; print(coverage.__version__)'], check=True)
    return subprocess.run(['gdb', '--silent', '--nx', '--nh'] + gdb_args + ['--eval-command', 'quit'], env=env, capture_output=capture_output,text=True)

def getTestsList(collect_only : bool, test_name_filter : str) -> list[str]:
    # NOTE: We run tests under GDB sessions and because of some cleanup/tests dependencies problems
    # we decided to run each test in a separate GDB session
    gdb_args = ['--command', GDB_INIT_PATH, '--command', 'pytests_collect.py']
    result = run_gdb(gdb_args)
    TESTS_COLLECT_OUTPUT = result.stdout

    if result.returncode == 1:
        print(TESTS_COLLECT_OUTPUT)
        exit(1)
    elif collect_only == 1:
        print(TESTS_COLLECT_OUTPUT)
        exit(0)

    import re
    # Extract the test names from the output using regex
    pattern = re.compile(r'tests/.*::.*')
    matches = pattern.findall(TESTS_COLLECT_OUTPUT)
    TESTS_LIST = [match for match in matches if re.search(test_name_filter, match)]
    return TESTS_LIST

def run_test(test_case: str, args: argparse.Namespace) -> Tuple[CompletedProcess[str], str]:
    gdb_args = ['--command', GDB_INIT_PATH, '--command', 'pytests_launcher.py']
    if args.cov:
        print("Running with coverage")
        gdb_args = ['-ex', 'py import sys;print(sys.path);import coverage;coverage.process_startup();'] + gdb_args
    env = os.environ.copy()
    env['LC_ALL'] = 'C.UTF-8'
    env['LANG'] = 'C.UTF-8'
    env['LC_CTYPE'] = 'C.UTF-8'
    env['SRC_DIR'] = ROOT_DIR
    env['COVERAGE_FILE'] = os.path.join(ROOT_DIR, '.cov/coverage')
    env['COVERAGE_PROCESS_START'] = COVERAGERC_PATH
    if args.pdb:
        env['USE_PDB'] = "1"
    env['PWNDBG_LAUNCH_TEST'] = test_case
    env['PWNDBG_DISABLE_COLORS'] = '1'
    result = run_gdb(gdb_args, env=env, capture_output=not args.serial)
    if result.returncode == 1:
        print(result.stdout)
    # print(result.stdout)
    return (result, test_case)
    # retval = result.returncode
    # print(result.stdout, end='', flush=True)
    # print(retval)
    # if serial:
    #     exit(retval)

def parse_output_file(output_file, args: argparse.Namespace):
    with open(output_file, 'r') as f:
        content = f.read()

    # Extract the test name and result using regex
    pattern = re.compile(r'(tests/[^ ]+)|(\x1b\[3.m(PASSED|FAILED|SKIPPED|XPASS|XFAIL)\x1b\[0m)')
    matches = pattern.findall(content)
    testname, result = matches[0][0], matches[-1][2]

    testfile = testname.split('::')[0]
    testname = testname.split('::')[1]

    print(f'{testname:<70} {result}')

    # Only show the output of failed tests unless the verbose flag was used
    if args.verbose or 'FAIL' in result:
        print('')
        with open(output_file, 'r') as f:
            print(f.read())
        print('')

    if not args.keep:
        # Delete the temporary file created by `parallel`
        os.remove(output_file)
    else:
        print(output_file)

def run_tests_and_print_stats(tests_list : list[str], args : argparse.Namespace):
    start = time.time()
    test_results :list[Tuple[CompletedProcess[str], str]] = []
    if args.serial:
         test_results = [run_test(test, args) for test in tests_list]
    else:
        with multiprocessing.Pool() as pool:
            test_results = pool.starmap(run_test, [(test, args) for test in tests_list])


    # if args.serial:
    #     for t in tests_list:
    #         run_test(t, args)
    # else:
    #     with tempfile.NamedTemporaryFile(delete=False) as f:
    #         JOBLOG_PATH = f.name
    #     print("")
    #     print(f"Running tests in parallel and using a joblog in {JOBLOG_PATH}", end="")
    #     if not args.keep:
    #         print(" (use --keep it to persist it)")
    #     else:
    #         print("")

    #     # The `--env _` is required when using `--record-env`
    #     cmd1 = f'env_parallel --env _ --output-as-files --joblog {JOBLOG_PATH} run_test ::: {" ".join(TESTS_LIST)}'
    #     cmd2 = f'env_parallel --env _ parse_output_file {JOBLOG_PATH}'
    #     subprocess.run(cmd1, shell=True)
    #     subprocess.run(cmd2, shell=True)

    end = time.time()
    seconds = int(end - start)
    print(f"Tests completed in {seconds} seconds")

    # # TODO: This doesn't work with serial
    # # The seventh column in the joblog is the exit value and the tenth is the test name
    # with open(JOBLOG_PATH, 'r') as f:
    #     content = f.read()
    # FAILED_TESTS = [line.split()[9] for line in content.splitlines() if line.split()[6] == '1']

    failed_tests = [(test_result, test_case) for test_result, test_case in test_results if test_result.returncode != 0]
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
        print(f"Failing tests: {', '.join([failed_test_name for _, failed_test_name in failed_tests])}")
        exit(1)

    # if not args.keep:
    #     # Delete the temporary joblog file
    #     os.remove(JOBLOG_PATH)
    # else:
    #     print(f"Not removing the {JOBLOG_PATH} since --keep was passed")

def parse_args():
    parser = argparse.ArgumentParser(description='Run tests.')
    parser.add_argument('-p', '--pdb', action='store_true', help='enable pdb (Python debugger) post mortem debugger on failed tests')
    parser.add_argument('-c', '--cov', action='store_true', help='enable codecov')
    parser.add_argument('-v', '--verbose', action='store_true', help='display all test output instead of just failing test output')
    parser.add_argument('-k', '--keep', action='store_true', help="don't delete the temporary files containing the command output")
    parser.add_argument('-s', '--serial', action='store_true', help='run tests one at a time instead of in parallel')
    parser.add_argument('--collect-only', action='store_true', help='only show the output of test collection, don\'t run any tests')
    parser.add_argument('test_name_filter', nargs='?', help='run only tests that match the regex', default='.*')
    return parser.parse_args()
if __name__ == '__main__':
    # TODO: --pdb implies --serial
    args = parse_args()
    if args.cov:
        print("Will run codecov")
    if args.pdb:
        print("Will run tests in serial and with Python debugger")
        args.serial = True
    if args.serial and args.keep:
        print("--keep and --serial is incompatible")
        exit(1)
    print(args)
    ensureZigPath()
    makeBinaries()
    tests: list[str] = getTestsList(args.collect_only, args.test_name_filter)
    # print(tests)
    # run_test(tests[0], args.cov, args.pdb)
    run_tests_and_print_stats(tests, args)
import gdb

import tests

REFERENCE_BINARY_THREADS = tests.binaries.get("multiple_threads.out")


def test_command_killthreads_kills_all_threads_except_current(start_binary):
    start_binary(REFERENCE_BINARY_THREADS)

    gdb.execute("break break_here")
    gdb.execute("run")
    assert len(gdb.selected_inferior().threads()) != 1

    gdb.execute("killthreads --all")

    # check if only one thread is left
    assert len(gdb.selected_inferior().threads()) == 1

    gdb.execute("continue")
    exit_code = gdb.execute("print $_exitcode", to_string=True)
    assert exit_code == "$1 = 0\n"  # if the second thread was killed, the exit code should be 0


def test_command_killthreads_kills_specific_thread(start_binary):
    start_binary(REFERENCE_BINARY_THREADS)

    gdb.execute("break break_here")
    gdb.execute("run")
    initial_thread_count = len(gdb.selected_inferior().threads())
    # check if thread with id 3 exists
    assert len([thread for thread in gdb.selected_inferior().threads() if thread.num == 3]) == 1

    gdb.execute("killthreads 3")

    # check if the thread was killed, and no other thread was killed
    assert len([thread for thread in gdb.selected_inferior().threads() if thread.num == 3]) == 0
    assert len(gdb.selected_inferior().threads()) == initial_thread_count - 1

    gdb.execute("kill")


def test_command_killthreads_before_binary_start():
    result = gdb.execute("killthreads", to_string=True)
    assert "The program is not being run" in result

from __future__ import annotations

import gdb

import pwndbg

from . import get_binary

REFERENCE_BINARY_THREADS = get_binary("multiple_threads.native.out")


def thread_ids() -> list[int]:
    # The inferior is stopped and GDB only prunes the thread list while it processes
    # target events, so this is final until we resume the inferior again.
    return [thread.index() for thread in pwndbg.dbg.selected_inferior().threads()]


def test_command_killthreads_kills_all_threads_except_current(start_binary):
    start_binary(REFERENCE_BINARY_THREADS)

    gdb.execute("break break_here")
    gdb.execute("run")
    assert thread_ids() == [1, 2, 3]

    gdb.execute("killthreads --all")

    # check if only one thread is left
    assert thread_ids() == [1]


def test_command_killthreads_kills_specific_thread(start_binary):
    start_binary(REFERENCE_BINARY_THREADS)

    gdb.execute("break break_here")
    gdb.execute("run")
    initial_thread_count = len(thread_ids())
    # check if thread with id 3 exists
    assert 3 in thread_ids()

    gdb.execute("killthreads 3")

    # check if the thread was killed, and no other thread was killed
    assert 3 not in thread_ids()
    assert len(thread_ids()) == initial_thread_count - 1

    gdb.execute("kill")


def test_command_killthreads_produces_error_when_unknown_thread_passed(start_binary):
    start_binary(REFERENCE_BINARY_THREADS)

    gdb.execute("break break_here")
    gdb.execute("run")
    # check if thread with id 3 exists
    assert (
        len([thread for thread in pwndbg.dbg.selected_inferior().threads() if thread.index() == 3])
        == 1
    )

    out = gdb.execute("killthreads 999", to_string=True)
    assert "Thread ID 999 does not exist" in out

    gdb.execute("kill")


def test_command_killthreads_before_binary_start():
    result = gdb.execute("killthreads", to_string=True)
    assert "The program is not being run" in result

from __future__ import annotations

import time

import gdb

import pwndbg.dbg
import tests

REFERENCE_BINARY_THREADS = tests.binaries.get("multiple_threads.out")


def wait_until(predicate: callable, timeout: int = 10):
    """
    Waits until the predicate returns True or timeout is reached.
    """
    counter = 0
    while True:
        if predicate():
            return True
        time.sleep(0.1)
        counter += 0.1
        if counter > timeout:
            assert False, "Timeout reached"


def test_command_killthreads_kills_all_threads_except_current(start_binary):
    start_binary(REFERENCE_BINARY_THREADS)

    gdb.execute("break break_here")
    gdb.execute("run")
    wait_until(lambda: len(pwndbg.dbg.selected_inferior().threads()) == 3)

    gdb.execute("killthreads --all")

    # check if only one thread is left
    wait_until(lambda: len(pwndbg.dbg.selected_inferior().threads()) == 1)


def test_command_killthreads_kills_specific_thread(start_binary):
    start_binary(REFERENCE_BINARY_THREADS)

    gdb.execute("break break_here")
    gdb.execute("run")
    initial_thread_count = len(pwndbg.dbg.selected_inferior().threads())
    # check if thread with id 3 exists
    wait_until(
        lambda: len(
            [thread for thread in pwndbg.dbg.selected_inferior().threads() if thread.index() == 3]
        )
        == 1
    )
    gdb.execute("killthreads 3")
    # check if the thread was killed, and no other thread was killed
    wait_until(
        lambda: len(
            [thread for thread in pwndbg.dbg.selected_inferior().threads() if thread.index() == 3]
        )
        == 0
    )
    assert len(pwndbg.dbg.selected_inferior().threads()) == initial_thread_count - 1

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

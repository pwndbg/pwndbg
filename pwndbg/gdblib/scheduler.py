from contextlib import contextmanager

import gdb


@contextmanager
def lock_scheduler():
    old_config = gdb.parameter("scheduler-locking")
    if old_config != "on":
        gdb.execute("set scheduler-locking on")
        yield
        gdb.execute("set scheduler-locking %s" % old_config)
    else:
        yield


def parse_and_eval_with_scheduler_lock(expr: str) -> gdb.Value:
    with lock_scheduler():
        return gdb.parse_and_eval(expr)

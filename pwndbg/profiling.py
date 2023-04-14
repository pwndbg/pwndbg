import cProfile
import time
from typing import Optional

profiler = None


def init(p: cProfile.Profile, _start_time: Optional[float]) -> None:
    global profiler
    profiler = Profiler(p)
    profiler._start_time = _start_time


class Profiler:
    def __init__(self, p: cProfile.Profile) -> None:
        self._profiler = p
        self._start_time: Optional[float] = None

    def print_time_elapsed(self):
        assert self._start_time is not None
        return print("Time Elapsed:", time.time() - self._start_time)

    def start(self) -> None:
        self._start_time = time.time()
        self._profiler.enable()

    def stop(self, filename=None) -> None:
        if not filename:
            filename = f"pwndbg-{int(time.time())}.pstats"

        self.print_time_elapsed()
        self._profiler.disable()
        self._start_time = None

        self._profiler.dump_stats(filename)

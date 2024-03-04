from __future__ import annotations

import cProfile
import time

profiler: Profiler | None = None


def init(p: cProfile.Profile, _start_time: float | None) -> None:
    global profiler
    profiler = Profiler(p)
    profiler._start_time = _start_time


class Profiler:
    def __init__(self, p: cProfile.Profile) -> None:
        self._profiler = p
        self._start_time: float | None = None

    def print_time_elapsed(self) -> None:
        assert self._start_time is not None
        print("Time Elapsed:", time.time() - self._start_time)

    def start(self) -> None:
        self._start_time = time.time()
        self._profiler.enable()

    def stop(self, filename: str | None = None) -> None:
        if not filename:
            filename = f"pwndbg-{int(time.time())}.pstats"

        self.print_time_elapsed()
        self._profiler.disable()
        self._start_time = None

        self._profiler.dump_stats(filename)

"""
Utilities for profiling pwndbg.
"""

from __future__ import annotations

import argparse

import pwndbg.profiling
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Utilities for profiling pwndbg.")
subparsers = parser.add_subparsers(dest="command")
parser_start = subparsers.add_parser("start", prog="profiler start")
parser_stop = subparsers.add_parser("stop", prog="profiler stop")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.PWNDBG)
def profiler(command) -> None:
    if command == "start":
        print("Starting profiler.")
        pwndbg.profiling.profiler.start()
    elif command == "stop":
        fname = "pwndbg.pstats"
        print("Stopped profiler. Wrote results to", fname)
        pwndbg.profiling.profiler.stop(fname)

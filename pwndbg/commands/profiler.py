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
parser_stop.add_argument(
    "--file", type=str, default="pwndbg.pstats", help="Output file for profile data."
)


@pwndbg.commands.Command(parser, category=CommandCategory.PWNDBG)
def profiler(command, file="pwndbg.pstats") -> None:
    if command == "start":
        print("Starting profiler.")
        pwndbg.profiling.profiler.start()
    elif command == "stop":
        print("Stopped profiler. Wrote results to", file)
        print(
            "To analyze the results, use the ./profiling/print_stats.py script in the pwndbg repo."
        )
        pwndbg.profiling.profiler.stop(file)

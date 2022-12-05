#!/usr/bin/env python3

import pstats
from argparse import ArgumentParser


def parse_args():
    parser = ArgumentParser(description="Print the profiling stats from a pstats file")
    parser.add_argument("-n", "--num", type=int, help="number of stats to print")
    parser.add_argument("-f", "--filter", help="regex to match against each entry")
    parser.add_argument(
        "--no-strip", action="store_true", help="print the entire file path for each entry"
    )
    parser.add_argument("file", help="pstats file to parse")
    parser.add_argument(
        "-s",
        "--sort",
        choices=["calls", "ncalls", "cumulative", "time"],
        default="cumulative",
    )

    return parser.parse_args()


def main():
    args = parse_args()
    s = pstats.Stats(args.file)
    if not args.no_strip:
        s.strip_dirs()
    s.sort_stats(args.sort).print_stats(args.filter, args.num)


if __name__ == "__main__":
    main()

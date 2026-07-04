from __future__ import annotations

import argparse

import pwndbg
import pwndbg.aglib
from pwndbg.color import generate_color_function
from pwndbg.commands import CommandCategory, fix_int_reraise_arg

parser = argparse.ArgumentParser(
    description="""Visualize stack frames of the current thread.

Each frame is annotated with the name of the function to which it belongs.
Repeated lines can be collapsed by setting 'vis-skip-repeating-val' config (on by default)."""
)
group = parser.add_mutually_exclusive_group()
group.add_argument(
    "count",
    nargs="?",
    type=lambda n: max(fix_int_reraise_arg(n, 0), 1),
    default=pwndbg.config.default_visualize_chunk_number,
    help="Number of frames to visualize.",
)
parser.add_argument(
    "--no-skip",
    "-s",
    action="store_true",
    default=False,
    help="Don't skip repeating vals (Ignore the `visp-skip-repeating-val` configuration).",
)
parser.add_argument(
    "--no-truncate",
    "-n",
    action="store_true",
    default=False,
    help="Display all the frame contents (Ignore the `max-visualize-chunk-size` configuration).",
)
group.add_argument(
    "--all-frames",
    "-a",
    action="store_true",
    default=False,
    help="Display all frames.",
)


@pwndbg.commands.Command(parser, category=CommandCategory.STACK)
@pwndbg.commands.OnlyWhenRunning
def stack_vis(
    count: int | None = None,
    no_skip: bool = False,
    no_truncate: bool = False,
    all_frames: bool = False,
) -> None:
    color_funcs = [
        generate_color_function("yellow"),
        generate_color_function("cyan"),
        generate_color_function("purple"),
        generate_color_function("green"),
        generate_color_function("blue"),
    ]

    ptr_size = pwndbg.aglib.arch.ptrsize

    frame = pwndbg.dbg.selected_frame()

    frame_delims = []
    labels_map = {}

    start = None
    low_addr = None
    high_addr = None

    c = 0
    while True:
        if not all_frames and c == count:
            break

        if frame is None:
            break

        low_addr = frame.sp()
        if high_addr is not None:
            # For some reason, it can happen that GDB reports 2 consecutive frames with the same SP and start,
            # e.g., when calling `pthread_cond_wait`
            low_addr = max(low_addr, high_addr)
        high_addr = frame.start()

        if low_addr == high_addr:
            frame = frame.parent()
            continue

        high_addr = max(high_addr, low_addr)

        if c == 0:
            start = low_addr

        frame_delims.append(high_addr + ptr_size)

        pc = frame.pc()
        symbol = pwndbg.aglib.symbol.resolve_addr(pc)
        if symbol:
            labels_map[low_addr] = [symbol]

        c += 1
        frame = frame.parent()

    pwndbg.aglib.memory.pprint_blocks(
        start=start,
        block_delims=frame_delims,
        color_funcs=color_funcs,
        labels_map=labels_map,
        cell_size=ptr_size,
        no_truncate=no_truncate,
        no_skip=no_skip,
    )

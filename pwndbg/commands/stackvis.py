from __future__ import annotations

import argparse

import pwndbg
import pwndbg.aglib
import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.commands
from pwndbg.color import generate_color_function
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="""Visualize stack frames of the current thread.

Each frame is annotated with the name of the function to which it belongs.
Repeated lines can be collapsed by setting 'vis-skip-repeating-val' config (on by default)."""
)
group = parser.add_mutually_exclusive_group()
group.add_argument(
    "count",
    nargs="?",
    type=int,
    default=None,
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
    if count is None:
        count = int(pwndbg.config.default_visualize_chunk_number)

    if count < 1:
        print(message.error("Count needs to be a positive number."))
        return

    frame = pwndbg.dbg.selected_frame()
    if frame is None:
        print(message.error("Could not find frame."))
        return

    color_funcs = [
        generate_color_function("yellow"),
        generate_color_function("cyan"),
        generate_color_function("purple"),
        generate_color_function("green"),
        generate_color_function("blue"),
    ]

    ptr_size = pwndbg.aglib.arch.ptrsize

    frame_delims = []
    labels_map = {}

    start: int | None = None
    # low_addr means frame.sp() means smaller addresses means higher in our tele
    low_addr: int = -1
    high_addr: int | None = None

    c = 0
    while True:
        if frame is None:
            break

        if c == count and not all_frames:
            break

        prev_low_addr = low_addr
        low_addr = frame.sp()
        high_addr = frame.start()

        # Usually you will have something like
        #   frame.sp()             = 0x7ffff7bfee30
        #   frame.start()          = 0x7ffff7bfee38
        #   frame.parent().sp()    = 0x7ffff7bfee40 (/\ 8 byte difference here)
        #   frame.parent().start() = 0x7ffff7bfee58

        if low_addr == prev_low_addr:
            # For some reason, it can happen that GDB reports 2 consecutive frames with the same SP and start,
            # e.g., when calling `pthread_cond_wait`
            # In this case, we just omit the second frame
            # FIXME: add a test for this
            continue

        if low_addr == high_addr and c == 0:
            # We are likely in the prologue of a function before it sets
            # up the stack frame.
            continue

        if low_addr == high_addr:
            # FIXME: I feel like this can happen but idk how to repro, I guess
            # i'll just skip until we figure it out...
            # FIXME: add test
            continue

        if high_addr is None:
            # I think this can only happen on the top-most frame, so we are kind of
            # gucci, but idk
            # FIXME: add test
            high_addr = low_addr

        if c == 0:
            # mark start of dump
            start = low_addr

        frame_delims.append(high_addr + ptr_size)

        pc = frame.pc()
        symbol = pwndbg.aglib.symbol.resolve_addr(pc)
        if symbol:
            labels_map[low_addr] = [symbol]

        c += 1
        frame = frame.parent()

    assert start is not None, "bug in stack_vis(), did not execute any iterations?"

    pwndbg.aglib.memory.pprint_blocks(
        start=start,
        block_delims=frame_delims,
        color_funcs=color_funcs,
        labels_map=labels_map,
        cell_size=ptr_size,
        no_truncate=no_truncate,
        no_skip=no_skip,
    )

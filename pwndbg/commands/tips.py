from __future__ import annotations

import argparse

import pwndbg.commands
from pwndbg.lib.tips import TIPS
from pwndbg.lib.tips import color_tip
from pwndbg.lib.tips import get_tip_of_the_day

parser = argparse.ArgumentParser(description="Shows tips.")
parser.add_argument("-a", "--all", action="store_true", help="Show all tips.")


@pwndbg.commands.ArgparsedCommand(parser)
def tips(all: bool) -> None:
    if all:
        for tip in TIPS:
            print(color_tip(tip))
    else:
        print(color_tip(get_tip_of_the_day()))

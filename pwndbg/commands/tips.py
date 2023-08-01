from __future__ import annotations

import argparse
import re

import pwndbg.commands
from pwndbg.color import message
from pwndbg.lib.tips import TIPS
from pwndbg.lib.tips import get_tip_of_the_day

parser = argparse.ArgumentParser(description="Shows tips.")
parser.add_argument("--all", action="store_true", help="Show all tips.")


@pwndbg.commands.ArgparsedCommand(parser)
def tips(all: bool) -> None:
    if all:
        for tip in TIPS:
            print(__color_tip(tip))
    else:
        print(__color_tip(get_tip_of_the_day()))


def __color_tip(tip: str) -> str:
    return re.sub("`(.*?)`", lambda s: message.warn(s.group()[1:-1]), get_tip_of_the_day())

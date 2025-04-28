from __future__ import annotations

import argparse

import pwndbg.commands
import pwndbg.lib.cache
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="""
Toggles memoization (caching).

Useful for diagnosing caching-related bugs. Decreases performance.
""",
)


@pwndbg.commands.Command(parser, category=CommandCategory.PWNDBG)
def memoize() -> None:
    pwndbg.lib.cache.IS_CACHING = not pwndbg.lib.cache.IS_CACHING

    status = message.off("OFF (pwndbg will work slower, use only for debugging pwndbg)")
    if pwndbg.lib.cache.IS_CACHING:
        status = message.on("ON")

    print(f"Caching is now {status}")

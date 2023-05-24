import argparse

import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""
Toggles memoization (caching).

Useful for diagnosing caching-related bugs. Decreases performance.
""",
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.PWNDBG)
def memoize() -> None:
    pwndbg.lib.cache.IS_CACHING = not pwndbg.lib.cache.IS_CACHING

    status = message.off("OFF (pwndbg will work slower, use only for debugging pwndbg)")
    if pwndbg.lib.cache.IS_CACHING:
        status = message.on("ON")

    print(f"Caching is now {status}")

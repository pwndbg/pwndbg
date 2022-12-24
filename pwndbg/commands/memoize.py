import argparse

import pwndbg.commands
from pwndbg.color import message

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""
Toggles memoization (caching).

Useful for diagnosing caching-related bugs. Decreases performance.
""",
)


@pwndbg.commands.ArgparsedCommand(parser)
def memoize():
    pwndbg.lib.memoize.memoize.caching = not pwndbg.lib.memoize.memoize.caching

    status = message.off("OFF (pwndbg will work slower, use only for debugging pwndbg)")
    if pwndbg.lib.memoize.memoize.caching:
        status = message.on("ON")

    print("Caching is now %s" % status)

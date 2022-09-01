import argparse

import pwndbg.commands
from pwndbg.color import message

parser = argparse.ArgumentParser(
    description="""
Toggles memoization (caching). Pwndbg will work slower when it's off, however
it's useful for diagnosing caching-related bugs.
"""
)


@pwndbg.commands.ArgparsedCommand(parser)
def memoize():
    pwndbg.lib.memoize.memoize.caching = not pwndbg.lib.memoize.memoize.caching

    status = message.off("OFF (pwndbg will work slower, use only for debugging pwndbg)")
    if pwndbg.lib.memoize.memoize.caching:
        status = message.on("ON")

    print("Caching is now %s" % status)

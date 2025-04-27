from __future__ import annotations

import functools
import sys
import traceback

import pwndbg.lib.cache
import pwndbg.lib.stdio
from pwndbg import config
from pwndbg.color import message

try:
    import ipdb as pdb
except ImportError:
    import pdb

_rich_console = None


def print_exception(exception_msg) -> None:
    global _rich_console

    if _rich_console is None:
        try:
            from rich.console import Console

            _rich_console = Console()
        except ImportError:
            _rich_console = ...

    if not isinstance(_rich_console, type(Ellipsis)):
        _rich_console.print_exception()
    else:
        print(exception_msg)


verbose = config.add_param(
    "exception-verbose",
    False,
    "print a full stacktrace for exceptions raised in pwndbg commands",
)
debug = config.add_param(
    "exception-debugger", False, "whether to debug exceptions raised in Pwndbg commands"
)


def inform_unmet_dependencies(errors) -> None:
    """
    Informs user about unmet dependencies
    """
    import pkg_resources

    msg = message.error("You appear to have unmet Pwndbg dependencies.\n")
    for e in errors:
        if isinstance(e, pkg_resources.DistributionNotFound):
            msg += message.notice(f"- required {e.args[0]}, but not installed\n")
        else:
            msg += message.notice(f"- required {e.args[1]}, installed: {e.args[0]}\n")
    msg += message.notice("Consider running: ")
    msg += message.hint("`setup.sh` ")
    msg += message.notice("from Pwndbg project directory.\n")
    print(msg)


@pwndbg.lib.cache.cache_until("forever")
def inform_report_issue(exception_msg) -> None:
    """
    Informs user that he can report an issue.
    The use of caching makes it reporting only once for a given exception message.
    """
    print(
        message.notice(
            "If that is an issue, you can report it on https://github.com/pwndbg/pwndbg/issues\n"
            "(Please don't forget to search if it hasn't been reported before)\n"
            "To generate the report and open a browser, you may run "
        )
        + message.hint("`bugreport --run-browser`")
        + message.notice("\nPS: Pull requests are welcome")
    )


def inform_verbose_and_debug() -> None:
    print(
        message.notice("For more info invoke `")
        + message.hint("set exception-verbose on")
        + message.notice("` and rerun the command\nor debug it by yourself with `")
        + message.hint("set exception-debugger on")
        + message.notice("`")
    )


def handle(name="Error"):
    """Displays an exception to the user, optionally displaying a full traceback
    and spawning an interactive post-moretem debugger.

    Notes:
        - ``set exception-verbose on`` enables stack traces.
        - ``set exception-debugger on`` enables the post-mortem debugger.
    """

    # This is for unit tests so they fail on exceptions instead of displaying them.
    if getattr(sys, "_pwndbg_unittest_run", False) is True:
        E, V, T = sys.exc_info()
        e = E(V)
        e.__traceback__ = T
        raise e

    # Display the error
    if debug or verbose:
        exception_msg = traceback.format_exc()
        print_exception(exception_msg)
        inform_report_issue(exception_msg)

    else:
        exc_type, exc_value, exc_traceback = sys.exc_info()

        print(message.error(f"Exception occurred: {name}: {exc_value} ({exc_type})"))

        inform_verbose_and_debug()

    # Break into the interactive debugger
    if debug:
        with pwndbg.lib.stdio.stdio:
            pdb.post_mortem()


@functools.wraps(pdb.set_trace)
def set_trace() -> None:
    """Enable sane debugging in Pwndbg by switching to the "real" stdio."""
    debugger = pdb.Pdb(
        stdin=sys.__stdin__, stdout=sys.__stdout__, skip=["pwndbg.lib.stdio", "pwndbg.exception"]
    )
    debugger.set_trace()


pdb.set_trace = set_trace


@config.trigger(verbose, debug)
def update() -> None:
    enable = verbose or debug
    pwndbg.dbg.set_python_diagnostics(bool(enable))

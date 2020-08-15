#!/usr/bin/env python
# -*- coding: utf-8 -*-

import functools
import pdb
import sys
import traceback

import gdb

import pwndbg.color.message as message
import pwndbg.config
import pwndbg.memoize
import pwndbg.stdio

try:
    import ipdb as pdb
except ImportError:
    pass

verbose = pwndbg.config.Parameter('exception-verbose', False, 'whether to print a full stacktrace for exceptions raised in Pwndbg commands')
debug = pwndbg.config.Parameter('exception-debugger', False, 'whether to debug exceptions raised in Pwndbg commands')


@pwndbg.memoize.forever
def inform_report_issue(exception_msg):
    """
    Informs user that he can report an issue.
    The use of `memoize` makes it reporting only once for a given exception message.
    """
    print(message.notice(
        "If that is an issue, you can report it on https://github.com/pwndbg/pwndbg/issues\n"
        "(Please don't forget to search if it hasn't been reported before)\n"
        "To generate the report and open a browser, you may run ") +
        message.hint("`bugreport --run-browser`") +
        message.notice("\nPS: Pull requests are welcome")
    )


def handle(name='Error'):
    """Displays an exception to the user, optionally displaying a full traceback
    and spawning an interactive post-moretem debugger.

    Notes:
        - ``set exception-verbose on`` enables stack traces.
        - ``set exception-debugger on`` enables the post-mortem debugger.
    """

    # This is for unit tests so they fail on exceptions instead of displaying them.
    if getattr(sys, '_pwndbg_unittest_run', False) is True:
        E, V, T = sys.exc_info()
        e = E(V)
        e.__traceback__ = T
        raise e

    # Display the error
    if debug or verbose:
        exception_msg = traceback.format_exc()
        print(exception_msg)
        inform_report_issue(exception_msg)

    else:
        exc_type, exc_value, exc_traceback = sys.exc_info()

        print(message.error('Exception occurred: {}: {} ({})'.format(name, exc_value, exc_type)))

        print(message.notice('For more info invoke `') +
              message.hint('set exception-verbose on') +
              message.notice('` and rerun the command\nor debug it by yourself with `') +
              message.hint('set exception-debugger on') +
              message.notice('`'))

    # Break into the interactive debugger
    if debug:
        with pwndbg.stdio.stdio:
            pdb.post_mortem()


@functools.wraps(pdb.set_trace)
def set_trace():
    """Enable sane debugging in Pwndbg by switching to the "real" stdio.
    """
    debugger = pdb.Pdb(stdin=sys.__stdin__,
                       stdout=sys.__stdout__,
                       skip=['pwndbg.stdio', 'pwndbg.exception'])
    debugger.set_trace()

pdb.set_trace = set_trace


@pwndbg.config.Trigger([verbose, debug])
def update():
    if verbose or debug:
        command = 'set python print-stack full'
    else:
        command = 'set python print-stack message'

    gdb.execute(command, from_tty=True, to_string=True)

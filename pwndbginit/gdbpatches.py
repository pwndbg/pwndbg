from __future__ import annotations

import importlib.abc
import os
import sys
import traceback

import gdb


def fix_exit():
    major_ver = int(gdb.VERSION.split(".")[0])
    if major_ver <= 15:
        # On certain verions of gdb (used on ubuntu 24.04) using sys.exit() can cause
        # a segfault. See:
        # https://github.com/pwndbg/pwndbg/pull/2900#issuecomment-2825456636
        # https://sourceware.org/bugzilla/show_bug.cgi?id=31946
        def _patched_exit(exit_code):
            # argparse requires a SystemExit exception, otherwise our CLI commands will exit incorrectly on invalid arguments
            stack_list = traceback.extract_stack(limit=2)
            if len(stack_list) == 2:
                p = stack_list[0]
                if p.filename.endswith("/argparse.py"):
                    raise SystemExit()

            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(exit_code)

        sys.exit = _patched_exit


def fix_stdout():
    # Add the original stdout methods back to gdb._GdbOutputFile for pwnlib colors
    sys.stdout.isatty = sys.__stdout__.isatty
    sys.stdout.fileno = sys.__stdout__.fileno


def fix_readline():
    # Fix gdb readline bug: https://github.com/pwndbg/pwndbg/issues/2232#issuecomment-2542564965
    class GdbRemoveReadlineFinder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname == "readline":
                raise ImportError("readline module disabled under GDB")
            return None

    sys.meta_path.insert(0, GdbRemoveReadlineFinder())


fix_stdout()
fix_readline()
fix_exit()

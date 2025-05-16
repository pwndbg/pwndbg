#!/usr/bin/env python
"""
If the PWNDBG_DOCGEN_VERIFY environment variable
is set, then    : Exit with non-zero exit status if the docs/commands/ files
                  aren't up to date with the sources. Don't modify anything.

If it isn't, this fixes up the docs/commands/ files to be up
to date with the (argparse) information from the sources.
"""

from __future__ import annotations

import os

# We need to patch shutil.get_terminal_size() because otherwise argparse will output
# .format_usage() based on terminal width which may be different for different users.
# I tried every other solution, it doesn't work :).
import shutil
from dataclasses import asdict

shutil.get_terminal_size = lambda fallback=(80, 24): os.terminal_size((80, 24))

import json
import sys
from typing import Tuple

import pwndbg.commands
from pwndbg.commands import CommandObj
from scripts._docs.command_docs_common import BASE_PATH
from scripts._docs.command_docs_common import ExtractedCommand
from scripts._docs.command_docs_common import category_to_folder_name
from scripts._docs.command_docs_common import extracted_filename
from scripts._docs.gen_docs_generic import get_debugger


def extract_commands() -> list[CommandObj]:
    """
    Extract the commands.

    Returns:
        A list of all CommandObj objects that this debugger can see.
    """
    commandobjs: list[CommandObj] = []

    # This depends on pwndbg.commands.load_commands()
    # `obj` iterates over all modules in pwndbg.commands (among other stuff).
    for obj_name in dir(pwndbg.commands):
        # Get the (potential) module by name.
        mod = getattr(pwndbg.commands, obj_name)

        # Iterate over everything in the module, which includes the command functions.
        for thing_name in dir(mod):
            cmdobj = getattr(mod, thing_name)

            if not isinstance(cmdobj, pwndbg.commands.CommandObj):
                continue

            # This object is a command!
            commandobjs.append(cmdobj)

    assert commandobjs
    return commandobjs


def distill_sources(commandobjs: list[CommandObj]) -> list[ExtractedCommand]:
    extracted: list[ExtractedCommand] = []
    for cmdobj in commandobjs:
        name = cmdobj.command_name
        category = cmdobj.category

        cat_folder = category_to_folder_name(category)
        filename = os.path.join(BASE_PATH, cat_folder, f"{name}.md")

        description = cmdobj.description
        if not description:
            print(f"ERROR: Command {name} ({filename}) does not have a description.")
            sys.exit(5)

        aliases = cmdobj.aliases
        examples = cmdobj.examples
        notes = cmdobj.notes
        pure_epilog = cmdobj.pure_epilog

        # Extract data from the parser
        parser = cmdobj.parser
        formatter = parser._get_formatter()

        usage = parser.format_usage()

        used_actions = {}

        # positional arguments
        # [(argument name, argument help)]
        positionals: list[Tuple[str, str]] = []

        if parser._positionals._group_actions:
            for action in parser._positionals._group_actions:
                this_id = id(action)
                if this_id in used_actions:
                    continue

                # The formatter decides if the default should be shown.
                param_help = formatter._expand_help(action)

                positionals.append((action.dest, param_help))
                used_actions[this_id] = True

        # option arguments
        # [(short name, long name, argument help)]
        optionals: list[Tuple[str, str, str]] = []

        if parser._option_string_actions:
            for k in parser._option_string_actions:
                action = parser._option_string_actions[k]
                this_id = id(action)
                if this_id in used_actions:
                    continue

                short_name = ""
                long_name = ""
                for opt in action.option_strings:
                    # --, long option
                    if len(opt) > 1 and opt[1] in parser.prefix_chars:
                        long_name = opt
                    # short opt
                    elif len(opt) > 0 and opt[0] in parser.prefix_chars:
                        short_name = opt

                # The formatter decides if the default should be shown.
                param_help = formatter._expand_help(action)

                optionals.append((short_name, long_name, param_help))
                used_actions[this_id] = True

        # Construct and append the final result
        extracted.append(
            ExtractedCommand(
                name,
                category,
                filename,
                description,
                aliases,
                examples,
                notes,
                pure_epilog,
                usage,
                positionals,
                optionals,
            )
        )

    return extracted


def main():
    print("\n== Extracting Commands ==")

    debugger = get_debugger()

    commandobjs = extract_commands()
    extracted = distill_sources(commandobjs)

    result = {}
    for c in extracted:
        # We do a mapping instead of a simple
        # list of objects so we can construct the index
        # later easily. TODO: can we just do list?
        result[c.filename] = asdict(c)

    # Write to file.
    out_path = extracted_filename(debugger)
    with open(out_path, "w") as file:
        json.dump(result, file)

    print("== Finished Extracting Commands ==")


# Since lldb's `command script import ...` doesn't
# actually run the file like gdb's `source ...`, we can't
# use the __name__ == "__main__" guard.
main()

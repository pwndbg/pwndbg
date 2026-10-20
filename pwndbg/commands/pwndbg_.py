from __future__ import annotations

import argparse
from collections import defaultdict

import pwndbg.commands
from pwndbg import color
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Prints out a list of all Pwndbg commands.")

cat_group = parser.add_mutually_exclusive_group()
cat_group.add_argument(
    "-c", "--category", type=str, default=None, dest="category_", help="Filter commands by category"
)
cat_group.add_argument(
    "--list-categories", dest="list_categories", action="store_true", help="List command categories"
)

parser.add_argument(
    "filter_pattern",
    type=str,
    nargs="?",
    default=None,
    help="Filter to apply to commands names/docs",
)


@pwndbg.commands.Command(parser, command_name="pwndbg", category=CommandCategory.PWNDBG)
def pwndbg_(filter_pattern, category_, list_categories) -> None:
    if list_categories:
        for category in CommandCategory:
            print(color.bold(color.green(f"{category.value}")))
        return

    from tabulate import tabulate

    table_data = defaultdict(list)
    for name, aliases, category, docs in list_and_filter_commands(filter_pattern):
        alias_str = ""
        if aliases:
            aliases = map(color.blue, aliases)
            alias_str = f" [{', '.join(aliases)}]"

        command_names = color.green(name) + alias_str
        table_data[category].append((command_names, docs))

    for category in CommandCategory:
        if category not in table_data or category_ and category_.lower() not in category.lower():
            continue
        data = table_data[category]

        category_header = color.bold(color.green(category + " Commands"))
        alias_header = color.bold(color.blue("Aliases"))
        print(
            tabulate(
                data,
                headers=[f"{category_header} [{alias_header}]", f"{color.bold('Description')}"],
            )
        )
        print()

    print(message.info("Also check out convenience functions with `help function`!"))


def list_and_filter_commands(filter_str: str) -> list[tuple[str, list[str], CommandCategory, str]]:
    """
    Returns:
        A list of (name, aliases, category, description) tuples.
    """
    sorted_commands = sorted(pwndbg.commands.commands, key=lambda c: c.command_name)

    if filter_str:
        filter_str = filter_str.lower()

    results = []

    for c in sorted_commands:
        name = c.command_name
        desc = c.description

        assert desc
        desc = desc.splitlines()[0]

        if not filter_str or filter_str in name.lower() or (desc and filter_str in desc.lower()):
            results.append((name, c.aliases, c.category, desc))

    return results

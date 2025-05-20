"""
Dumps all pwndbg-specific configuration points.
"""

from __future__ import annotations

import argparse

import pwndbg
import pwndbg.commands
import pwndbg.lib.config
from pwndbg.color import generateColorFunction
from pwndbg.color import ljust_colored
from pwndbg.color import strip
from pwndbg.color.message import hint
from pwndbg.commands import CommandCategory
from pwndbg.lib.config import Scope

if pwndbg.dbg.is_gdblib_available():
    import pwndbg.gdblib.config


def print_row(
    name: str,
    value: str,
    default: str,
    set_show_doc: str,
    ljust_optname: int,
    ljust_doc: int,
    empty_space: int = 2,
):
    name = ljust_colored(name, ljust_optname + empty_space)
    set_show_doc = ljust_colored(set_show_doc, ljust_doc + empty_space)
    defval = extend_value_with_default(value, default)
    result = f"{name} {set_show_doc} {defval} "
    print(result)
    return result


def extend_value_with_default(value, default):
    if strip(value) != strip(default):
        return f"{value} ({default})"
    return value


def get_config_parameters(scope: Scope, filter_pattern: str):
    values = [
        v
        for k, v in pwndbg.config.params.items()
        if isinstance(v, pwndbg.lib.config.Parameter) and v.scope == scope
    ]

    if filter_pattern:
        filter_pattern = filter_pattern.lower()
        values = [
            v
            for v in values
            if filter_pattern in v.name.lower() or filter_pattern in v.set_show_doc.lower()
        ]

    return values


parser = argparse.ArgumentParser(description="Shows pwndbg-specific configuration.")
parser.add_argument(
    "filter_pattern",
    type=str,
    nargs="?",
    default=None,
    help="Filter to apply to config parameters names/descriptions",
)


def display_config(filter_pattern: str, scope: Scope, has_file_command: bool = True) -> None:
    values = get_config_parameters(scope, filter_pattern)

    if not values:
        print(hint(f'No {scope.name} parameter found with filter "{filter_pattern}"'))
        return

    longest_optname = max(map(len, (v.name for v in values)))
    longest_doc = max(map(len, (v.set_show_doc for v in values)))

    header = print_row("Name", "Value", "Default", "Documentation", longest_optname, longest_doc)
    print("-" * len(header))

    for v in sorted(values):
        if isinstance(v, pwndbg.color.theme.ColorParameter):
            # Only the theme scope should use ColorParameter
            assert scope == Scope.theme

            value = generateColorFunction(v.value)(v.value)
            default = generateColorFunction(v.default)(v.default)
        else:
            value = v.pretty()
            default = v.pretty_default()

        print_row(v.name, value, default, v.set_show_doc, longest_optname, longest_doc)

    print(
        hint(
            f"You can set a {scope.name} variable with `set <{scope.name}-var> <value>`, and read more about it with `help set <{scope.name}-var>`."
        )
    )
    if has_file_command:
        print(
            hint(
                f"You can generate a configuration file using `{scope.name}file` "
                "- then put it in your .gdbinit after initializing pwndbg."
            )
        )


@pwndbg.commands.Command(parser, category=CommandCategory.PWNDBG)
def config(filter_pattern) -> None:
    display_config(filter_pattern, Scope.config)


configfile_parser = argparse.ArgumentParser(
    description="Generates a configuration file for the current pwndbg options."
)
configfile_parser.add_argument(
    "--show-all", action="store_true", help="Display all configuration options."
)

parser = argparse.ArgumentParser(description="Shows pwndbg-specific theme configuration.")
parser.add_argument(
    "filter_pattern",
    type=str,
    nargs="?",
    default=None,
    help="Filter to apply to theme parameters names/descriptions",
)


@pwndbg.commands.Command(parser, category=CommandCategory.PWNDBG)
def theme(filter_pattern) -> None:
    display_config(filter_pattern, Scope.theme)


if pwndbg.dbg.is_gdblib_available():
    # Register the configfile command
    @pwndbg.commands.Command(configfile_parser, category=CommandCategory.PWNDBG)
    def configfile(show_all=False) -> None:
        configfile_print_scope(Scope.config, show_all)


themefile_parser = argparse.ArgumentParser(
    description="Generates a configuration file for the current pwndbg theme options."
)
themefile_parser.add_argument(
    "--show-all", action="store_true", help="Force displaying of all theme options."
)


if pwndbg.dbg.is_gdblib_available():
    # Register the themefile command.
    @pwndbg.commands.Command(themefile_parser, category=CommandCategory.PWNDBG)
    def themefile(show_all=False) -> None:
        configfile_print_scope(Scope.theme, show_all)


parser = argparse.ArgumentParser(description="Shows heap related configuration.")
parser.add_argument(
    "filter_pattern",
    type=str,
    nargs="?",
    default=None,
    help="Filter to apply to config parameters names/descriptions",
)


@pwndbg.commands.Command(parser, category=CommandCategory.PWNDBG)
def heap_config(filter_pattern: str) -> None:
    display_config(filter_pattern, Scope.heap, has_file_command=False)
    print(
        hint(
            "Some parameters (e.g. main-arena) will be used only when resolve-heap-via-heuristic is `auto` or `force`"
        )
    )


def configfile_print_scope(scope: Scope, show_all: bool = False) -> None:
    params = pwndbg.config.get_params(scope)

    if not show_all:
        params = list(filter(lambda p: p.is_changed, params))

    if params:
        if not show_all:
            print(hint("Showing only changed values:"))
        for p in params:
            native_default = pwndbg.gdblib.config_mod.Parameter._value_to_gdb_native(
                p.default, param_class=pwndbg.gdblib.config.CLASS_MAPPING[p.param_class]
            )
            native_value = pwndbg.gdblib.config_mod.Parameter._value_to_gdb_native(
                p.value, param_class=pwndbg.gdblib.config.CLASS_MAPPING[p.param_class]
            )
            print(f"# {p.name}: {p.set_show_doc}")
            print(f"# default: {native_default}")
            print(f"set {p.name} {native_value}")
            print()
    else:
        # FIXME: Message would be wrong for a heapfile command.
        print(hint(f"No changed values. To see current values use `{scope.name}`."))

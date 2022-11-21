"""
Dumps all pwndbg-specific configuration points.
"""

import argparse

import pwndbg.commands
import pwndbg.gdblib.config
from pwndbg.color import generateColorFunction
from pwndbg.color import ljust_colored
from pwndbg.color import strip
from pwndbg.color.message import hint


def print_row(name, value, default, set_show_doc, ljust_optname, ljust_value, empty_space=6):
    name = ljust_colored(name, ljust_optname + empty_space)
    defval = extend_value_with_default(value, default)
    defval = ljust_colored(defval, ljust_value + empty_space)
    result = " ".join((name, defval, set_show_doc))
    print(result)
    return result


def extend_value_with_default(value, default):
    if strip(value) != strip(default):
        return "%s (%s)" % (value, default)
    return value


def get_config_parameters(scope, filter_pattern):
    values = [
        v
        for k, v in pwndbg.gdblib.config.params.items()
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


parser = argparse.ArgumentParser(
    description="Shows pwndbg-specific config. The list can be filtered."
)
parser.add_argument(
    "filter_pattern",
    type=str,
    nargs="?",
    default=None,
    help="Filter to apply to config parameters names/descriptions",
)


def display_config(filter_pattern: str, scope: str):
    values = get_config_parameters(scope, filter_pattern)

    if not values:
        print(hint(f'No {scope} parameter found with filter "{filter_pattern}"'))
        return

    longest_optname = max(map(len, [v.name for v in values]))
    longest_value = max(
        # We use `repr` here so the string values will be in quotes
        map(len, [extend_value_with_default(repr(v.value), repr(v.default)) for v in values])
    )

    header = print_row("Name", "Value", "Def", "Documentation", longest_optname, longest_value)
    print("-" * (len(header)))

    for v in sorted(values):
        if isinstance(v, pwndbg.color.theme.ColorParameter):
            # Only the theme scope should use ColorParameter
            assert scope == "theme"

            value = generateColorFunction(v.value)(v.value)
            default = generateColorFunction(v.default)(v.default)
        else:
            value = repr(v.value)
            default = repr(v.default)

        print_row(v.name, value, default, v.set_show_doc, longest_optname, longest_value)

    print(hint(f"You can set config variable with `set <{scope}-var> <value>`"))
    print(
        hint(
            f"You can generate configuration file using `{scope}file` "
            "- then put it in your .gdbinit after initializing pwndbg"
        )
    )


@pwndbg.commands.ArgparsedCommand(parser)
def config(filter_pattern):
    display_config(filter_pattern, "config")


configfile_parser = argparse.ArgumentParser(
    description="Generates a configuration file for the current Pwndbg options"
)
configfile_parser.add_argument(
    "--show-all", action="store_true", help="Force displaying of all configs."
)

parser = argparse.ArgumentParser(
    description="Shows pwndbg-specific theme config. The list can be filtered."
)
parser.add_argument(
    "filter_pattern",
    type=str,
    nargs="?",
    default=None,
    help="Filter to apply to theme parameters names/descriptions",
)


@pwndbg.commands.ArgparsedCommand(parser)
def theme(filter_pattern):
    display_config(filter_pattern, "theme")


@pwndbg.commands.ArgparsedCommand(configfile_parser)
def configfile(show_all=False):
    configfile_print_scope("config", show_all)


themefile_parser = argparse.ArgumentParser(
    description="Generates a configuration file for the current Pwndbg theme options"
)
themefile_parser.add_argument(
    "--show-all", action="store_true", help="Force displaying of all theme options."
)


@pwndbg.commands.ArgparsedCommand(themefile_parser)
def themefile(show_all=False):
    configfile_print_scope("theme", show_all)


def configfile_print_scope(scope, show_all=False):
    params = pwndbg.gdblib.config.get_params(scope)

    if not show_all:
        params = list(filter(lambda p: p.is_changed, params))

    if params:
        if not show_all:
            print(hint("Showing only changed values:"))
        for p in params:
            print("# %s: %s" % (p.name, p.set_show_doc))
            print("# default: %s" % p.native_default)
            print("set %s %s" % (p.name, p.native_value))
            print()
    else:
        print(hint("No changed values. To see current values use `%s`." % scope))

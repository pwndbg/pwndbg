import argparse
import errno
from collections import defaultdict

import gdb

import pwndbg.auxv
import pwndbg.color as C
import pwndbg.commands
import pwndbg.gdblib.regs
import pwndbg.gdblib.symbol
from pwndbg.commands import CommandCategory
from pwndbg.gdblib.scheduler import parse_and_eval_with_scheduler_lock

errno.errorcode[0] = "OK"  # type: ignore # manually add error code 0 for "OK"

parser = argparse.ArgumentParser(
    description="Converts errno (or argument) to its string representation."
)
parser.add_argument(
    "err",
    type=int,
    nargs="?",
    default=None,
    help="Errno; if not passed, it is retrieved from __errno_location",
)


@pwndbg.commands.ArgparsedCommand(parser, command_name="errno", category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
def errno_(err) -> None:
    if err is None:
        # Try to get the `errno` variable value
        # if it does not exist, get the errno variable from its location
        try:
            err = int(gdb.parse_and_eval("errno"))
        except gdb.error:
            try:
                # We can't simply call __errno_location because its .plt.got entry may be uninitialized
                # (e.g. if the binary was just started with `starti` command)
                # So we have to check the got.plt entry first before calling it
                errno_loc_gotplt = pwndbg.gdblib.symbol.address("__errno_location@got.plt")

                # If the got.plt entry is not there (is None), it means the symbol is not used by the binary
                if errno_loc_gotplt is None or pwndbg.gdblib.vmmap.find(
                    pwndbg.gdblib.memory.pvoid(errno_loc_gotplt)
                ):
                    err = int(
                        parse_and_eval_with_scheduler_lock(
                            "*((int *(*) (void)) __errno_location) ()"
                        )
                    )
                else:
                    print(
                        "Could not determine error code automatically: the __errno_location@got.plt has no valid address yet (perhaps libc.so hasn't been loaded yet?)"
                    )
                    return
            except gdb.error:
                print(
                    "Could not determine error code automatically: neither `errno` nor `__errno_location` symbols were provided (perhaps libc.so hasn't been not loaded yet?)"
                )
                return

    msg = errno.errorcode.get(int(err), "Unknown error code")
    print(f"Errno {err}: {msg}")


parser = argparse.ArgumentParser(description="Prints out a list of all pwndbg commands.")

group = parser.add_mutually_exclusive_group()
group.add_argument("--shell", action="store_true", help="Only display shell commands")
group.add_argument("--all", dest="all_", action="store_true", help="Only display shell commands")

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


@pwndbg.commands.ArgparsedCommand(parser, command_name="pwndbg", category=CommandCategory.PWNDBG)
def pwndbg_(filter_pattern, shell, all_, category_, list_categories) -> None:
    if list_categories:
        for category in CommandCategory:
            print(C.bold(C.green(f"{category.value}")))
        return

    if all_:
        shell_cmds = True
        pwndbg_cmds = True
    elif shell:
        shell_cmds = True
        pwndbg_cmds = False
    else:
        shell_cmds = False
        pwndbg_cmds = True

    from tabulate import tabulate

    table_data = defaultdict(lambda: [])
    for name, aliases, category, docs in list_and_filter_commands(
        filter_pattern, pwndbg_cmds, shell_cmds
    ):
        alias_str = ""
        aliases_len = 0
        if aliases:
            aliases = map(C.blue, aliases)
            alias_str = f" [{', '.join(aliases)}]"

        command_names = C.green(name) + alias_str
        table_data[category].append((command_names, docs))

    for category in CommandCategory:
        if category not in table_data or category_ and category_.lower() not in category.lower():
            continue
        data = table_data[category]

        category_header = C.bold(C.green(category + " Commands"))
        alias_header = C.bold(C.blue("Aliases"))
        print(
            tabulate(
                data, headers=[f"{category_header} [{alias_header}]", f"{C.bold('Description')}"]
            )
        )
        print()


def list_and_filter_commands(filter_str, pwndbg_cmds=True, shell_cmds=False):
    sorted_commands = list(pwndbg.commands.commands)
    sorted_commands.sort(key=lambda x: x.__name__)

    if filter_str:
        filter_str = filter_str.lower()

    results = []

    for c in sorted_commands:
        # If this is a shell command and we didn't ask for shell commands, skip it
        if c.shell and not shell_cmds:
            continue

        # If this is a normal command and we didn't ask for normal commands, skip it
        if not c.shell and not pwndbg_cmds:
            continue

        # Don't print aliases
        if c.is_alias:
            continue

        name = c.__name__
        docs = c.__doc__

        if docs:
            docs = docs.strip()
        if docs:
            docs = docs.splitlines()[0]

        if not filter_str or filter_str in name.lower() or (docs and filter_str in docs.lower()):
            results.append((name, c.aliases, c.category, docs))

    return results

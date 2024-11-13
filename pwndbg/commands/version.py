"""
Displays gdb, python and pwndbg versions.
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import sys
from subprocess import check_call
from subprocess import check_output
from tempfile import NamedTemporaryFile
from urllib.parse import quote

import gdb

import pwndbg
import pwndbg.commands
import pwndbg.integration
from pwndbg.color import message
from pwndbg.commands import CommandCategory


def _gdb_version() -> str:
    return gdb.VERSION


def _py_version():
    return sys.version.replace("\n", " ")


def capstone_version():
    try:
        import capstone

        return ".".join(map(str, capstone.cs_version()))
    except ImportError:
        return "not found"


def unicorn_version():
    try:
        import unicorn

        return unicorn.__version__
    except ImportError:
        return "not found"


def all_versions():
    gdb_str = f"Gdb:      {_gdb_version()}"
    py_str = f"Python:   {_py_version()}"
    pwndbg_str = f"Pwndbg:   {pwndbg.__version__}"

    capstone_str = f"Capstone: {capstone_version()}"
    unicorn_str = f"Unicorn:  {unicorn_version()}"

    all_versions = (gdb_str, py_str, pwndbg_str, capstone_str, unicorn_str)

    all_versions += pwndbg.integration.provider.get_versions()
    return all_versions


@pwndbg.commands.ArgparsedCommand(
    "Displays GDB, Python, and pwndbg versions.", category=CommandCategory.PWNDBG
)
def version() -> None:
    """
    Displays GDB, Python, and pwndbg versions.
    """
    print("\n".join(map(message.system, all_versions())))


bugreport_parser = argparse.ArgumentParser(description="Generate a bug report.")
bugreport_group = bugreport_parser.add_mutually_exclusive_group()
bugreport_group.add_argument(
    "--run-browser", "-b", action="store_true", help="Open browser on github/issues/new"
)
bugreport_group.add_argument(
    "--use-gh", "-g", action="store_true", help="Create issue using Github CLI"
)


@pwndbg.commands.ArgparsedCommand(bugreport_parser, category=CommandCategory.PWNDBG)
def bugreport(run_browser=False, use_gh=False):
    ISSUE_TEMPLATE = """
<!--
Before reporting a new issue, make sure that we do not have any duplicates already open.
If there is one it might be good to take part in the discussion there.

Please make sure you have checked that the issue persists on LATEST pwndbg version.

Below is a template for BUG REPORTS.
Don't include it if this is a FEATURE REQUEST.
-->


### Description

<!--
Briefly describe the problem you are having in a few paragraphs.
-->

### Steps to reproduce

<!--
What do we have to do to reproduce the problem?
If this is connected to particular C/asm code or a binary,
please provide the binary or if possible, a smallest C code that reproduces the issue.
-->

Gdb session history:
```
{gdb_history}
```

### My setup

<!--
Show us your gdb/python/pwndbg/OS/IDA Pro version (depending on your case).

NOTE: We are currently testing Pwndbg only on Ubuntu installations but it should work fine on other distros as well.

This can be displayed in pwndbg through `version` command.

If it is somehow unavailable, use:
* `show version` - for gdb
* `py import sys; print(sys.version)` - for python
* pwndbg version/git commit id
-->

```
{setup}
```"""

    gdb_config = gdb.execute("show configuration", to_string=True).split("\n")
    all_info = all_versions()
    os_info = platform.system()

    current_setup = f"Platform: {platform.platform()}\n"

    if os_info.lower() == "linux" and os.path.isfile("/etc/os-release"):
        with open("/etc/os-release") as os_release:
            contents = os_release.read()
            match = re.search('PRETTY_NAME="?([^",\n]+)', contents)
            if match:
                os_info = match.group(1)

    current_setup += f"OS: {os_info}\n"

    # 1. showing osabi
    osabi_info = platform.uname().version
    current_setup += f"OS ABI: {osabi_info}\n"

    # 2. showing architecture
    arch_info = platform.machine()
    current_setup += f"Architecture: {arch_info}\n"

    # 3. showing endian
    endian_info = sys.byteorder
    current_setup += f"Endian: {endian_info}\n"

    # 4. Depending on current arch -- note that those are only available if given arch is supported by current GDB, like gdb-multiarch
    if arch_info in ["armv7l", "aarch64"]:
        arm_info = gdb.execute("show arm", to_string=True)
        current_setup += f"ARM: {arm_info}\n"

    elif arch_info in ["mips", "mips64"]:
        mips_info = gdb.execute("show mips", to_string=True)
        current_setup += f"MIPS: {mips_info}\n"

    # 7. showing charset
    charset_info = sys.getdefaultencoding()
    current_setup += f"Charset: {charset_info}\n"

    # 8. showing width, height
    try:
        width_info = os.get_terminal_size().columns
        height_info = os.get_terminal_size().lines
    except OSError:
        # Terminal size may not be available in non-interactive environments (e.g., scripts, IDEs)
        width_info = "no terminal size"
        height_info = "no terminal size"

    current_setup += f"Width: {width_info}\n"
    current_setup += f"Height: {height_info}\n"

    current_setup += "\n".join(all_info)
    current_setup += "\n" + "\n".join(gdb_config)

    # get saved history size (not including current gdb session)
    gdb_history_file = gdb.execute("show history filename", to_string=True)
    gdb_history_file = gdb_history_file[
        gdb_history_file.index('"') + 1 : gdb_history_file.rindex('"')
    ]
    gdb_history_len = 0
    try:
        with open(gdb_history_file) as f:
            gdb_history_len = len(f.readlines())
    except FileNotFoundError:
        pass

    max_command_no = 0
    history_commands = gdb.execute("show commands", to_string=True)
    if history_commands:
        history_commands = history_commands.split("\n")
        if len(history_commands) > 1:
            # The last element of the list is the `show commands` command we
            # just ran, so we need to get the second to last one
            last_command = history_commands[-2]
            max_command_no = int(last_command.split()[0]) - 1

    show_command_size = 10  # 'show command' returns 10 commands
    gdb_current_session_history = {}
    current_command_no = gdb_history_len + 1

    while current_command_no <= max_command_no:
        cmds = gdb.execute(
            "show commands " + str(current_command_no + (show_command_size // 2) + 1),
            to_string=True,
        ).split("\n")[:-1]
        for cmd in cmds:
            cmd_no, cmd = cmd.split(maxsplit=1)
            cmd_no = int(cmd_no)
            if cmd_no <= gdb_history_len:
                continue
            if current_command_no > max_command_no:
                break
            gdb_current_session_history[cmd_no] = cmd
            current_command_no += 1

    gdb_current_session_history = (v for (k, v) in sorted(gdb_current_session_history.items()))
    gdb_current_session_history = "\n".join(gdb_current_session_history)

    issue_bugreport = ISSUE_TEMPLATE.format(
        gdb_history=gdb_current_session_history, setup=current_setup
    )
    print(issue_bugreport)

    please_please_submit = "Please submit the bugreport generated above at "
    github_issue_url = "https://github.com/pwndbg/pwndbg/issues/new"
    github_issue_body = "?body=" + quote(issue_bugreport)

    if use_gh:
        try:
            with NamedTemporaryFile("w", delete=True) as f:
                f.write(issue_bugreport)
                f.flush()
                check_call([os.environ.get("EDITOR", "vi"), f.name])
                check_call(["gh", "issue", "create", "--body-file", f.name])
        except Exception:
            print(please_please_submit + github_issue_url)
    elif run_browser:
        try:
            check_output(["xdg-open", github_issue_url + github_issue_body])
        except Exception:
            print(please_please_submit + github_issue_url)
    else:
        print(please_please_submit + github_issue_url)

"""
Displays gdb, python and pwndbg versions.
"""


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
import pwndbg.ida
from pwndbg.color import message
from pwndbg.commands import CommandCategory


def _gdb_version():
    try:
        return gdb.VERSION  # GDB >= 8.1 (or earlier?)
    except AttributeError:
        return gdb.execute("show version", to_string=True).split("\n")[0]


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
    gdb_str = "Gdb:      %s" % _gdb_version()
    py_str = "Python:   %s" % _py_version()
    pwndbg_str = "Pwndbg:   %s" % pwndbg.__version__

    capstone_str = "Capstone: %s" % capstone_version()
    unicorn_str = "Unicorn:  %s" % unicorn_version()

    all_versions = (gdb_str, py_str, pwndbg_str, capstone_str, unicorn_str)

    ida_versions = pwndbg.ida.get_ida_versions()

    if ida_versions is not None:
        ida_version = "IDA PRO:  %s" % ida_versions["ida"]
        ida_py_ver = "IDA Py:   %s" % ida_versions["python"]
        ida_hr_ver = "Hexrays:  %s" % ida_versions["hexrays"]
        all_versions += (ida_version, ida_py_ver, ida_hr_ver)
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

    current_setup = "Platform: %s\n" % platform.platform()

    if os_info.lower() == "linux" and os.path.isfile("/etc/os-release"):
        with open("/etc/os-release", "r") as os_release:
            contents = os_release.read()
            match = re.search('PRETTY_NAME="?([^",\n]+)', contents)
            if match:
                os_info = match.group(1)

    current_setup += "OS: %s\n" % os_info
    current_setup += "\n".join(all_info)
    current_setup += "\n" + "\n".join(gdb_config)

    # get saved history size (not including current gdb session)
    gdb_history_file = gdb.execute("show history filename", to_string=True)
    gdb_history_file = gdb_history_file[
        gdb_history_file.index('"') + 1 : gdb_history_file.rindex('"')
    ]
    gdb_history_len = 0
    try:
        with open(gdb_history_file, "r") as f:
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
            raise
    elif run_browser:
        try:
            check_output(["xdg-open", github_issue_url + github_issue_body])
        except Exception:
            print(please_please_submit + github_issue_url)
    else:
        print(please_please_submit + github_issue_url)

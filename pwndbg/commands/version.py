"""
Implements version and bugreport commands.
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

import pwndbg
import pwndbg.commands
import pwndbg.integration
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.dbg import DebuggerType


def os_info():
    os_info = platform.system()

    if os_info.lower() == "linux" and os.path.isfile("/etc/os-release"):
        with open("/etc/os-release") as os_release:
            contents = os_release.read()
            match = re.search('PRETTY_NAME="?([^",\n]+)', contents)
            if match:
                os_info = match.group(1)

    return os_info


def module_version(module):
    try:
        return __import__(module).__version__
    except ImportError:
        return "not found"


def debugger_version():
    if pwndbg.dbg.is_gdblib_available():
        import gdb

        return f"GDB:      {gdb.VERSION}"
    else:
        return f"LLDB:     {'.'.join(map(str, pwndbg.dbg_mod.lldb.LLDB_VERSION))}"


def all_versions():
    py_version = sys.version.replace("\n", " ")
    return (
        f"Pwndbg:   {pwndbg.__version__}",
        f"Python:   {py_version}",
        debugger_version(),
        f"Capstone: {module_version('capstone')}",
        f"Unicorn:  {module_version('unicorn')}",
        f"Pwnlib:   {module_version('pwnlib')}",
    ) + pwndbg.integration.provider.get_versions()


def get_target_arch():
    arch_info = pwndbg.aglib.arch.name
    target = f"Target Arch: {arch_info}\n"

    if pwndbg.dbg.is_gdblib_available():
        import gdb

        # Note: this are only available if given arch is supported by GDB
        # (e.g., `gdb-multiarch` on Ubuntu)
        if arch_info in ("arm", "armcm", "aarch64"):
            arm_info = gdb.execute("show arm", to_string=True)
            target += f"ARM: {arm_info}\n"

        elif arch_info in ("mips", "mips64"):
            mips_info = gdb.execute("show mips", to_string=True)
            target += f"MIPS: {mips_info}\n"

    return target


def get_terminal_size():
    try:
        width_info = os.get_terminal_size().columns
        height_info = os.get_terminal_size().lines
    except OSError:
        # Terminal size may not be available in non-interactive environments (e.g., scripts, IDEs)
        width_info = height_info = "<unavailable>"

    return f"Terminal width: {width_info}, height: {height_info}\n"


def version_impl() -> None:
    """
    Implementation of the `version` command.
    """
    print("\n".join(map(message.system, all_versions())))


# In LLDB, this command is implemented as part of the Pwndbg CLI.
@pwndbg.commands.Command(
    "Displays Pwndbg and its important deps versions.",
    exclude_debuggers={DebuggerType.LLDB},
    category=CommandCategory.PWNDBG,
)
def version() -> None:
    version_impl()


bugreport_parser = argparse.ArgumentParser(description="Generate a bug report.")
bugreport_group = bugreport_parser.add_mutually_exclusive_group()
bugreport_group.add_argument(
    "--run-browser", "-b", action="store_true", help="Open browser on github/issues/new"
)
bugreport_group.add_argument(
    "--use-gh", "-g", action="store_true", help="Create issue using Github CLI"
)


@pwndbg.commands.Command(bugreport_parser, category=CommandCategory.PWNDBG)
def bugreport(run_browser=False, use_gh=False):
    ISSUE_TEMPLATE = """
<!--
Please see if the bug isn't reported already on: https://github.com/pwndbg/pwndbg/issues
and take part in discussion if it was.

Before reporting a new issue, make sure it happens on latest Pwndbg version.

Use the template below.
-->


### Description

<!--
Describe the problem you are having in a few paragraphs.
-->

### Steps to reproduce

<!--
What do we have to do to reproduce the problem?
If this is connected to particular C/asm code or a binary,
please provide the binary or if possible, a smallest C code that reproduces the issue.
-->

Session history:
```
{session_history}
```

### My setup

<!--
Show us your Pwndbg and any other relevant versions.
-->

```
{setup}
```"""
    setup = "\n".join(all_versions()) + "\n"
    setup += f"OS: {os_info()} ({platform.platform()}, {sys.byteorder} endian)\n"
    setup += f"OS ABI: {platform.uname().version}\n"
    setup += f"Charset: {sys.getdefaultencoding()}\n"
    setup += get_terminal_size()
    setup += get_target_arch()

    # Commented out for now: do we need this? It seems to be a bloat for GDB.
    # People rarely build custom GDB with fancy options...?
    # setup += get_debugger_configuration()

    session_history = get_debugger_session_history()

    issue_bugreport = ISSUE_TEMPLATE.format(setup=setup, session_history=session_history)
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


def get_debugger_configuration():
    if pwndbg.dbg.is_gdblib_available():
        import gdb

        gdb_config = gdb.execute("show configuration", to_string=True).split("\n")
        return "\n" + "\n".join(gdb_config)

    # LLDB: TODO/FIXME: Do we need this?
    else:
        return ""


def get_debugger_session_history():
    if pwndbg.dbg.is_gdblib_available():
        import gdb

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
        return "\n".join(gdb_current_session_history)

    # LLDB: TODO/FIXME: Not yet supported
    else:
        return "<session history not supported on lldb yet>"

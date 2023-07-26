from __future__ import annotations

from subprocess import CalledProcessError

import pwndbg.commands
import pwndbg.lib.cache
import pwndbg.wrappers

cmd_name = "checksec"
cmd_pwntools = ["pwn", "checksec"]


@pwndbg.wrappers.OnlyWithCommand(cmd_name, cmd_pwntools)
@pwndbg.lib.cache.cache_until("objfile")
def get_raw_out(local_path: str) -> str:
    try:
        return pwndbg.wrappers.call_cmd(get_raw_out.cmd + ["--file=" + local_path])
    except CalledProcessError:
        pass
    try:
        return pwndbg.wrappers.call_cmd(get_raw_out.cmd + ["--file", local_path])
    except CalledProcessError:
        pass
    return pwndbg.wrappers.call_cmd(get_raw_out.cmd + [local_path])


@pwndbg.wrappers.OnlyWithCommand(cmd_name, cmd_pwntools)
def relro_status(local_path: str) -> str:
    relro = "No RELRO"
    out = get_raw_out(local_path)

    if "Full RELRO" in out:
        relro = "Full RELRO"
    elif "Partial RELRO" in out:
        relro = "Partial RELRO"

    return relro


@pwndbg.wrappers.OnlyWithCommand(cmd_name, cmd_pwntools)
def pie_status(local_path) -> str:
    pie = "No PIE"
    out = get_raw_out(local_path)

    if "PIE enabled" in out:
        pie = "PIE enabled"

    return pie

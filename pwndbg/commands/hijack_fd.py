from __future__ import annotations

import argparse
import contextlib
import socket
from typing import Literal
from typing import NamedTuple
from typing import Optional
from typing import Tuple
from urllib.parse import ParseResult
from urllib.parse import urlparse

from pwnlib import asm
from pwnlib import constants
from pwnlib import shellcraft
from pwnlib.util.net import sockaddr

import pwndbg.aglib.memory
import pwndbg.aglib.shellcode
import pwndbg.commands
import pwndbg.lib.abi
import pwndbg.lib.memory
import pwndbg.lib.regs
from pwndbg.commands import CommandCategory


class ShellcodeRegs(NamedTuple):
    newfd: str
    syscall_ret: str
    stack: str


def get_shellcode_regs() -> ShellcodeRegs:
    register_set = pwndbg.lib.regs.reg_sets[pwndbg.aglib.arch.name]
    syscall_abi = pwndbg.aglib.arch.syscall_abi
    if syscall_abi is None:
        raise pwndbg.dbg_mod.Error("Syscall ABI not defined for current architecture")

    # pickup free register what is not used for syscall abi
    newfd_reg = next(
        (
            reg_name
            for reg_name in register_set.gpr
            if reg_name not in syscall_abi.register_arguments + [syscall_abi.syscall_register]
        )
    )
    assert (
        newfd_reg is not None
    ), f"architecture {pwndbg.aglib.arch.name} don't have unused register..."

    return ShellcodeRegs(newfd_reg, register_set.retval, register_set.stack)


def stack_size_alignment(s: int) -> int:
    syscall_abi = pwndbg.aglib.arch.syscall_abi
    if syscall_abi is None:
        raise pwndbg.dbg_mod.Error("Syscall ABI not defined for current architecture")

    return s + (syscall_abi.arg_alignment - (s % syscall_abi.arg_alignment))


def asm_replace_file(replace_fd: int, filename: str) -> Tuple[int, str]:
    filename = filename.encode() + b"\x00"

    regs = get_shellcode_regs()
    stack_size = stack_size_alignment(len(filename))

    open_asm = (
        shellcraft.syscall("SYS_open", regs.stack, "O_CREAT|O_RDWR", 0o666)
        if hasattr(constants, "SYS_open")
        else shellcraft.syscall("SYS_openat", "AT_FDCWD", regs.stack, "O_CREAT|O_RDWR", 0o666)
    )

    dup_asm = (
        shellcraft.syscall("SYS_dup2", regs.newfd, replace_fd)
        if hasattr(constants, "SYS_dup2")
        else shellcraft.syscall("SYS_dup3", regs.newfd, replace_fd, 0)
    )

    return stack_size, asm.asm(
        "".join(
            [
                shellcraft.pushstr(filename, False),
                open_asm,
                shellcraft.mov(regs.newfd, regs.syscall_ret),
                dup_asm,
                shellcraft.syscall("SYS_close", regs.newfd),
            ]
        )
    )


def asm_replace_socket(replace_fd: int, socket_data: ParsedSocket) -> Tuple[int, str]:
    sockdata, addr_len, _ = sockaddr(socket_data.address, socket_data.port, socket_data.ip_version)
    socktype = {"tcp": "SOCK_STREAM", "udp": "SOCK_DGRAM"}[socket_data.protocol]
    family = {"ipv4": "AF_INET", "ipv6": "AF_INET6"}[socket_data.ip_version]

    regs = get_shellcode_regs()
    stack_size = stack_size_alignment(len(sockdata))

    dup_asm = (
        shellcraft.syscall("SYS_dup2", regs.newfd, replace_fd)
        if hasattr(constants, "SYS_dup2")
        else shellcraft.syscall("SYS_dup3", regs.newfd, replace_fd, 0)
    )

    return stack_size, asm.asm(
        "".join(
            [
                shellcraft.syscall("SYS_socket", family, socktype, 0),
                shellcraft.mov(regs.newfd, regs.syscall_ret),
                shellcraft.pushstr(sockdata, False),
                shellcraft.syscall("SYS_connect", regs.newfd, regs.stack, addr_len),
                dup_asm,
                shellcraft.syscall("SYS_close", regs.newfd),
            ]
        )
    )


@contextlib.asynccontextmanager
async def exec_shellcode_with_stack(ec: pwndbg.dbg_mod.ExecutionController, blob, stack_size: int):
    # This function could be improved, for example:
    # - Run the shellcode inside an emulator like Unicorn
    # - Calculate the maximum stack size the shellcode would consume dynamically.

    stack_start_diff = pwndbg.aglib.regs.sp
    stack_start = stack_start_diff - stack_size
    original_stack = pwndbg.aglib.memory.read(stack_start, stack_size)

    try:
        async with pwndbg.aglib.shellcode.exec_shellcode(
            ec, blob, restore_context=True, disable_breakpoints=True
        ):
            stack_diff_size = stack_start_diff - pwndbg.aglib.regs.sp

            # Make sure stack is not corrupted somehow
            assert not (
                stack_diff_size > stack_size
            ), f"stack is probably corrupted size_current=f{stack_diff_size} size_max_want={stack_size}"

            yield
    finally:
        pwndbg.aglib.memory.write(stack_start, original_stack)


parser = argparse.ArgumentParser(
    description="""Replace a file descriptor of a debugged process.

The new file descriptor can point to:
- a file
- a pipe
- a socket
- a device, etc.

Examples:
1. Redirect STDOUT to a file:
   `hijack-fd 1 /dev/null`

2. Redirect STDERR to a socket:
   `hijack-fd 2 tcp://localhost:8888`
""",
)

parser.add_argument(
    "fdnum",
    help="File descriptor (FD) number to be replaced with the specified new socket or file.",
    type=int,
)


class ParsedSocket(NamedTuple):
    protocol: Literal["tcp", "udp"]
    ip_version: Literal["ipv4", "ipv6"]
    address: str
    port: int


def parse_socket(url: str) -> ParsedSocket:
    if "://" in url:
        # For handling:
        # - `tcp://[::1]:80`
        # - `udp://example.com:80`
        # - `tcp+ipv6://example.com:80`
        parsed = urlparse(url)
    else:
        # For handling:
        # - `127.0.0.1:80`
        parsed = ParseResult("", url, "", "", "", "")

    # Handling eg: `tcp+ipv6://example.com:80`
    scheme_info = parsed.scheme.split("+", 1)

    selected_protocol: Literal["tcp", "udp"] = "tcp"
    selected_ip_protocol: Literal["ipv4", "ipv6"] | None = None
    if parsed.scheme:
        for any_value in scheme_info:
            if any_value in ("tcp", "udp"):
                selected_protocol = any_value
            elif any_value in ("ipv4", "ipv6"):
                selected_ip_protocol = any_value

    domain_or_ip = parsed.hostname
    if not domain_or_ip:
        raise argparse.ArgumentTypeError("Domain or IP is required")

    port = parsed.port
    if not port:
        raise argparse.ArgumentTypeError("Port is required")

    protocol_ordered = (
        ("ipv4", socket.AF_INET),
        ("ipv6", socket.AF_INET6),
    )

    found_ip_protocol: Literal["ipv4", "ipv6"] | None = None
    address_ipv4_or_ipv6: str = ""
    for family_name, family_const in protocol_ordered:
        if selected_ip_protocol and selected_ip_protocol != family_name:
            continue

        try:
            # Resolve the given domain or IP address to its corresponding IP address
            ips = socket.getaddrinfo(domain_or_ip, None, family_const)
        except socket.gaierror:
            # happen when domain not found
            continue

        for _, _, _, _, ip in ips:
            address_ipv4_or_ipv6 = ip[0]
            found_ip_protocol = family_name

        if found_ip_protocol:
            break

    if not address_ipv4_or_ipv6:
        raise argparse.ArgumentTypeError(
            f"Could not resolve {domain_or_ip} to proper {selected_ip_protocol} address"
        )

    if not found_ip_protocol:
        raise argparse.ArgumentTypeError("Protocol only accept: ipv4,ipv6")

    return ParsedSocket(selected_protocol, found_ip_protocol, address_ipv4_or_ipv6, port)


PARSED_FILE_ARG = Tuple[Optional[ParsedSocket], Optional[str]]


def parse_file_or_socket(s: str) -> PARSED_FILE_ARG:
    # is file
    if s.startswith("/") or s.startswith("./"):
        return None, s
    return parse_socket(s), None


parser.add_argument(
    "newfile",
    help="""Specify a file or a socket.

For files, the filename must start with `/` (e.g., `/etc/passwd`).

For sockets, the following formats are allowed:
- `127.0.0.1:80` (default is TCP)
- `tcp://[::1]:80`
- `udp://example.com:80`
- `tcp+ipv6://example.com:80`
    """,
    type=parse_file_or_socket,
)


@pwndbg.commands.Command(parser, category=CommandCategory.MISC, command_name="hijack-fd")
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenUserspace
def hijack_fd(fdnum: int, newfile: PARSED_FILE_ARG) -> None:
    socket_data, filename = newfile
    if filename:
        stack_size, asm_bin = asm_replace_file(fdnum, filename)
    elif socket_data:
        stack_size, asm_bin = asm_replace_socket(fdnum, socket_data)
    else:
        assert False

    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController):
        async with exec_shellcode_with_stack(ec, asm_bin, stack_size):
            print(
                "Operation succeeded. Errors are not captured.\n"
                "You can verify this with `procinfo` if the file descriptor has been replaced."
            )

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)

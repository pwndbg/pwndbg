"""
Retrieve files from the debuggee's filesystem.  Useful when
debugging a remote process over SSH or similar, where e.g.
/proc/FOO/maps is needed from the remote system.
"""

from __future__ import annotations

import errno
import os
import shutil
import tempfile
from typing import Iterator
from typing import Tuple

import pwndbg.aglib.proc
import pwndbg.aglib.qemu
import pwndbg.aglib.remote
import pwndbg.lib.cache

_remote_files_dir = None


def reset_remote_files() -> None:
    global _remote_files_dir

    if _remote_files_dir is not None:
        shutil.rmtree(_remote_files_dir)
        _remote_files_dir = None


def remote_files_dir():
    global _remote_files_dir

    if _remote_files_dir is None:
        _remote_files_dir = tempfile.mkdtemp()

    return _remote_files_dir


def get_proc_exe_file() -> str:
    """
    Returns the local path to the debugged file name.
    """
    return get_file(pwndbg.aglib.proc.exe, try_local_path=True)


@pwndbg.lib.cache.cache_until("start")
def can_download_remote_file() -> bool:
    if not pwndbg.aglib.remote.is_remote():
        return False
    elif pwndbg.aglib.qemu.is_qemu_kernel():
        return False

    # Some[1] gdb servers don't implement vFile packets.
    # [1] - qemu-user <8.1
    # [1] - Rosetta2
    # [1] - maybe embedded probe like: `Black Magic Probe V2.3`
    # WTF: There is no indication in `qSupported` when `vFile` packets are supported
    # Probe and check what it returns
    try:
        vfile_open("", 0, 0)
    except OSError:
        return True
    except NotImplementedError:
        return False

    return False


def get_file(path: str, try_local_path: bool = False) -> str:
    """
    Downloads the specified file from the system where the current process is
    being debugged.

    If the `path` is prefixed with "target:" the prefix is stripped
    (to support remote target paths properly).

    If the `try_local_path` is set to `True` and the `path` exists locally and "target:" prefix is not present, it will return the local path instead of downloading the file.

    Returns:
        The local path to the file
    """
    has_target_prefix = path.startswith("target:")
    has_good_prefix = path.startswith(("/", "./", "../")) or has_target_prefix
    if not has_good_prefix:
        raise OSError("get_file called with incorrect path", errno.ENOENT)

    if has_target_prefix:
        path = path[7:]  # len('target:') == 7

    local_path = path
    if not pwndbg.aglib.remote.is_remote():
        if not os.path.exists(local_path):
            raise OSError(f"File '{local_path}' does not exist", errno.ENOENT)

        return local_path

    if try_local_path and not has_target_prefix and os.path.exists(local_path):
        return local_path

    if can_download_remote_file():
        local_path = tempfile.mktemp(dir=remote_files_dir())
        try:
            pwndbg.dbg.selected_inferior().download_remote_file(path, local_path)
        except pwndbg.dbg_mod.Error as e:
            # This module originally raised this as an OSError.
            raise OSError(e)
    else:
        raise OSError(f"get_file('{local_path}') is not supported for your target", errno.ENODEV)

    return local_path


def get(path: str) -> bytes:
    """
    Retrieves the contents of the specified file on the system
    where the current process is being debugged.

    Returns:
        A byte array, or None.
    """
    local_path = get_file(path)

    try:
        with open(local_path, "rb") as f:
            return f.read()
    except Exception:
        return b""


def readlink(path: str) -> str:
    """readlink(path) -> str

    Read the link specified by 'path' on the system being debugged.

    Handles local, qemu-usermode, and remote debugging cases.
    """
    if pwndbg.aglib.remote.is_remote():
        # FIXME: implement `get_sysroot` when remote debugging,
        #  logic should be same as we do in `get_file`
        if can_download_remote_file():
            try:
                return vfile_readlink(path).decode("utf-8")
            except Exception:
                return ""
        return ""

    try:
        return os.readlink(path)
    except Exception:
        return ""


@pwndbg.lib.cache.cache_until("start")
def is_vfile_qemu_user_bug() -> bool:
    # This is a BUG[1] in the gdbstub of QEMU user mode. It should return data encoded in hexadecimal,
    # but instead, it returns the data as a decimal integer (%d).
    # [1] https://github.com/qemu/qemu/blob/b14d0649628cbe88ac0ef35fcf58cd1fc22735b8/gdbstub/user-target.c#L322
    if not pwndbg.aglib.qemu.is_qemu_usermode():
        return False

    # On a bugged QEMU version, the response is `F-1,36`
    # On a fixed QEMU version, the response is `F-1,24`
    # This performs the syscall: `openat(0, "/\01*256", O_RDONLY|0x20) = -1 ENAMETOOLONG (File name too long)`
    response = pwndbg.dbg.selected_inferior().send_remote("vFile:open:2f" + ("01" * 256))
    return response == b"F-1,36"


def _vfile_check_response(response: bytes):
    if len(response) == 0:
        raise NotImplementedError("Not supported")
    # F result [,errno] [;attachment]; strip attachment first, skip if no errno
    result_errno = response.split(b";", 1)[0]
    if result_errno.startswith(b"F") and b"," in result_errno:
        result, errno = result_errno[1:].split(b",", 1)  # Skip "F"
        if int(result) != -1:
            raise NotImplementedError(f"Unknown response status {result!r}")
        err = int(errno, 10 if is_vfile_qemu_user_bug() else 16)
        raise OSError(err, "Error")


def vfile_readlink(pathname: str | bytes) -> bytes:
    """
    Reads the target of a symbolic link on the remote system.

    :param pathname: The path to the symbolic link (string).
    :param buffer_size: The size of the buffer to read into (integer).
    :return: The target of the symbolic link as a string.
    """
    if isinstance(pathname, str):
        pathname = pathname.encode("utf-8")
    encoded_pathname = pathname.hex()

    packet = f"vFile:readlink:{encoded_pathname}"
    response = pwndbg.dbg.selected_inferior().send_remote(packet)
    _vfile_check_response(response)

    parts = response[1:].split(b";", 1)
    # bytes_read = int(parts[0], 16)
    target = gdb_memtox_inverse(parts[1])
    return target


def vfile_readfile(filename: str, chunk_size=1000) -> Iterator[bytes]:
    """
    Reads the entire content of a file on the remote system.

    :param filename: The path to the file (string).
    :param chunk_size: The number of bytes to read in each iteration (integer).
    :return: The complete content of the file as bytes.
    """
    fd = None
    try:
        # 0 = readonly
        fd = vfile_open(filename, 0, 0)
        offset = 0

        while True:
            bytes_read, data = vfile_pread(fd, chunk_size, offset)
            if bytes_read == 0:
                break
            yield data
            offset += bytes_read
    finally:
        if fd is not None:
            vfile_close(fd)


def vfile_open(filename: str, flags: int, mode: int) -> int:
    """
    Opens a file on the remote system and returns the file descriptor.

    :param filename: The path to the file (string).
    :param flags: Flags passed to the open call (integer, base 16).
        These correspond to the constant values in the enum `OpenOptions` from LLDB’s `File.h`,
        not the traditional `open(2)` flags.
    :param mode: Mode bits for the file (integer, base 16).
    :return: File descriptor (integer), or raises an exception if an error occurs.
    """
    encoded_filename = filename.encode("utf-8").hex()
    packet = f"vFile:open:{encoded_filename},{flags:08X},{mode:08X}"
    response = pwndbg.dbg.selected_inferior().send_remote(packet)
    _vfile_check_response(response)

    file_descriptor = int(response[1:].decode(), 10 if is_vfile_qemu_user_bug() else 16)
    return file_descriptor


# GDB defines the encoding of binary data transferred through commands here:
# - https://sourceware.org/gdb/current/onlinedocs/gdb.html/Overview.html#:~:text=The%20binary%20data%20representation%20uses%207d
# This function unescapes these character
# Example of QEMU function that does this escaping:
# https://github.com/qemu/qemu/blob/de278e54aefed143526174335f8286f7437d20be/gdbstub/gdbstub.c#L184
def gdb_memtox_inverse(data: bytes) -> bytes:
    buffer = bytearray()

    i = 0
    while i < len(data):
        b = data[i]
        if b == 125:  # == ord("}"):
            buffer.append(data[i + 1] ^ 0x20)
            i += 1
        else:
            buffer.append(b)
        i += 1

    return buffer


def vfile_pread(fd: int, size: int, offset: int) -> Tuple[int, bytes]:
    """
    Reads data from a file descriptor.

    :param fd: File descriptor (integer).
    :param size: Number of bytes to read (integer, base 16).
    :param offset: Offset in the file to start reading from (integer, base 16).
    :return: Tuple of (bytes_read, data) where bytes_read is an integer and data is the binary data.
    """
    packet = f"vFile:pread:{fd:X},{size:X},{offset:X}"
    response = pwndbg.dbg.selected_inferior().send_remote(packet)
    _vfile_check_response(response)

    parts = response[1:].split(b";", 1)
    bytes_read = int(parts[0].decode(), 16)
    # We have to decode the data, because some bytes -  #,$,*,} - have special encodings
    data = gdb_memtox_inverse(parts[1])

    return bytes_read, data


def vfile_close(fd):
    """
    Closes a previously opened file descriptor.

    :param fd: File descriptor (integer).
    :return: None, or raises an exception if an error occurs.
    """
    packet = f"vFile:close:{fd:X}"
    response = pwndbg.dbg.selected_inferior().send_remote(packet)
    _vfile_check_response(response)
    return None

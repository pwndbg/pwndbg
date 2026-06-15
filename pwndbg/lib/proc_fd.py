"""
Helpers for walking ``/proc/*/fd`` to identify which processes share a given
kernel object.

Currently used by procinfo to turn an anonymous pipe FD ("pipe:[N]") into a
list of (pid, fd, comm, mode) endpoints. Like the SOCK_DIAG path this is
inherently local-only — the data lives in the host kernel's procfs and means
nothing for a remote / different-kernel target.
"""

from __future__ import annotations

import os


class Pipe:
    """Anonymous pipe FD as seen from one process.

    ``inode`` and ``fd`` describe our own end. ``mode`` is "r"/"w"/"rw"/"?"
    derived from /proc/PID/fdinfo. ``peers`` lists every *other* FD across
    the system that points at the same pipe inode, with the same mode info,
    so the user can see who's on the other end (or that they hold both ends
    themselves).
    """

    inode: int | None = None
    fd: int | None = None
    mode: str | None = None
    peers: list[tuple[int, int, str, str]]

    def __init__(self) -> None:
        self.peers = []

    def __str__(self) -> str:
        s = f"pipe:[{self.inode}]"
        parts: list[str] = []
        if self.mode and self.mode != "?":
            parts.append(self.mode)
        if self.peers:
            parts.append("peers: " + "; ".join(_format_peer(p) for p in self.peers))
        if parts:
            s += " (" + ", ".join(parts) + ")"
        return s

    def __repr__(self) -> str:
        return f"Pipe({self})"


def _format_peer(peer: tuple[int, int, str, str]) -> str:
    pid, fd, comm, mode = peer
    s = f"pid={pid}"
    if comm:
        s += f" '{comm}'"
    s += f" fd={fd}"
    if mode and mode != "?":
        s += f" {mode}"
    return s


def _read_fdinfo_mode(pid: int, fd: int) -> str:
    """Return access mode of an FD from /proc/PID/fdinfo/FD as 'r'/'w'/'rw'.

    Returns '?' if fdinfo can't be read or doesn't carry the flags line. The
    fdinfo flags field is octal text and contains the original open() flags;
    the bottom two bits encode the access mode (O_RDONLY / O_WRONLY / O_RDWR).
    """
    try:
        with open(f"/proc/{pid}/fdinfo/{fd}") as f:
            for line in f:
                if not line.startswith("flags:"):
                    continue
                _, _, value = line.partition(":")
                value = value.strip()
                if not value:
                    return "?"
                try:
                    flags = int(value, 8)
                except ValueError:
                    return "?"
                access = flags & 0o3
                if access == 0:
                    return "r"
                if access == 1:
                    return "w"
                if access == 2:
                    return "rw"
                return "?"
    except OSError:
        return "?"
    return "?"


def find_pipe_endpoints(
    target_inodes: set[int],
) -> dict[int, list[tuple[int, int, str, str]]]:
    """For each pipe inode in ``target_inodes``, return all FDs holding it.

    Result maps inode -> list of ``(pid, fd, comm, mode)`` sorted by
    ``(pid, fd)`` for determinism. Inodes with no discoverable holder
    are absent (the kernel may report a pipe inode that's only held by a
    process whose ``/proc/PID/fd`` we can't read).

    Permission errors on individual processes are ignored — this is best
    effort, the same way ``lsof`` is for non-root users.
    """
    if not target_inodes:
        return {}

    result: dict[int, list[tuple[int, int, str, str]]] = {}
    try:
        proc_entries = os.listdir("/proc")
    except OSError:
        return {}

    for entry in proc_entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        fd_dir = f"/proc/{pid}/fd"
        try:
            fd_entries = os.listdir(fd_dir)
        except OSError:
            continue

        comm: str | None = None
        for fd_name in fd_entries:
            try:
                fd = int(fd_name)
            except ValueError:
                continue
            try:
                link = os.readlink(f"{fd_dir}/{fd_name}")
            except OSError:
                continue
            if not link.startswith("pipe:["):
                continue
            try:
                inode = int(link[len("pipe:[") : -1])
            except ValueError:
                continue
            if inode not in target_inodes:
                continue

            if comm is None:
                try:
                    with open(f"/proc/{pid}/comm") as f:
                        comm = f.read().strip()
                except OSError:
                    comm = ""

            mode = _read_fdinfo_mode(pid, fd)
            result.setdefault(inode, []).append((pid, fd, comm, mode))

    for inode in result:
        result[inode].sort(key=lambda t: (t[0], t[1]))

    return result

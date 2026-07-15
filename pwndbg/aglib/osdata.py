"""
Fetch ``info os`` tables from a remote GDB stub via ``qXfer:osdata:read``.

This is how we enumerate system-wide state (like every process's open file
descriptors) on a remote target: the vFile packets can read individual files
but cannot list directories, while osdata asks the stub itself to walk /proc
on its side. gdbserver implements it on Linux; stubs that don't (qemu-user,
embedded probes) answer with an empty reply and we report that as None.
"""

from __future__ import annotations

import pwndbg.aglib.file
import pwndbg.dbg_mod
import pwndbg.lib.osdata

# The length we request per qXfer read. It is only an upper bound: the stub
# trims each reply to fit its own packet buffer (gdbserver advertises ~128KiB
# via qSupported PacketSize, QEMU's stub caps at 4KiB, embedded probes can be
# ~1KiB) and the loop below advances by the bytes actually received, so a
# stub with a smaller buffer just needs more round-trips.
_CHUNK = 0xF00


def read(table: str) -> str | None:
    """Fetch the raw XML of the given osdata table ("files", "processes", ...).

    Returns None if the stub doesn't support qXfer:osdata:read (empty reply),
    doesn't know the table (error reply), or the transfer fails part-way.
    """
    data = bytearray()
    offset = 0

    while True:
        try:
            response = pwndbg.dbg.selected_inferior().send_remote(
                f"qXfer:osdata:read:{table}:{offset:x},{_CHUNK:x}"
            )
        except pwndbg.dbg_mod.Error:
            return None

        if not response:
            # Empty reply is the protocol's "packet not supported".
            return None

        marker, payload = response[:1], response[1:]
        # The reply is the binary-escaped chunk prefixed with 'm' (more data
        # follows) or 'l' (this is the last chunk). Anything else ('E NN', ...)
        # is an error.
        if marker not in (b"m", b"l"):
            return None

        chunk = pwndbg.aglib.file.gdb_memtox_inverse(payload)
        data += chunk

        if marker == b"l":
            break
        if not chunk:
            # 'm' with no data would loop forever; treat as a broken stub.
            return None
        # qXfer offsets count unescaped object bytes.
        offset += len(chunk)

    return data.decode("utf-8", errors="replace")


def open_files() -> list[tuple[int, int, str, str]] | None:
    """Every open FD on the remote system as (pid, fd, comm, name) rows.

    ``name`` is the fd's readlink target on the remote, e.g. "pipe:[1103727]"
    or "/dev/pts/0". Returns None when the stub can't provide the table.
    """
    xml_text = read("files")
    if xml_text is None:
        return None
    return pwndbg.lib.osdata.parse_files_rows(xml_text)

#!/usr/bin/env python3
"""Report damaged debuginfod cache entries and characterise the damage.

A cache entry that is a structurally valid ELF with zeroed DWARF makes GDB throw
`DWARF Error: wrong version in unit header`, which aborts whatever GDB was doing
- including an inferior call. This script says whether the zeros are unwritten
blocks (sparse / lost) or zero bytes that were actually stored.
"""

from __future__ import annotations

import hashlib
import os
import struct
import sys

PAGE = 4096


def sections(d: bytes):
    if d[:4] != b"\x7fELF":
        return None
    e_shoff, = struct.unpack_from("<Q", d, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 0x3A)
    stroff = struct.unpack_from("<IIQQQQ", d, e_shoff + e_shstrndx * e_shentsize)[4]
    out = []
    for i in range(e_shnum):
        nameoff, _, _, _, off, size = struct.unpack_from(
            "<IIQQQQ", d, e_shoff + i * e_shentsize
        )
        end = d.index(b"\0", stroff + nameoff)
        out.append((d[stroff + nameoff:end].decode(), off, size))
    return out


def zero_runs(d: bytes, start: int, size: int):
    hi = min(len(d), start + size)
    runs: list[tuple[int, int]] = []
    run_start = None
    off = start & ~(PAGE - 1)
    while off < hi:
        chunk = d[max(off, start):min(off + PAGE, hi)]
        if chunk and not any(chunk):
            run_start = max(off, start) if run_start is None else run_start
        elif run_start is not None:
            runs.append((run_start, off - run_start))
            run_start = None
        off += PAGE
    if run_start is not None:
        runs.append((run_start, hi - run_start))
    return runs


def holes(path: str, size: int):
    found = []
    with open(path, "rb") as f:
        off = 0
        while off < size:
            try:
                hole = os.lseek(f.fileno(), off, os.SEEK_HOLE)
                if hole >= size:
                    break
                data = os.lseek(f.fileno(), hole, os.SEEK_DATA)
            except OSError:
                break
            found.append((hole, data - hole))
            off = data
    return found


def hexdump(d: bytes, out, autoskip: bool) -> None:
    """xxd-format dump; with autoskip, repeated lines collapse to `*` like `xxd -a`."""
    previous = None
    starred = False
    for off in range(0, len(d), 16):
        chunk = d[off:off + 16]
        if autoskip and chunk == previous and len(chunk) == 16:
            if not starred:
                out.write("*\n")
                starred = True
            continue
        starred = False
        previous = chunk
        groups = " ".join(chunk[i:i + 2].hex() for i in range(0, len(chunk), 2))
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.write(f"{off:08x}: {groups:<39} {text}\n")


def report(path: str) -> bool:
    st = os.stat(path)
    if st.st_size == 0:
        return False  # negative-cache marker, expected
    d = open(path, "rb").read()
    shs = sections(d)
    damage = []
    if shs is None:
        damage.append("not an ELF - GDB ignores this entry")
    else:
        for name, off, size in shs:
            if name.startswith(".debug_"):
                for run_off, run_len in zero_runs(d, off, size):
                    damage.append(f"{name}: {run_len} zero bytes at {run_off:#x}")
    if not damage:
        return False

    sparse = holes(path, st.st_size)
    allocated = st.st_blocks * 512
    if sparse:
        verdict = "blocks were never written (file is sparse)"
    elif allocated < st.st_size - PAGE:
        verdict = f"under-allocated: only {allocated} of {st.st_size} bytes on disk"
    else:
        verdict = "fully allocated - the zeros were written into the file"

    print(f"=== DAMAGED: {path}")
    print(f"    size={st.st_size} allocated={allocated} mtime={st.st_mtime}")
    print(f"    sha256={hashlib.sha256(d).hexdigest()}")
    print(f"    holes={sparse or 'none'}")
    print(f"    VERDICT: {verdict}")
    for line in damage:
        print(f"    {line}")

    if DUMP_DIR is not None:
        os.makedirs(DUMP_DIR, exist_ok=True)
        name = f"{os.path.basename(os.path.dirname(path))}.{os.path.basename(path)}.hex"
        with open(os.path.join(DUMP_DIR, name), "w") as f:
            hexdump(d, f, autoskip=False)
        print(f"    full hexdump written to {os.path.join(DUMP_DIR, name)}")
    if DUMP_STDOUT:
        print(f"--- xxd of {path} (repeated lines collapsed to *)")
        hexdump(d, sys.stdout, autoskip=True)
    return True


DUMP_DIR: str | None = None
DUMP_STDOUT = False


def main(paths: list[str]) -> int:
    bad = sum(report(p) for p in paths)
    print(f"checked {len(paths)} cache entries, {bad} damaged")
    return 1 if bad else 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if "--hexdump" in args:
        args.remove("--hexdump")
        DUMP_STDOUT = True
    if "--hexdump-dir" in args:
        i = args.index("--hexdump-dir")
        DUMP_DIR = args[i + 1]
        del args[i:i + 2]
    if not args:
        root = os.path.expanduser("~/.cache/debuginfod_client")
        args = [
            os.path.join(dirpath, f)
            for dirpath, _, files in os.walk(root)
            for f in files
            if f in ("debuginfo", "executable") or f.startswith("section-")
        ]
    sys.exit(main(args))

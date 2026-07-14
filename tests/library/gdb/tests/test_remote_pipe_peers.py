"""
Tests for procinfo's pipe peer discovery over a remote target (gdbserver).

The local implementation walks /proc/*/fd directly; the remote one asks the
stub for its "files" osdata table (qXfer:osdata:read) and reads fdinfo over
vFile. The reference binary forks so that one pipe has its other end in a
*different* process: seeing that peer is only possible through the system-wide
osdata listing, so this can't silently pass through the same-process fallback.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Iterator

import pytest

from . import get_binary
from .utils import run_gdb_with_script

GDBSERVER = shutil.which("gdbserver")
REFERENCE_BINARY_PIPE_FORK = get_binary("reference-binary-pipe-fork.native.out")


@pytest.fixture
def gdbserver_with_pipe_fork_binary() -> Iterator[int]:
    process = subprocess.Popen(
        [GDBSERVER, "127.0.0.1:0", REFERENCE_BINARY_PIPE_FORK],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stderr is not None
    # With port 0 gdbserver picks a free port and announces it on stderr.
    port = None
    for _ in range(20):
        line = process.stderr.readline()
        if not line:
            break
        match = re.search(r"Listening on port (\d+)", line)
        if match:
            port = int(match.group(1))
            break
    if port is None:
        process.kill()
        pytest.fail("gdbserver did not report a listening port")

    yield port

    process.kill()
    process.wait()


@pytest.mark.skipif(GDBSERVER is None, reason="gdbserver is not installed")
def test_procinfo_pipe_peers_on_remote_target(gdbserver_with_pipe_fork_binary: int) -> None:
    port = gdbserver_with_pipe_fork_binary

    result = run_gdb_with_script(
        binary=REFERENCE_BINARY_PIPE_FORK,
        pyafter=[
            # Pwndbg defaults to following the fork *child*; the parent is the
            # side that reaches break_here holding the pipe ends.
            "set follow-fork-mode parent",
            f"target remote 127.0.0.1:{port}",
            "break break_here",
            "continue",
            "procinfo",
        ],
        timeout=120,
    )

    match = re.search(r"^pid\s+(\d+)", result, re.MULTILINE)
    assert match, f"no pid line in procinfo output:\n{result}"
    debuggee_pid = match.group(1)

    pipe_lines = [line for line in result.splitlines() if "pipe:[" in line and "peers:" in line]
    assert pipe_lines, f"no pipe peer lines in procinfo output:\n{result}"

    # The "own" pipe: read end and write end both live in the debuggee, and
    # each end's peer is the debuggee itself.
    assert any("(r, peers:" in line and f"pid={debuggee_pid} " in line for line in pipe_lines), (
        f"no self-peering read end:\n{result}"
    )
    assert any("(w, peers:" in line and f"pid={debuggee_pid} " in line for line in pipe_lines), (
        f"no self-peering write end:\n{result}"
    )

    # The "cross" pipe: its write end lives in the forked child, i.e. a pid
    # other than the debuggee's. Only the osdata-backed system-wide listing
    # can discover it on a remote target.
    peer_pids: set[str] = set()
    for line in pipe_lines:
        peer_pids.update(re.findall(r"pid=(\d+)", line.split("peers:", 1)[1]))
    assert any(pid != debuggee_pid for pid in peer_pids), (
        f"no cross-process pipe peer found (peers all in {debuggee_pid}):\n{result}"
    )

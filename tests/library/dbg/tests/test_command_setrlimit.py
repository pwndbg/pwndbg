from __future__ import annotations

import errno
import shlex
import sys
from pathlib import Path

import pytest

from ....host import Controller
from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.native.out")


@pwndbg_test
async def test_setrlimit_invalid_arguments(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY)
    for command, expected in (
        ("setrlimit unknown 1", "argument resource: invalid choice"),
        ("setrlimit cpu not-a-number", "Invalid limit 'not-a-number'"),
        ("setrlimit cpu 1 invalid_hard", "Invalid limit 'invalid_hard'"),
    ):
        out = await ctrl.execute_and_capture(command)
        assert expected in out


@pytest.mark.skipif(sys.platform != "linux", reason="Checks Linux resource limit enforcement")
@pwndbg_test
async def test_setrlimit_applies_limits(ctrl: Controller, tmp_path: Path) -> None:
    import resource

    import pwndbg.aglib.proc

    await ctrl.launch(REFERENCE_BINARY, env={"LC_ALL": "C"})
    pid = pwndbg.aglib.proc.pid()

    out = await ctrl.execute_and_capture("setrlimit cpu 10")
    assert "Set cpu limit (return=0): soft=10, hard=10" in out
    assert resource.prlimit(pid, resource.RLIMIT_CPU) == (10, 10)

    out = await ctrl.execute_and_capture("setrlimit nofile 32 64")
    assert "Set nofile limit (return=0): soft=32, hard=64" in out
    assert resource.prlimit(pid, resource.RLIMIT_NOFILE) == (32, 64)

    # Exercise the resource IDs missing from the original command. Preserve
    # each current limit rather than imposing host-dependent restrictions.
    for name, resource_num in (
        ("rss", resource.RLIMIT_RSS),
        ("nproc", resource.RLIMIT_NPROC),
        ("memlock", resource.RLIMIT_MEMLOCK),
    ):
        limits = resource.prlimit(pid, resource_num)
        values = ["infinite" if value == resource.RLIM_INFINITY else str(value) for value in limits]
        out = await ctrl.execute_and_capture(f"setrlimit {name} {' '.join(values)}")
        assert f"Set {name} limit (return=0)" in out
        assert resource.prlimit(pid, resource_num) == limits

    # Redirect stderr before setting NOFILE to zero. This must run last: the
    # hard limit cannot be raised again, and continuing exits the dynamic loader.
    stderr_path = tmp_path / "inferior.stderr"
    await ctrl.execute(f"hijack-fd 2 {shlex.quote(str(stderr_path))}")
    out = await ctrl.execute_and_capture("setrlimit nofile 0 0")
    assert "Set nofile limit (return=0): soft=0, hard=0" in out
    assert resource.prlimit(pid, resource.RLIMIT_NOFILE) == (0, 0)

    await ctrl.cont()

    assert not pwndbg.aglib.proc.alive()
    stderr = stderr_path.read_text()
    # Some loaders print the errno number instead of its description.
    assert "Too many open files" in stderr or f"Error {errno.EMFILE}" in stderr

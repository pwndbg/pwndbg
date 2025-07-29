from __future__ import annotations

from ....host import Controller
from . import break_at_sym
from . import get_binary
from . import pwndbg_test

# We use the heap_vis binary as it enforces pthreads and so will have TLS on all distros
REFERENCE_BINARY = get_binary("heap_vis.out")


@pwndbg_test
async def test_command_errno(ctrl: Controller) -> None:
    """
    Tests the errno command display
    """
    await ctrl.launch(REFERENCE_BINARY)

    # Since 'ctrl.launch' stops on the very first instruction, 'errno' might not
    # yet be available, depending on the system. If it is available, it should
    # be zero.
    result = "".join((await ctrl.execute_and_capture("errno")).splitlines())
    assert (
        result
        == "Could not determine error code automatically: neither `errno` nor `__errno_location` symbols were provided (perhaps libc.so hasn't been not loaded yet?)"
    ) or (result == "Errno 0: OK")

    break_at_sym("main")
    await ctrl.cont()

    result = await ctrl.execute_and_capture("errno")
    assert result == "Errno 0: OK\n"

    await ctrl.execute("p *(int*)&errno=11")
    result = await ctrl.execute_and_capture("errno")
    assert result == "Errno 11: EAGAIN\n"

    await ctrl.execute("p *(int*)&errno=111")
    result = await ctrl.execute_and_capture("errno")
    assert result == "Errno 111: ECONNREFUSED\n"

    result = await ctrl.execute_and_capture("errno 8")
    assert result == "Errno 8: ENOEXEC\n"

    result = await ctrl.execute_and_capture("errno 123")
    assert result == "Errno 123: ENOMEDIUM\n"

    result = await ctrl.execute_and_capture("errno 250")
    assert result == "Errno 250: Unknown error code\n"

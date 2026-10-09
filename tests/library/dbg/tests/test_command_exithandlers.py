from __future__ import annotations

from ....host import Controller
from . import break_at_sym
from . import get_binary
from . import launch_to
from . import pwndbg_test

EXITHANDLERS_BINARY = get_binary("exithandlers.native.out")


@pwndbg_test
async def test_command_exithandlers(ctrl: Controller) -> None:
    import pwndbg.aglib.memory
    import pwndbg.aglib.symbol
    import pwndbg.aglib.vmmap

    await ctrl.launch(EXITHANDLERS_BINARY)
    await launch_to(ctrl, EXITHANDLERS_BINARY, "main")
    out = await ctrl.execute_and_capture("exithandlers")
    assert "No tls_dtor handlers registered." in out
    assert "No __exit_funcs handlers registered." not in out
    out_lines = out.splitlines()
    assert "Registered __exit_funcs handlers:" in out_lines
    dl_fini_handler_line = out_lines[out_lines.index("Registered __exit_funcs handlers:") + 1]
    assert "[ef_cxa (4)]" in dl_fini_handler_line
    dl_fini_entry_addr_and_symbol = dl_fini_handler_line.split(":")[1].split("[")[0].strip()
    if (
        "(_dl_fini)" in dl_fini_entry_addr_and_symbol
        and (dl_fini_real_addr := pwndbg.aglib.symbol.lookup_symbol("_dl_fini")) is not None
    ):
        assert int(dl_fini_entry_addr_and_symbol.split(" ")[0], 16) == int(dl_fini_real_addr)
    else:
        # strip for LLDB ('0x7ffff7fc6e60 (___lldb_unnamed_symbol_5e60)')
        dl_fini_entry_addr_and_symbol = dl_fini_entry_addr_and_symbol.split(" ")[0]
        dl_fini_entry_addr = int(dl_fini_entry_addr_and_symbol, 16)
        assert pwndbg.aglib.memory.is_readable_address(dl_fini_entry_addr)
        assert (dl_fini_page := pwndbg.aglib.vmmap.find(dl_fini_entry_addr)) is not None
        assert dl_fini_page.X_OK

    break_at_sym("break_here")
    await ctrl.cont()
    out = await ctrl.execute_and_capture("exithandlers")
    assert "No tls_dtor handlers registered." not in out
    assert "No __exit_funcs handlers registered." not in out
    out_lines = out.splitlines()
    assert "Registered __exit_funcs handlers:" in out_lines
    exit_funcs_start = out_lines.index("Registered __exit_funcs handlers:")
    system_entry = out_lines[exit_funcs_start + 1]
    deadbeef_cxa_entry = out_lines[exit_funcs_start + 2]
    # need to delete whitespace since the table alignment can make the lines differ
    assert out_lines[exit_funcs_start + 3].replace(" ", "") == dl_fini_handler_line.replace(" ", "")
    assert "[ef_on (2)]" in system_entry
    assert "'/bin/whoami'" in system_entry  # arg chain
    assert (
        "(system" in system_entry or "(__libc_system" in system_entry
    )  # no closing brace to allow @plt, @plt.got, etc
    # don't assert for the actual system address, as this is not reliable (probably something to do with relocations...)
    assert "[ef_cxa (4)]" in deadbeef_cxa_entry
    assert "0xdeadbeef" in deadbeef_cxa_entry
    assert "arg = 0" in deadbeef_cxa_entry

    tls_dtor_entry = out_lines[out_lines.index("Registered tls_dtor handlers:") + 1]
    assert "0xcafebabe" in tls_dtor_entry
    assert "obj = 0xfeedface" in tls_dtor_entry

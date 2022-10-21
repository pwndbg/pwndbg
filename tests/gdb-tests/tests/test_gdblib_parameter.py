import gdb
import pytest

import pwndbg.gdblib.config


@pytest.mark.parametrize(
    "params",
    (("int", 123, "123"), ("bool", True, "on"), ("string", "some-string-val", "some-string-val")),
)
def test_gdb_parameter_default_value_works(start_binary, params):
    name_suffix, default_value, displayed_value = params

    param_name = f"test-param-{name_suffix}"

    param = pwndbg.gdblib.config.add_param(param_name, default_value, "some show string")

    # Initialize and register param in GDB as if it would be done by gdblib.config.init_params
    pwndbg.gdblib.config_mod.Parameter(param)

    out = gdb.execute(f"show {param_name}", to_string=True)
    assert out in (
        f"""The current value of '{param_name}' is "{displayed_value}".\n""",  # GDB 12.x
        f"Show some show string {displayed_value}\n",  # GDB 9.x
    )
    assert gdb.parameter(param_name) == default_value

    # TODO/FIXME: We need to add documentation
    out = gdb.execute(f"help show {param_name}", to_string=True)
    assert out == "Show some show string\nThis command is not documented.\n"
    assert (
        gdb.execute(f"help set {param_name}", to_string=True)
        == "Set some show string\nThis command is not documented.\n"
    )

    # TODO/FIXME: Is there a way to unregister a GDB parameter defined in Python?
    # Probably no? If the fact that we register params above ever causes issues,
    # then we should just not test it via gdb.* APIs and only check if the added param
    # has proper/expected fields set?

import gdb
import pytest

import pwndbg.gdblib.config


@pytest.mark.parametrize(
    "params",
    (
        ("int", 123, "123", {}),
        ("bool", True, "on", {}),
        ("bool", False, "off", {}),
        ("string", "some-string-val", "some-string-val", {}),
        ("auto-bool", None, "auto", {"param_class": gdb.PARAM_AUTO_BOOLEAN}),
        ("unlimited-uint", 0, "unlimited", {"param_class": gdb.PARAM_UINTEGER}),
        ("unlimited-int", 0, "unlimited", {"param_class": gdb.PARAM_INTEGER}),
        # GDB < 9.x does not support PARAM_ZUINTEGER_UNLIMITED
        ("unlimited-zuint", -1, "unlimited", {"param_class": gdb.PARAM_ZUINTEGER_UNLIMITED})
        if hasattr(gdb, "PARAM_ZUINTEGER_UNLIMITED")
        else (),
        (
            "enum",
            "enum1",
            "enum1",
            {"param_class": gdb.PARAM_ENUM, "enum_sequence": ["enum1", "enum2", "enum3"]},
        ),
    ),
)
def test_gdb_parameter_default_value_works(start_binary, params):
    if not params:
        pytest.skip("Current GDB version does not support this testcase")

    name_suffix, default_value, displayed_value, optional_kwargs = params

    param_name = f"test-param-{name_suffix}"
    help_docstring = f"Help docstring for {param_name}"

    param = pwndbg.gdblib.config.add_param(
        param_name,
        default_value,
        "some show string",
        help_docstring=help_docstring,
        **optional_kwargs,
    )

    # Initialize and register param in GDB as if it would be done by gdblib.config.init_params
    pwndbg.gdblib.config_mod.Parameter(param)

    out = gdb.execute(f"show {param_name}", to_string=True)
    assert out == f"The current value of {param_name!r} is {displayed_value!r}\n"
    if (
        optional_kwargs.get("param_class") in (gdb.PARAM_UINTEGER, gdb.PARAM_INTEGER)
        and default_value == 0
    ):
        # Note: This is really weird, according to GDB docs, 0 should mean "unlimited" for gdb.PARAM_UINTEGER and gdb.PARAM_INTEGER, but somehow GDB sets the value to `None` actually :/
        # And hilarious thing is that GDB won't let you set the default value to `None` when you construct the `gdb.Parameter` object with `gdb.PARAM_UINTEGER` or `gdb.PARAM_INTEGER` lol
        # Maybe it's a bug of GDB?
        # Anyway, to avoid some unexpected behaviors, we still set pwndbg's Parameter object's value to 0 in `get_set_string()` and `__init__()`
        assert gdb.parameter(param_name) is None
    else:
        assert gdb.parameter(param_name) == default_value
    assert param.value == default_value

    out = gdb.execute(f"help show {param_name}", to_string=True)
    assert out == f"Show some show string\n{help_docstring}\n"
    assert (
        gdb.execute(f"help set {param_name}", to_string=True)
        == f"Set some show string\n{help_docstring}\n"
    )

    # TODO/FIXME: Is there a way to unregister a GDB parameter defined in Python?
    # Probably no? If the fact that we register params above ever causes issues,
    # then we should just not test it via gdb.* APIs and only check if the added param
    # has proper/expected fields set?

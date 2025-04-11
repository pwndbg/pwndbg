from __future__ import annotations

import gdb
import pytest

import pwndbg.dbg
import pwndbg.lib.config


@pytest.mark.parametrize(
    "params",
    (
        ("int", 123, "123", {}),
        ("bool", True, "on", {}),
        ("bool", False, "off", {}),
        ("string", "some-string-val", "some-string-val", {}),
        ("auto-bool", None, "auto", {"param_class": pwndbg.lib.config.PARAM_AUTO_BOOLEAN}),
        ("unlimited-uint", 0, "unlimited", {"param_class": pwndbg.lib.config.PARAM_UINTEGER}),
        ("unlimited-int", 0, "unlimited", {"param_class": pwndbg.lib.config.PARAM_INTEGER}),
        (
            "enum",
            "enum1",
            "enum1",
            {
                "param_class": pwndbg.lib.config.PARAM_ENUM,
                "enum_sequence": ["enum1", "enum2", "enum3"],
            },
        ),
        # Note: GDB < 9 does not support PARAM_ZUINTEGER*, so we implement it by ourselves for consistency
        (
            "zuint",
            0,
            "0",
            {
                "param_class": (
                    pwndbg.lib.config.PARAM_ZUINTEGER
                    if hasattr(gdb, "PARAM_ZUINTEGER")
                    else "PARAM_ZUINTEGER"
                )
            },
        ),
        (
            "unlimited-zuint",
            -1,
            "unlimited",
            {
                "param_class": (
                    pwndbg.lib.config.PARAM_ZUINTEGER_UNLIMITED
                    if hasattr(gdb, "PARAM_ZUINTEGER_UNLIMITED")
                    else "PARAM_ZUINTEGER_UNLIMITED"
                )
            },
        ),
    ),
)
def test_gdb_parameter_default_value_works(start_binary, params):
    if not params:
        pytest.skip("Current GDB version does not support this testcase")

    name_suffix, default_value, displayed_value, optional_kwargs = params

    param_name = f"test-param-{name_suffix}"
    help_docstring = f"Help docstring for {param_name}"

    set_show_doc = "the value of the foo"

    param = pwndbg.config.add_param(
        param_name,
        default_value,
        set_show_doc,
        help_docstring=help_docstring,
        **optional_kwargs,
    )

    # Initialize and register param in GDB as if it would be done by gdblib.config.init_params
    if pwndbg.dbg.is_gdblib_available():
        from pwndbg.gdblib import config_mod as gdblib_config_mod

        gdblib_config_mod.Parameter(param)

    out = gdb.execute(f"show {param_name}", to_string=True)
    assert (
        out
        == f"{set_show_doc.capitalize()} is {displayed_value!r}. See `help set {param_name}` for more information.\n"
    )
    if (
        optional_kwargs.get("param_class")
        in (pwndbg.lib.config.PARAM_UINTEGER, pwndbg.lib.config.PARAM_INTEGER)
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

    # help_docstring is modified inside the Parameter constructor

    out = gdb.execute(f"help show {param_name}", to_string=True)
    assert out == f"Show {set_show_doc}.\n{param.help_docstring}\n"
    assert (
        gdb.execute(f"help set {param_name}", to_string=True)
        == f"Set {set_show_doc}.\n{param.help_docstring}\n"
    )

    # TODO/FIXME: Is there a way to unregister a GDB parameter defined in Python?
    # Probably no? If the fact that we register params above ever causes issues,
    # then we should just not test it via gdb.* APIs and only check if the added param
    # has proper/expected fields set?

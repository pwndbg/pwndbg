from __future__ import annotations

from unittest import mock

import gdb

import pwndbg.lib.config
from pwndbg import config


def set_show(param_name, value):
    gdb.execute(f"show {param_name}")
    gdb.execute(f"set {param_name} {value}")
    gdb.execute(f"show {param_name}")


def single_param(param_name, triggers):
    p = getattr(config, param_name.replace("-", "_"))

    mock_triggers = []
    for trigger in triggers:
        mock_triggers.append(mock.Mock(side_effect=trigger))

    orig_triggers = config.triggers[param_name]
    config.triggers[param_name] = mock_triggers

    if p.value is True:
        set_show(param_name, "off")
    elif p.value is False:
        set_show(param_name, "on")
    elif isinstance(p.value, int):
        set_show(param_name, 0)
        set_show(param_name, 1)
        set_show(param_name, -1)
    elif isinstance(p.value, str) and p.param_class != pwndbg.lib.config.PARAM_ENUM:
        set_show(param_name, "")
        set_show(param_name, "some invalid text")
        set_show(param_name, "red")
        set_show(param_name, "bold,yellow")
    elif isinstance(p.value, str) and p.param_class == pwndbg.lib.config.PARAM_ENUM:
        # Only valid values are allowed, invalid values will cause an error
        for enum in p.enum_sequence:
            set_show(param_name, enum)
    else:
        print(p.value, type(p.value))
        assert False

    for mock_trigger in mock_triggers:
        mock_trigger.assert_called()

    config.triggers[param_name] = orig_triggers


def test_triggers():
    # The behavior of some triggers depend on the value of other parameters!
    #
    # This means that the order in which we run through the parameters matters,
    # and, in particular, some instances will cause the test to fail, where
    # others will not. If this test starts failing seemingly for no reason after
    # a change to the order of imports, this might be the reason.
    #
    # Important time dependencies to keep in mind:
    #     - `disable-colors` will normally be disabled during the test, so we
    #       must ensure this only happens after this test case has gone through
    #       all parameters that set color, or the test will likely fail.
    #

    deferred = []
    for param_name, triggers in config.triggers.items():
        if param_name == "disable-colors":
            deferred.append((param_name, triggers))
            continue

        single_param(param_name, triggers)

    for param_name, triggers in deferred:
        single_param(param_name, triggers)

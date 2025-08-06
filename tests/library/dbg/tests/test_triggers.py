from __future__ import annotations

from typing import Any
from unittest import mock

from ....host import Controller
from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.out")


async def set_param(ctrl: Controller, param_name: str, value: Any):
    await ctrl.execute(f"set {param_name} {value}")


async def single_param(ctrl: Controller, param_name: str, triggers: Any):
    import pwndbg
    from pwndbg import config

    p = getattr(config, param_name.replace("-", "_"))

    mock_triggers = []
    # Side-effects of some `integration-provider` triggers require GDB.
    if param_name != "integration-provider" or pwndbg.dbg.is_gdblib_available():
        for trigger in triggers:
            mock_triggers.append(mock.Mock(side_effect=trigger))

    orig_triggers = config.triggers[param_name]
    config.triggers[param_name] = mock_triggers

    if p.value is True:
        await set_param(ctrl, param_name, "off")
    elif p.value is False:
        await set_param(ctrl, param_name, "on")
    elif isinstance(p.value, int):
        await set_param(ctrl, param_name, 0)
        await set_param(ctrl, param_name, 1)
        await set_param(ctrl, param_name, -1)
    elif isinstance(p.value, str) and p.param_class != pwndbg.lib.config.PARAM_ENUM:
        await set_param(ctrl, param_name, "")
        await set_param(ctrl, param_name, "some invalid text")
        await set_param(ctrl, param_name, "red")
        await set_param(ctrl, param_name, "bold,yellow")
    elif isinstance(p.value, str) and p.param_class == pwndbg.lib.config.PARAM_ENUM:
        # Only valid values are allowed, invalid values will cause an error
        for enum in p.enum_sequence:
            await set_param(ctrl, param_name, enum)
    else:
        print(p.value, type(p.value))
        assert False

    for mock_trigger in mock_triggers:
        mock_trigger.assert_called()

    config.triggers[param_name] = orig_triggers


@pwndbg_test
async def test_triggers(ctrl: Controller) -> None:
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
    from pwndbg import config

    # Some triggers require an active inferior, so launch it.
    await ctrl.launch(REFERENCE_BINARY)

    deferred = []
    for param_name, triggers in config.triggers.items():
        if param_name == "disable-colors":
            deferred.append((param_name, triggers))
            continue

        await single_param(ctrl, param_name, triggers)

    for param_name, triggers in deferred:
        await single_param(ctrl, param_name, triggers)

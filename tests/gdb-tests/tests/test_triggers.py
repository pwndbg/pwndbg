from unittest import mock

import gdb

from pwndbg.gdblib import config


def set_show(param_name, value):
    gdb.execute("show %s" % param_name)
    gdb.execute("set %s %s" % (param_name, value))
    gdb.execute("show %s" % param_name)


def test_triggers():
    for param_name, triggers in config.triggers.items():
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
        elif isinstance(p.value, str):
            set_show(param_name, "")
            set_show(param_name, "some invalid text")
            set_show(param_name, "red")
            set_show(param_name, "bold,yellow")
        else:
            print(p.value, type(p.value))
            assert False

        for mock_trigger in mock_triggers:
            mock_trigger.assert_called()

        config.triggers[param_name] = orig_triggers

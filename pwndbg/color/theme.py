import pwndbg.lib.config
from pwndbg.gdblib import config


class ColorParameter(pwndbg.lib.config.Parameter):
    pass


def add_param(name, default, docstring, color_param=False):
    return config.add_param(name, default, docstring, "theme")


def add_color_param(name, default, docstring):
    return config.add_param_obj(ColorParameter(name, default, docstring, scope="theme"))

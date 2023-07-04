import pwndbg.lib.config
from pwndbg.gdblib import config


class ColorParameter(pwndbg.lib.config.Parameter):
    pass


def add_param(name: str, default, set_show_doc, color_param: bool = False):
    return config.add_param(name, default, set_show_doc, scope="theme")


def add_color_param(name: str, default, set_show_doc):
    return config.add_param_obj(ColorParameter(name, default, set_show_doc, scope="theme"))

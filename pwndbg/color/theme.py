import pwndbg.gdblib.config


def add_param(name, default, docstring):
    return pwndbg.gdblib.config.add_param(name, default, docstring, "theme")


def add_color_param(name, default, docstring):
    return add_param(name, default, docstring)

from pwndbg.gdblib import config


def add_param(name, default, docstring):
    return config.add_param(name, default, docstring, "theme")


def add_color_param(name, default, docstring):
    return add_param(name, default, docstring)

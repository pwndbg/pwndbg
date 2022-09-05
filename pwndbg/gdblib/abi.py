import functools

import gdb

import pwndbg.color.message as M
import pwndbg.gdblib.events

abi = None
linux = False


# TODO: Maybe move this to hooks.py?
@pwndbg.gdblib.events.start
def update():
    global abi
    global linux

    # Detect current ABI of client side by 'show osabi'
    #
    # Examples of strings returned by `show osabi`:
    # 'The current OS ABI is "auto" (currently "GNU/Linux").\nThe default OS ABI is "GNU/Linux".\n'
    # 'The current OS ABI is "GNU/Linux".\nThe default OS ABI is "GNU/Linux".\n'
    # 'El actual SO ABI es «auto» (actualmente «GNU/Linux»).\nEl SO ABI predeterminado es «GNU/Linux».\n'
    # 'The current OS ABI is "auto" (currently "none")'
    #
    # As you can see, there might be GDBs with different language versions
    # and so we have to support it there too.
    # Lets assume and hope that `current osabi` is returned in first line in all languages...
    abi = gdb.execute("show osabi", to_string=True).split("\n")[0]

    # Currently we support those osabis:
    # 'GNU/Linux': linux
    # 'none': bare metal

    linux = "GNU/Linux" in abi

    if not linux:
        msg = M.warn(
            "The bare metal debugging is enabled since gdb's osabi is '%s' which is not 'GNU/Linux'.\n"
            "Ex. the page resolving and memory de-referencing ONLY works on known pages.\n"
            "This option is based on gdb client compile arguments (by default) and will be corrected if you load an ELF with a '.note.ABI-tag' section.\n"
            "If you are debugging a program that runs on the Linux ABI, please select the correct gdb client."
            % abi
        )
        print(msg)


def LinuxOnly(default=None):
    """Create a decorator that the function will be called when ABI is Linux.
    Otherwise, return `default`.
    """

    def decorator(func):
        @functools.wraps(func)
        def caller(*args, **kwargs):
            if linux:
                return func(*args, **kwargs)
            else:
                return default

        return caller

    return decorator


# Update when starting the gdb to show warning message for non-Linux ABI user.
update()

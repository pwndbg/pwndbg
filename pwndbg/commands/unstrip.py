import os.path

from pwnlib.libcdb import unstrip_libc

import pwndbg.commands
from pwndbg.color import message
from pwndbg.vmmap import info_sharedlibrary


def _is_libc(path):
    filename = os.path.basename(path)
    # TODO: this will lead to false positives
    if filename == "libc.so.6" or (filename.startswith("libc") and filename.endswith(".so")):
        return True


@pwndbg.commands.ArgparsedCommand("Unstrips the current libc")
def unstrip():
    mappings = info_sharedlibrary()
    for mapping in mappings:
        path = mapping.objfile
        if _is_libc(path):
            print(message.notice("Attempting to unstrip %s" % path))
            if unstrip_libc(mapping.objfile):
                print(message.success("Successfully unstripped libc"))
                break
            else:
                print(message.error("Failed to unstrip libc"))

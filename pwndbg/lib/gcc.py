"""
Functions for determining the architecture-dependent path to
GCC and any flags it should be executed with.
"""

from __future__ import annotations

import glob
import os
import platform
from typing import Any
from typing import List

from pwndbg.lib.arch import ArchDefinition

printed_message = False


def which(arch: ArchDefinition) -> List[str]:
    gcc = _which_binutils("g++", arch)

    if gcc is None:
        global printed_message
        if not printed_message:
            printed_message = True
            print("Can't find appropriate GCC, using default version")

        if arch.ptrsize == 32:
            return ["g++", "-m32"]
        elif arch.ptrsize == 64:
            return ["g++", "-m32"]
        else:
            raise ValueError(f"Unknown pointer size: {arch.ptrsize}")

    return [gcc] + _flags(arch.name)


def _which_binutils(util: str, arch: ArchDefinition, **kwargs: Any) -> str | None:
    ###############################
    # Borrowed from pwntools' code
    ###############################

    arch_name = arch.name

    # Fix up binjitsu vs Debian triplet naming, and account
    # for 'thumb' being its own binjitsu architecture.
    arches: List[str | None] = [arch_name] + {
        "thumb": ["arm", "armcm", "aarch64"],
        "i386": ["x86_64", "amd64"],
        "i686": ["x86_64", "amd64"],
        "i386:x86-64": ["x86_64", "amd64"],
        "amd64": ["x86_64", "i386"],
    }.get(arch_name, [])

    # If one of the candidate architectures matches the native
    # architecture, use that as a last resort.
    machine = platform.machine()
    machine = "i386" if machine == "i686" else machine

    if arch_name in arches:
        arches.append(None)

    for arch_name in arches:
        # hack for homebrew-installed binutils on mac
        for gutil in ["g" + util, util]:
            # e.g. objdump
            if arch_name is None:
                pattern = gutil

            # e.g. aarch64-linux-gnu-objdump
            else:
                pattern = f"{arch_name}*linux*-{gutil}"

            for dir in os.environ["PATH"].split(":"):
                res = sorted(glob.glob(os.path.join(dir, pattern)))
                if res:
                    return res[0]

    return None


def _flags(arch_name: str) -> List[str]:
    if arch_name == "i386":
        return ["-m32"]
    if arch_name.endswith("x86-64"):
        return ["-m64"]

    return []

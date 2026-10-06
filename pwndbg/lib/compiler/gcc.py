from __future__ import annotations

import shutil
from typing import Literal

from dispatch import CompilerType

from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE
from pwndbg.lib.arch import ArchDefinition
from pwndbg.lib.err import DependencyNotFoundError

from .util import compiler_target_triple


def type() -> CompilerType:
    return CompilerType.GCC

# Alright so, in the wonderful case of gcc, the name of the compiler binary depends on what
# you supplied to ./configure when building it, so the target triple you're supposed to use
# depends on the distribution.
# e.g.
# debian / ubuntu / arch: aarch64-linux-gnu-gcc
# nixos:                  aarch64-unknown-linux-gnu-gcc
# alpine:                 aarch64-alpine-linux-musl-gcc
#        (though this is not glibc...)

# Fortunately, we are not the first to have to solve this problem of
# gcc toolchain autodetection:
# https://github.com/llvm/llvm-project/blob/d7225c0591ba1b79afca445f73b0d1c84e9a5d83/clang/lib/Driver/ToolChains/Gnu.cpp#L2108
# https://github.com/rust-lang/cc-rs/blob/2ac0cd630dbdd2829d1d7b7ac4415aaf5c8a6f19/src/lib.rs#L4318

# Unfortunately, the solutions are quite chonky, and I would rather not have all that
# complexity here.

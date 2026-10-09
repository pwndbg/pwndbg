from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

import pwndbg.lib.cache
from pwndbg.color import gray
from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE
from pwndbg.lib.arch import ArchDefinition
from pwndbg.lib.err import CompilerNotFoundError
from pwndbg.lib.err import DependencyNotFoundError
from pwndbg.lib.err import Status

from . import clang
from . import gcc
from . import zig
from .dispatch import Compiler
from .dispatch import CompilerType
from .dispatch import ToolchainInvocation

# Order is important.
_compilers: tuple[Compiler, ...] = (zig, clang, gcc)


@pwndbg.lib.cache.cache_until("start", "objfile")
def __get_compiler(
    arch: ArchDefinition,
) -> tuple[ToolchainInvocation, Compiler] | str:
    """
    Find a working toolchain for the given target arch.

    `arch` must be aglib.arch.

    Returns:
        The suitable compiler with its toolchain information,
        or an error message string if lookup failed.
    """
    print(gray(f"Compiler for {arch.name} needed, looking for it... "), end="", flush=True)

    potentials: list[ToolchainInvocation | None] = []
    best: tuple[ToolchainInvocation, Compiler] | None = None
    errors: list[DependencyNotFoundError] = []
    for candidate_compiler in _compilers:
        try:
            invoc: ToolchainInvocation | None = candidate_compiler.invocation_with_target(arch)
            if invoc.objcopy is not None:
                # It's important to exit early if possible because finding gcc is slow
                best = (invoc, candidate_compiler)
                break
        except DependencyNotFoundError as e:
            print(gray(f"{candidate_compiler.type().value} not present.."), end="", flush=True)
            errors.append(e)
            invoc = None
        potentials.append(invoc)

    if best is not None:
        # clear line
        print("\x1b[2K\r", end="")
        print(gray(f"Using compiler {best[1].type().value} for {arch.name}."))
        return best

    # There is no compiler which also has objcopy, but maybe there is one
    # without it?
    # FIXME: I tie in compiler & objcopy detection because for GCC the
    # path search is expensive and they share the same prefix. For zig
    # it will always return it.
    # But it can be that one has gcc but not binutils or has clang but
    # not llvm or vice-versa, so probably this should be decoupled.

    for anything, candidate_compiler in zip(potentials, _compilers, strict=True):
        if anything is not None:
            # Yup!
            # clear line
            print("\x1b[2K\r", end="")
            print(
                gray(
                    f"Using compiler {candidate_compiler.type().value} for {arch.name} (no objcopy though)."
                )
            )
            return anything, candidate_compiler

    print()
    return "\n\t" + "\n\t".join([str(err) for err in errors])


def _get_compiler(arch: ArchDefinition) -> tuple[ToolchainInvocation, Compiler]:
    """
    Find a working toolchain for the given target arch.

    `arch` must be aglib.arch.

    Raises:
        CompilerNotFoundError: if a compiler for the target arch could not be found
    """
    res = __get_compiler(arch)
    if isinstance(res, str):
        raise CompilerNotFoundError(res)

    return res


def invocation(arch: ArchDefinition, compiler_arguments: list[str]) -> list[str]:
    """
    Return the command line invocation for running the compiler with
    `compiler_arguments` flags against the target arch.

    `arch` must be aglib.arch.
    """
    toolchain, _ = _get_compiler(arch)
    return toolchain.compiler + compiler_arguments


def objcopy_invocation(arch: ArchDefinition, objcopy_arguments: list[str]) -> list[str]:
    """
    Return the command line invocation for running the compiler toolchain's objcopy with
    `objcopy_arguments` flags against the target arch.

    `arch` must be aglib.arch.
    """
    toolchain, compiler = _get_compiler(arch)
    if toolchain.objcopy is None:
        raise DependencyNotFoundError(
            "objcopy", f"{compiler.type().value} is the current compiler but has no objcopy"
        )
    return toolchain.objcopy + objcopy_arguments


def which(arch: ArchDefinition) -> str:
    """
    Which compiler are we using?
    """
    _, compiler = _get_compiler(arch)
    return compiler.type().value


# =================== Higher level API ===============

# ===== Assembling =====

_asm_prefix_header = ".global _start\n.global __start\n.section .text\n_start:\n__start:\n"
_asm_header: dict[PWNDBG_SUPPORTED_ARCHITECTURES_TYPE, str] = {
    # `.intel_syntax noprefix` forces the use of Intel assembly syntax instead of AT&T
    "x86-64": _asm_prefix_header + ".intel_syntax noprefix\n",
    "i386": _asm_prefix_header + ".intel_syntax noprefix\n",
    "i8086": _asm_prefix_header + ".intel_syntax noprefix\n",
    # `.set noreorder` disables instruction reordering for MIPS to handle delay slots correctly
    "mips": _asm_prefix_header + ".set noreorder\n",
    "aarch64": _asm_prefix_header,
    # `.syntax unified` enables the unified assembly syntax for ARM/Thumb
    "arm": _asm_prefix_header + ".syntax unified\n.arm\n",
    "armcm": _asm_prefix_header + ".syntax unified\n.thumb\n",
    "rv32": _asm_prefix_header,
    "rv64": _asm_prefix_header,
    "sparc": _asm_prefix_header,
    "powerpc": _asm_prefix_header,
    "loongarch64": _asm_prefix_header,
    "s390x": _asm_prefix_header,
    "hexagon": _asm_prefix_header,
}
_asm_flags: dict[PWNDBG_SUPPORTED_ARCHITECTURES_TYPE, list[str]] = {
    "mips": ["-fno-pic", "-mno-abicalls"],  # needed for gcc
    "rv32": ["-mno-relax"],  # clang gets messed up without these
    "rv64": ["-mno-relax"],
}


class AssemblingError(Exception):
    """
    Error while running the assembler.
    """


def asm(arch: ArchDefinition, data: str, includes: list[Path] | None = None) -> bytes:
    """
    Assemble the `data` string for the passed architecture and return the assembled bytes.

    This does NOT return a runable ELF nor link against the operating system, it returns
    the raw bytes that can be directly run inside a process.

    FIXME: When assembling for armeb this always emits BE32, never BE8, even though there's
    lots of stuff that runs BE8. To emit BE8 we need to add a linking step or fix the bytes
    ourselves.

    Arguments:
        arch: must be aglib.arch
        data: the assembly
        includes: list of extra files to include

    Raises:
        CompilerNotFoundError: if a compiler for the target arch could not be found
        DependencyNotFoundError: if objcopy is not present with the associated compiler
        AssemblingError: if the compiler failed to assemble
    """
    toolchain, compiler = _get_compiler(arch)

    if toolchain.objcopy is None:
        raise DependencyNotFoundError(
            "objcopy", f"{compiler.type().value} is the current compiler but has no objcopy"
        )

    header = _asm_header.get(arch.name)
    assert header is not None

    if includes is None:
        includes = []

    include_str: str = "".join(f'#include "{path}"\n' for path in includes)

    with tempfile.TemporaryDirectory() as tmpdir:
        asm_file = os.path.join(tmpdir, "input.S")
        compiled_file = os.path.join(tmpdir, "out.elf")
        bytecode_file = os.path.join(tmpdir, "out.bytecode")

        with open(asm_file, "w") as f:
            f.write(include_str)
            f.write(header)
            f.write(data)

        extra_asm_flags: list[str] = _asm_flags.get(arch.name, [])

        print(
            gray(f"Assembling for {arch.name} with {compiler.type().value}... "), end="", flush=True
        )

        # Build the binary with the assembler
        compile_process = subprocess.run(
            toolchain.freestanding_assembler + extra_asm_flags + [asm_file, "-o", compiled_file],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
        )
        if compile_process.returncode != 0:
            raise AssemblingError(
                "assembling error:", compile_process.stdout, compile_process.stderr
            )

        # clear line
        print("\x1b[2K\r", end="", flush=True)

        # Check if we have relocations, if yes this is a bug in pwndbg (or assembler)
        with open(compiled_file, "rb") as f:
            elf = ELFFile(f)
            # zig emits relocations for debug info (??) so we ignore that
            text_idx = elf.get_section_index(".text")
            has_relocs = any(
                isinstance(s, RelocationSection)
                and s["sh_info"] == text_idx
                and s.num_relocations()
                for s in elf.iter_sections()
            )
            if has_relocs:
                raise AssemblingError(
                    "assembling error:",
                    "result has relocations. this is a bug in Pwndbg, report it please",
                )

        zig_hint = (
            " (zig compiles objcopy on first usage)" if compiler.type() == CompilerType.ZIG else ""
        )
        print(
            gray(
                f"Assembling (objcopy) for {arch.name} with {compiler.type().value}{zig_hint}... "
            ),
            end="",
            flush=True,
        )

        # Extract bytecode
        objcopy_process = subprocess.run(
            toolchain.objcopy
            + ["-O", "binary", "--only-section=.text", compiled_file, bytecode_file],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
        )
        if objcopy_process.returncode != 0:
            raise AssemblingError("objcopy error:", objcopy_process.stdout, objcopy_process.stderr)

        # clear line
        print("\x1b[2K\r", end="", flush=True)

        with open(bytecode_file, "rb") as f:
            return f.read()


# ====== Compiling =====


def compile_program(arch: ArchDefinition, compiler_flags: list[str]) -> Status:
    """
    Compile a C program.

    Arguments:
        arch: Must be aglib.arch.
        compiler_flags: The flags to pass to the compiler, including the input and
            output files.

    Returns:
        A status object carrying an error message if compilation failed.
    """
    toolchain, _ = _get_compiler(arch)
    commandline: list[str] = toolchain.compiler + compiler_flags
    try:
        # capture_output=True makes it so the compilation errors are not instantly
        # dumped to the user, but are in the CalledProcessError object.
        # https://docs.python.org/3/library/subprocess.html#subprocess.run:~:text=stdout%20and%20stderr%20if%20they%20were%20captured
        subprocess.run(commandline, check=True, text=True, capture_output=True)
        return Status()
    except subprocess.CalledProcessError as exception:
        return Status.fail(
            str(exception)
            + f"\nStdout: {exception.stdout}"
            + f"\nStderr: {exception.stderr}"
            + f"\nFailed to compile {compiler_flags[0]}. Please fix any compilation errors there may be."
        )
    except Exception as exception:
        return Status.fail(str(exception) + "\nAn error occurred while compiling.")

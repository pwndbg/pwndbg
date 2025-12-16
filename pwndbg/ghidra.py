"""
Ghidra integration.
"""

from __future__ import annotations

import os

import pwndbg.aglib
import pwndbg.aglib.proc
import pwndbg.color.context as C
import pwndbg.color.syntax_highlight as H
import pwndbg.dbg_mod
import pwndbg.radare2
import pwndbg.rizin

if pwndbg.dbg.is_gdblib_available():
    import pwndbg.gdblib.symbol


decompiler = pwndbg.config.add_param(
    "decompiler",
    "radare2",
    "framework that your ghidra plugin installed",
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=["radare2", "rizin"],
)


def decompile(func=None):
    """
    Return the source of the given function decompiled by ghidra.

    If no function is given, decompile the function within the current pc.
    This function requires radare2, r2pipe and r2ghidra, or their related rizin counterparts.

    Raises Exception if any fatal error occurs.
    """
    func_specified = func is not None
    try:
        if decompiler == "radare2":
            r = pwndbg.radare2.r2pipe()
        elif decompiler == "rizin":
            r = pwndbg.rizin.rzpipe()
    except ImportError:
        raise Exception("r2pipe or rzpipe not available, but required for r2/rz->ghidra bridge")

    if pwndbg.aglib.qemu.is_qemu_kernel():
        pc = pwndbg.aglib.regs.read_reg(pwndbg.aglib.regs.current.pc)
        if func is None:
            func = pwndbg.aglib.symbol.resolve_addr(pc)
            if func is not None:
                func = func.split("+")[0]
        if func is not None:
            func = f"sym.{func}"

    if not func:
        func = (
            hex(pwndbg.aglib.regs.read_reg(pwndbg.aglib.regs.current.pc))
            if pwndbg.aglib.proc.alive()
            else "main"
        )

    r.cmd(f"afr @ {func}")
    src = r.cmdj("pdgj @ " + func)
    if not src:
        raise Exception(f"Decompile command failed, check if '{func}' is a valid target")

    current_line_marker = "/*%%PWNDBG_CODE_MARKER%%*/"
    source = src.get("code", "")
    closest_line = 1

    # If not running there is no current pc to mark
    if pwndbg.aglib.proc.alive():
        pc = pwndbg.aglib.regs.read_reg(pwndbg.aglib.regs.current.pc)

        closest = 0
        for off in (a.get("offset", 0) for a in src.get("annotations", [])):
            if off == 0 and pc > 0x1000:
                continue
            if abs(pc - closest) > abs(pc - off):
                closest = off
        pos_annotations = sorted(
            [a for a in src.get("annotations", []) if a.get("offset") == closest],
            key=lambda a: a["start"],
        )

        # Append code prefix marker for the current line and replace it later
        if pos_annotations:
            curline = closest_line = source.count("\n", 0, pos_annotations[0]["start"])
            source = source.split("\n")
            line = source[curline]
            if line.startswith("    "):
                line = line[min(4, len(pwndbg.config.code_prefix) + 1) :]
            source[curline] = current_line_marker + " " + line
            source = "\n".join(source)

    if pwndbg.config.syntax_highlight:
        # highlighting depends on the file extension to guess the language, so try to get one...
        src_filename = None
        if pwndbg.dbg.is_gdblib_available():
            src_filename = pwndbg.gdblib.symbol.selected_frame_source_absolute_filename()
        if not src_filename:
            filename = pwndbg.aglib.proc.exe()
            src_filename = filename + ".c" if os.path.basename(filename).find(".") < 0 else filename
        source = H.syntax_highlight(source, src_filename)

    # Replace code prefix marker after syntax highlighting
    source = source.replace(current_line_marker, C.prefix(pwndbg.config.code_prefix), 1)

    if not func_specified:
        source = source.split("\n")
        n = int(pwndbg.config.context_code_lines)

        # Compute the line range
        start = max(closest_line - 1 - n // 2, 0)
        end = min(closest_line - 1 + n // 2 + 1, len(source))

        # split the code
        source = source[start:end]
        source = "\n".join(source)
    return source

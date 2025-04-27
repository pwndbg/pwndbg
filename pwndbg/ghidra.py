from __future__ import annotations

import os

import pwndbg.aglib.proc
import pwndbg.aglib.regs
import pwndbg.color.context as C
import pwndbg.color.syntax_highlight as H
import pwndbg.dbg
import pwndbg.radare2
import pwndbg.rizin

if pwndbg.dbg.is_gdblib_available():
    import pwndbg.gdblib.symbol

from pwndbg.color import message

r2decompiler = pwndbg.config.add_param(
    "r2decompiler",
    "radare2",
    "framework that your ghidra plugin installed",
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=["radare2", "rizin"],
)


@pwndbg.config.trigger(r2decompiler)
def set_r2decompiler() -> None:
    if r2decompiler.value in ["radare2", "rizin"]:
        return
    print(
        message.warn(
            f"Invalid r2decompiler: `{r2decompiler.value}`, please select from radare2 or rizin"
        )
    )
    r2decompiler.revert_default()


def decompile(func=None):
    """
    Return the source of the given function decompiled by ghidra.

    If no function is given, decompile the function within the current pc.
    This function requires radare2, r2pipe and r2ghidra, or their related rizin counterparts.

    Raises Exception if any fatal error occurs.
    """
    try:
        if r2decompiler == "radare2":
            r2 = pwndbg.radare2.r2pipe()
            # LD -> list supported decompilers (e cmd.pdc=?)
            # Outputs for example: pdc\npdg
            if "pdg" not in r2.cmd("LD").split("\n"):
                raise Exception("radare2 plugin r2ghidra must be installed and available from r2")
        else:
            assert r2decompiler == "rizin"
            r2 = pwndbg.rizin.rzpipe()
            # Lc -> list core plugins
            if "ghidra" not in r2.cmd("Lc"):
                raise Exception("rizin plugin rzghidra must be installed and available from rz")
    except ImportError:
        raise Exception("r2pipe or rzpipe not available, but required for r2/rz->ghidra bridge")

    if not func:
        func = (
            hex(pwndbg.aglib.regs[pwndbg.aglib.regs.current.pc])
            if pwndbg.aglib.proc.alive
            else "main"
        )

    src = r2.cmdj("pdgj @ " + func)
    if not src:
        raise Exception(f"Decompile command failed, check if '{func}' is a valid target")

    current_line_marker = "/*%%PWNDBG_CODE_MARKER%%*/"
    source = src.get("code", "")

    # If not running there is no current pc to mark
    if pwndbg.aglib.proc.alive:
        pc = pwndbg.aglib.regs[pwndbg.aglib.regs.current.pc]

        closest = 0
        for off in (a.get("offset", 0) for a in src.get("annotations", [])):
            if abs(pc - closest) > abs(pc - off):
                closest = off
        pos_annotations = sorted(
            [a for a in src.get("annotations", []) if a.get("offset") == closest],
            key=lambda a: a["start"],
        )

        # Append code prefix marker for the current line and replace it later
        if pos_annotations:
            curline = source.count("\n", 0, pos_annotations[0]["start"])
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
            filename = pwndbg.dbg.selected_inferior().main_module_name()
            src_filename = filename + ".c" if os.path.basename(filename).find(".") < 0 else filename
        source = H.syntax_highlight(source, src_filename)

    # Replace code prefix marker after syntax highlighting
    source = source.replace(current_line_marker, C.prefix(pwndbg.config.code_prefix), 1)
    return source

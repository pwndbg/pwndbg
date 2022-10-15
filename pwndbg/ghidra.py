import os

import gdb

import pwndbg.color.context as C
import pwndbg.color.syntax_highlight as H
import pwndbg.gdblib.regs
import pwndbg.radare2


def decompile(func=None):
    """
    Return the source of the given function decompiled by ghidra.

    If no function is given, decompile the function within the current pc.
    This function requires radare2, r2pipe and r2ghidra.

    Raises Exception if any fatal error occurs.
    """
    try:
        r2 = pwndbg.radare2.r2pipe()
    except ImportError:
        raise Exception("r2pipe not available, but required for r2->ghidra bridge")

    # LD -> list supported decompilers (e cmd.pdc=?)
    # Outputs for example: pdc\npdg
    if "pdg" not in r2.cmd("LD").split("\n"):
        raise Exception("radare2 plugin r2ghidra must be installed and available from r2")

    if not func:
        func = (
            hex(pwndbg.gdblib.regs[pwndbg.gdblib.regs.current.pc])
            if pwndbg.gdblib.proc.alive
            else "main"
        )

    src = r2.cmdj("pdgj @" + func)
    if not src:
        raise Exception("Decompile command failed, check if '{}' is a valid target".format(func))

    current_line_marker = "/*%%PWNDBG_CODE_MARKER%%*/"
    source = src.get("code", "")

    # If not running there is no current pc to mark
    if pwndbg.gdblib.proc.alive:
        pc = pwndbg.gdblib.regs[pwndbg.gdblib.regs.current.pc]

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
                line = line[min(4, len(pwndbg.gdblib.config.code_prefix) + 1) :]
            source[curline] = current_line_marker + " " + line
            source = "\n".join(source)

    if pwndbg.gdblib.config.syntax_highlight:
        # highlighting depends on the file extension to guess the language, so try to get one...
        src_filename = pwndbg.gdblib.symbol.selected_frame_source_absolute_filename()
        if not src_filename:
            filename = gdb.current_progspace().filename
            src_filename = filename + ".c" if os.path.basename(filename).find(".") < 0 else filename
        source = H.syntax_highlight(source, src_filename)

    # Replace code prefix marker after syntax highlighting
    source = source.replace(current_line_marker, C.prefix(pwndbg.gdblib.config.code_prefix), 1)
    return source

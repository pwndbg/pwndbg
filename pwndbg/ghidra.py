import os

import gdb

import pwndbg.color.syntax_highlight as H
import pwndbg.radare2
import pwndbg.regs


def decompile(func=None):
    """
    Return the source of the given function decompiled by ghidra.

    If no function is given, decompile the function within the current pc.
    This function requires radare2, r2pipe and r2ghidra.

    Raises Exception if any fatal error occures.
    """
    filename = gdb.current_progspace().filename
    try:
        r2 = pwndbg.radare2.r2pipe(filename)
        # LD         list supported decompilers (e cmd.pdc=?)
        # Outputs for example:: pdc\npdg
        if not "pdg" in r2.cmd("LD").split("\n"):
            return ["radare2 plugin r2ghidra-dec must be installed and available from r2"]
    except ImportError: # no r2pipe present
        return ["r2pipe not available, but required for r2->ghidra-bridge"]
    if func is None:
        try:
            func = hex(pwndbg.regs[pwndbg.regs.current.pc])
        except:
            func = "main"
    src = r2.cmdj("pdgj @" + func)
    source = src.get("code", "")
    curline = None
    try:
        cur = pwndbg.regs[pwndbg.regs.current.pc]
    except AttributeError:
        cur = None # If not running there is no current.pc
    if cur is not None:
        closest = 0
        for off in (a.get("offset", 0) for a in src.get("annotations", [])):
            if abs(cur - closest) > abs(cur - off):
                closest = off
        pos_annotations = sorted([a for a in src.get("annotations", []) if a.get("offset") == closest],
                         key=lambda a: a["start"])
        if pos_annotations:
            curline = source.count("\n", 0, pos_annotations[0]["start"])
    source = source.split("\n")
    # Append --> for the current line if possible
    if curline is not None:
        line = source[curline]
        if line.startswith('    '):
            line = line[4:]
        source[curline] = '--> ' + line
    # Join the source for highlighting
    source = "\n".join(source)
    if pwndbg.config.syntax_highlight:
        # highlighting depends on the file extension to guess the language, so try to get one...
        try: # try to read the source filename from debug information
            src_filename = gdb.selected_frame().find_sal().symtab.fullname()
        except: # if non, take the original filename and maybe append .c (just assuming is was c)
            src_filename = filename+".c" if os.path.basename(filename).find(".") < 0 else filename
        source = H.syntax_highlight(source, src_filename)
    source = source.split("\n")
    return source

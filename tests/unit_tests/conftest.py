# Pytest conftest to inject test-time mocks for gdb and pwndbg.commands
from __future__ import annotations

import sys
import types

import pytest

# Inject a minimal 'gdb' module with a 'types' submodule so imports succeed
if "gdb" not in sys.modules:
    gdb_mod = types.ModuleType("gdb")

    # minimal error class used by pwndbg code
    class GdbError(Exception):
        pass

    gdb_mod.error = GdbError

    # Provide an execute stub that returns empty string (some code may call it)
    def _execute(cmd, to_string=False, **kwargs):
        return ""

    gdb_mod.execute = _execute

    # Minimal RemoteTargetConnection placeholder used by some code paths
    RemoteTargetConnection = types.SimpleNamespace
    gdb_mod.RemoteTargetConnection = RemoteTargetConnection

    # Create gdb.types submodule
    gdb_types = types.ModuleType("gdb.types")

    # Add a has_field stub to avoid attribute errors
    def has_field(typ, name):
        return False

    gdb_types.has_field = has_field

    # Register modules
    sys.modules["gdb"] = gdb_mod
    sys.modules["gdb.types"] = gdb_types


@pytest.fixture(scope="session", autouse=True)
def inject_pwndbg_gdblib_mocks_session():
    """
    Session-level fixture to inject minimal mocks for pwndbg.gdblib and related modules.
    This runs at the start of pytest before any tests import pwndbg.dbg.gdb.
    """
    from contextlib import contextmanager

    # Only inject mocks if test_module_section_locations will be run
    # (Check by inspecting pytest's config)
    pwndbg_gdblib = types.ModuleType("pwndbg.gdblib")

    # provide events namespace with simple pause/unpause decorators used in code
    events = types.SimpleNamespace()

    def no_op_decorator(fn=None):
        if fn is None:

            def _wrap(f):
                return f

            return _wrap
        return fn

    events.stop = no_op_decorator
    events.start = no_op_decorator
    events.exit = no_op_decorator
    events.cont = no_op_decorator
    events.memory_changed = no_op_decorator
    events.register_changed = no_op_decorator
    events.new_objfile = no_op_decorator
    events.pause = lambda *a, **k: None
    events.unpause = lambda *a, **k: None
    pwndbg_gdblib.events = events
    pwndbg_gdblib.prompt = types.SimpleNamespace(context_shown=False)

    # Register gdblib.events as a submodule
    gw_events_mod = types.ModuleType("pwndbg.gdblib.events")
    gw_events_mod.stop = events.stop
    gw_events_mod.start = events.start
    gw_events_mod.exit = events.exit
    gw_events_mod.cont = events.cont
    gw_events_mod.memory_changed = events.memory_changed
    gw_events_mod.register_changed = events.register_changed
    gw_events_mod.new_objfile = events.new_objfile
    gw_events_mod.pause = events.pause
    gw_events_mod.unpause = events.unpause
    sys.modules["pwndbg.gdblib.events"] = gw_events_mod
    pwndbg_gdblib.events = gw_events_mod

    # Minimal stub: load_gdblib
    def load_gdblib():
        return None

    pwndbg_gdblib.load_gdblib = load_gdblib

    # Register gdblib.scheduler
    pwndbg_gdblib_scheduler = types.ModuleType("pwndbg.gdblib.scheduler")

    @contextmanager
    def lock_scheduler():
        yield

    pwndbg_gdblib_scheduler.lock_scheduler = lock_scheduler
    sys.modules["pwndbg.gdblib.scheduler"] = pwndbg_gdblib_scheduler
    pwndbg_gdblib.scheduler = pwndbg_gdblib_scheduler

    # Register gdblib itself
    sys.modules["pwndbg.gdblib"] = pwndbg_gdblib

    # If pwndbg is already imported (likely from real package), override its gdblib
    if "pwndbg" in sys.modules:
        import pwndbg

        pwndbg.gdblib = pwndbg_gdblib

    # Inject mocks for pwndbg.aglib, dbg_mod, lib.memory, lib.arch, etc.
    pwndbg_aglib = types.ModuleType("pwndbg.aglib")

    def load_aglib():
        return None

    pwndbg_aglib.load_aglib = load_aglib
    pwndbg_aglib.regs = {}
    sys.modules["pwndbg.aglib"] = pwndbg_aglib

    # pwndbg.dbg_mod
    pwndbg_dbg_mod = types.ModuleType("pwndbg.dbg_mod")

    class Registers:
        pass

    class Value:
        pass

    class Frame:
        pass

    class Thread:
        pass

    class MemoryMap:
        def __init__(self, pages=None):
            self.pages = pages or []

    class SymbolLookupType:
        ANY = 0
        VARIABLE = 1
        FUNCTION = 2

    class Error(Exception):
        pass

    pwndbg_dbg_mod.Registers = Registers
    pwndbg_dbg_mod.Value = Value
    pwndbg_dbg_mod.Frame = Frame
    pwndbg_dbg_mod.Thread = Thread
    pwndbg_dbg_mod.MemoryMap = MemoryMap
    pwndbg_dbg_mod.SymbolLookupType = SymbolLookupType
    pwndbg_dbg_mod.Error = Error
    sys.modules["pwndbg.dbg_mod"] = pwndbg_dbg_mod

    # pwndbg.lib.memory
    pwndbg_lib_memory = types.ModuleType("pwndbg.lib.memory")

    class Page:
        pass

    pwndbg_lib_memory.Page = Page
    sys.modules["pwndbg.lib.memory"] = pwndbg_lib_memory

    # pwndbg.lib.arch
    pwndbg_lib_arch = types.ModuleType("pwndbg.lib.arch")

    class ArchAttribute:
        MIPS_ISA_5 = "mips5"
        MIPS_ISA_MICRO = "micromips"
        MIPS_ISA_32 = "isa32"
        MIPS_ISA_32R2 = "isa32r2"
        MIPS_ISA_32R3 = "isa32r3"
        MIPS_ISA_32R5 = "isa32r5"
        MIPS_ISA_32R6 = "isa32r6"
        MIPS_ISA_64 = "isa64"
        MIPS_ISA_64R2 = "isa64r2"
        MIPS_ISA_64R3 = "isa64r3"
        MIPS_ISA_64R5 = "isa64r5"
        MIPS_ISA_64R6 = "isa64r6"

    class ArchDefinition:
        pass

    class Platform:
        pass

    pwndbg_lib_arch.ArchAttribute = ArchAttribute
    pwndbg_lib_arch.ArchDefinition = ArchDefinition
    pwndbg_lib_arch.Platform = Platform
    sys.modules["pwndbg.lib.arch"] = pwndbg_lib_arch

    yield

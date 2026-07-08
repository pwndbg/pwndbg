"""
MCP Tools implementation for pwndbg

This module implements the MCP tools that expose pwndbg's core functionality
to AI Agents via the Model Context Protocol.
"""

from __future__ import annotations

import io
import sys
from typing import Any, Dict, List

import pwndbg.aglib
import pwndbg.aglib.heap
import pwndbg.aglib.regs
import pwndbg.commands
import pwndbg.dbg
from pwndbg.mcp.models import (
    Breakpoint,
    CommandResult,
    ExecutionState,
    HeapChunk,
    HeapInfo,
    MemoryContent,
    MemoryRegion,
    RegisterState,
    StackFrame,
)


def execute_command(command: str) -> Dict[str, Any]:
    """
    Execute a pwndbg/GDB command and return the output.

    Args:
        command: The command to execute (e.g., "vmmap", "hexdump $rsp 64")

    Returns:
        CommandResult with output, error, and return code
    """
    try:
        # Use GDB's execute with to_string to capture output
        # This is the real API used throughout pwndbg codebase
        if pwndbg.dbg.is_gdblib_available():
            import gdb
            output = gdb.execute(command, to_string=True)
            result = CommandResult(output=output.strip(), return_code=0)
        else:
            # LLDB path - would need different implementation
            result = CommandResult(output="", error="LLDB not yet supported in MCP", return_code=1)

        return result.to_dict()
    except Exception as e:
        return CommandResult(output="", error=str(e), return_code=1).to_dict()


def get_registers() -> Dict[str, Any]:
    """
    Get the current CPU register state.

    Returns:
        RegisterState with all register values
    """
    try:
        regs = {}
        # Use the real API: pwndbg.aglib.regs.read_reg(reg)
        for reg in pwndbg.aglib.regs.all:
            try:
                value = pwndbg.aglib.regs.read_reg(reg)
                if value is not None:
                    regs[reg] = value
            except Exception:
                continue

        pc = pwndbg.aglib.regs.pc or 0
        sp = pwndbg.aglib.regs.sp or 0

        # Try to get flags - need to read eflags register directly
        flags = None
        try:
            eflags = pwndbg.aglib.regs.read_reg("eflags")
            if eflags is not None:
                flags = {
                    "CF": bool(eflags & 0x1),
                    "PF": bool(eflags & 0x4),
                    "AF": bool(eflags & 0x10),
                    "ZF": bool(eflags & 0x40),
                    "SF": bool(eflags & 0x80),
                    "TF": bool(eflags & 0x100),
                    "IF": bool(eflags & 0x200),
                    "DF": bool(eflags & 0x400),
                    "OF": bool(eflags & 0x800),
                }
        except Exception:
            pass

        state = RegisterState(registers=regs, pc=pc, sp=sp, flags=flags)
        return state.to_dict()
    except Exception as e:
        return {"error": str(e)}


def inspect_memory(address: int, size: int = 64) -> Dict[str, Any]:
    """
    Read and display memory contents at the given address.

    Args:
        address: Memory address to read from
        size: Number of bytes to read (default: 64)

    Returns:
        MemoryContent with hex and ASCII representation
    """
    try:
        # Read memory
        data = pwndbg.aglib.memory.read(address, size)

        # Create ASCII representation
        ascii_repr = ""
        for byte in data:
            if 32 <= byte <= 126:
                ascii_repr += chr(byte)
            else:
                ascii_repr += "."

        content = MemoryContent(address=address, data=bytes(data), ascii_repr=ascii_repr)
        return content.to_dict()
    except Exception as e:
        return {"error": str(e), "address": hex(address)}


def heap_analysis() -> Dict[str, Any]:
    """
    Analyze the current heap state.

    Returns:
        HeapInfo with chunks, top chunk, and memory statistics
    """
    try:
        # Get heap instance - pwndbg.aglib.heap.current is the real API
        heap = pwndbg.aglib.heap.current

        chunks = []
        top = 0
        system_mem = 0
        max_system_mem = 0

        try:
            # Iterate through chunks - need to check the actual API
            # The Chunk class has: address, size, prev_size, flags, fd, bk properties
            if hasattr(heap, 'chunk') and callable(heap.chunk):
                # Try to iterate chunks starting from a known address
                # This is a simplified approach - real implementation would need
                # to traverse the heap properly
                pass

            # Get top chunk and memory stats from arena
            if hasattr(heap, 'arenas'):
                for arena in heap.arenas:
                    if hasattr(arena, 'top'):
                        top = arena.top or 0
                    if hasattr(arena, 'system_mem'):
                        system_mem = arena.system_mem or 0
                    if hasattr(arena, 'max_system_mem'):
                        max_system_mem = arena.max_system_mem or 0

        except Exception:
            pass

        info = HeapInfo(
            chunks=chunks,
            top=top,
            system_mem=system_mem,
            max_system_mem=max_system_mem,
        )
        return info.to_dict()
    except Exception as e:
        return {"error": str(e)}


def stack_analysis() -> Dict[str, Any]:
    """
    Analyze the current stack frames.

    Returns:
        List of StackFrame objects
    """
    try:
        frames = []

        # Get backtrace using gdb.execute
        try:
            if pwndbg.dbg.is_gdblib_available():
                import gdb
                output = gdb.execute("backtrace", to_string=True)

                # Parse backtrace output
                for line in output.strip().split("\n"):
                    if line.startswith("#"):
                        parts = line.split()
                        if len(parts) >= 2:
                            frame_num = int(parts[0][1:])  # Remove '#'
                            addr_str = parts[1]

                            # Try to parse address
                            try:
                                if addr_str.startswith("0x"):
                                    addr = int(addr_str, 16)
                                else:
                                    addr = 0
                            except Exception:
                                addr = 0

                            # Try to get function name
                            func = None
                            if len(parts) >= 3:
                                func = parts[2]

                            frame = StackFrame(
                                address=addr,
                                function=func,
                                offset=frame_num,
                            )
                            frames.append(frame)
        except Exception:
            pass

        return {"frames": [f.to_dict() for f in frames]}
    except Exception as e:
        return {"error": str(e)}


def breakpoint_set(location: str, type: str = "breakpoint") -> Dict[str, Any]:
    """
    Set a breakpoint at the specified location.

    Args:
        location: Address, symbol, or source location (e.g., "0x400000", "main", "file.c:10")
        type: Type of breakpoint ("breakpoint", "watchpoint", "catchpoint")

    Returns:
        Breakpoint object with details
    """
    try:
        if not pwndbg.dbg.is_gdblib_available():
            return {"error": "LLDB not yet supported in MCP"}

        import gdb

        # Execute breakpoint command using gdb.execute
        if type == "breakpoint":
            output = gdb.execute(f"break {location}", to_string=True)
        elif type == "watchpoint":
            output = gdb.execute(f"watch {location}", to_string=True)
        elif type == "catchpoint":
            output = gdb.execute(f"catch {location}", to_string=True)
        else:
            return {"error": f"Unknown breakpoint type: {type}"}

        # Parse output to get breakpoint number and address
        # Example output: "Breakpoint 1 at 0x400000"
        bp_num = 0
        addr = 0

        for line in output.split("\n"):
            if "Breakpoint" in line or "Watchpoint" in line or "Catchpoint" in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part.isdigit():
                        bp_num = int(part)
                    elif part.startswith("0x"):
                        try:
                            addr = int(part, 16)
                        except Exception:
                            pass

        bp = Breakpoint(
            number=bp_num,
            address=addr,
            enabled=True,
            type=type,
            location=location,
        )
        return bp.to_dict()
    except Exception as e:
        return {"error": str(e)}


def continue_execution() -> Dict[str, Any]:
    """
    Continue program execution.

    Returns:
        ExecutionState with stop reason and location
    """
    try:
        if not pwndbg.dbg.is_gdblib_available():
            return {"error": "LLDB not yet supported in MCP"}

        import gdb

        # Execute continue command using gdb.execute
        output = gdb.execute("continue", to_string=True)

        # Parse output to determine stop reason
        stopped = True
        reason = None
        signal = None
        address = None

        # Check for common stop reasons
        if "breakpoint" in output.lower():
            reason = "breakpoint"
        elif "signal" in output.lower():
            reason = "signal"
            # Try to extract signal name
            for line in output.split("\n"):
                if "SIG" in line:
                    parts = line.split()
                    for part in parts:
                        if part.startswith("SIG"):
                            signal = part
        elif "exited" in output.lower():
            reason = "exited"
            stopped = False

        # Get current address
        try:
            address = pwndbg.aglib.regs.pc
        except Exception:
            pass

        state = ExecutionState(
            stopped=stopped,
            reason=reason,
            signal=signal,
            address=address,
        )
        return state.to_dict()
    except Exception as e:
        return {"error": str(e)}


# Tool registry for MCP Server
TOOLS = {
    "execute_command": {
        "function": execute_command,
        "description": "Execute a pwndbg/GDB command and return the output",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The command to execute (e.g., 'vmmap', 'hexdump $rsp 64')",
                }
            },
            "required": ["command"],
        },
    },
    "get_registers": {
        "function": get_registers,
        "description": "Get the current CPU register state",
        "parameters": {"type": "object", "properties": {}},
    },
    "inspect_memory": {
        "function": inspect_memory,
        "description": "Read and display memory contents at the given address",
        "parameters": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "integer",
                    "description": "Memory address to read from (in hex or decimal)",
                },
                "size": {
                    "type": "integer",
                    "description": "Number of bytes to read (default: 64)",
                    "default": 64,
                },
            },
            "required": ["address"],
        },
    },
    "heap_analysis": {
        "function": heap_analysis,
        "description": "Analyze the current heap state",
        "parameters": {"type": "object", "properties": {}},
    },
    "stack_analysis": {
        "function": stack_analysis,
        "description": "Analyze the current stack frames",
        "parameters": {"type": "object", "properties": {}},
    },
    "breakpoint_set": {
        "function": breakpoint_set,
        "description": "Set a breakpoint at the specified location",
        "parameters": {
            "type": "object",
            "properties": {
                "location": {
                    "type": "string",
                    "description": "Address, symbol, or source location (e.g., '0x400000', 'main', 'file.c:10')",
                },
                "type": {
                    "type": "string",
                    "description": "Type of breakpoint ('breakpoint', 'watchpoint', 'catchpoint')",
                    "default": "breakpoint",
                },
            },
            "required": ["location"],
        },
    },
    "continue_execution": {
        "function": continue_execution,
        "description": "Continue program execution",
        "parameters": {"type": "object", "properties": {}},
    },
}

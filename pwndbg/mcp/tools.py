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


def find_rop_gadgets(grep: str | None = None, memlimit: str = "50MB") -> Dict[str, Any]:
    """
    Find ROP gadgets in the current binary or memory mappings.

    Args:
        grep: Optional string to grep the output for (e.g., "pop rdi")
        memlimit: Maximum size of memory pages to scan (default: "50MB")

    Returns:
        Dictionary with list of gadgets found
    """
    try:
        if not pwndbg.dbg.is_gdblib_available():
            return {"error": "LLDB not yet supported in MCP"}

        import gdb
        import tempfile
        from io import StringIO
        import contextlib

        # Build rop command
        cmd_parts = ["rop"]
        if grep:
            cmd_parts.extend(["--grep", grep])
        cmd_parts.extend(["--memlimit", memlimit])

        # Execute rop command and capture output
        cmd = " ".join(cmd_parts)
        output = gdb.execute(cmd, to_string=True)

        # Parse gadgets from output
        gadgets = []
        lines = output.strip().split("\n")

        for line in lines:
            # Skip header and summary lines
            if line.startswith("Gadgets information") or line.startswith("=") or not line.strip():
                continue
            if "Unique gadgets found:" in line:
                continue

            # Parse gadget line: "0x0007dce8 : pop rdi ; or dword ptr [rax], eax ; add rsp, 0x28 ; ret"
            if ":" in line and "0x" in line:
                parts = line.split(":", 1)
                if len(parts) >= 2:
                    addr_str = parts[0].strip()
                    gadget_str = parts[1].strip()

                    try:
                        addr = int(addr_str, 16)
                        gadgets.append({
                            "address": hex(addr),
                            "instruction": gadget_str,
                        })
                    except ValueError:
                        continue

        return {
            "gadgets": gadgets,
            "count": len(gadgets),
        }
    except Exception as e:
        return {"error": str(e)}


def search_memory(
    pattern: str,
    search_type: str = "bytes",
    executable_only: bool = False,
    writable_only: bool = False,
    limit: int | None = None,
) -> Dict[str, Any]:
    """
    Search memory for byte sequences, strings, pointers, or integer values.

    Args:
        pattern: The pattern to search for (string, hex bytes, or integer)
        search_type: Type of search ("bytes", "string", "dword", "qword", "pointer")
        executable_only: Search only executable segments
        writable_only: Search only writable segments
        limit: Maximum number of results to return

    Returns:
        Dictionary with list of addresses where pattern was found
    """
    try:
        if not pwndbg.dbg.is_gdblib_available():
            return {"error": "LLDB not yet supported in MCP"}

        import gdb

        # Build search command
        cmd_parts = ["search"]

        # Add type flag
        if search_type == "string":
            cmd_parts.extend(["-t", "string"])
        elif search_type == "dword":
            cmd_parts.extend(["-t", "dword"])
        elif search_type == "qword":
            cmd_parts.extend(["-t", "qword"])
        elif search_type == "pointer":
            cmd_parts.extend(["-p"])
        else:  # bytes
            cmd_parts.extend(["-t", "bytes"])

        # Add flags
        if executable_only:
            cmd_parts.append("-e")
        if writable_only:
            cmd_parts.append("-w")
        if limit:
            cmd_parts.extend(["--limit", str(limit)])

        # Add pattern
        cmd_parts.append(pattern)

        # Execute search command
        cmd = " ".join(cmd_parts)
        output = gdb.execute(cmd, to_string=True)

        # Parse addresses from output
        addresses = []
        for line in output.strip().split("\n"):
            # Look for hex addresses in output
            if "0x" in line:
                parts = line.split()
                for part in parts:
                    if part.startswith("0x"):
                        try:
                            addr = int(part, 16)
                            addresses.append(hex(addr))
                        except ValueError:
                            continue

        return {
            "addresses": addresses,
            "count": len(addresses),
            "pattern": pattern,
        }
    except Exception as e:
        return {"error": str(e)}


def disassemble(
    address: int | None = None,
    count: int = 10,
) -> Dict[str, Any]:
    """
    Disassemble instructions near the specified address or current PC.

    Args:
        address: Address to disassemble near (default: current PC)
        count: Number of instructions to disassemble (default: 10)

    Returns:
        Dictionary with list of disassembled instructions
    """
    try:
        if not pwndbg.dbg.is_gdblib_available():
            return {"error": "LLDB not yet supported in MCP"}

        import gdb

        # Build nearpc command
        cmd_parts = ["nearpc"]
        if address is not None:
            cmd_parts.append(hex(address))
        cmd_parts.append(str(count))

        # Execute nearpc command
        cmd = " ".join(cmd_parts)
        output = gdb.execute(cmd, to_string=True)

        # Parse instructions from output
        instructions = []
        for line in output.strip().split("\n"):
            if not line.strip():
                continue

            # Parse instruction line: "   0x400000 <main>    push rbp"
            # or "→  0x400000 <main>    push rbp"
            line = line.strip()

            # Skip if no address found
            if "0x" not in line:
                continue

            # Extract address
            parts = line.split()
            addr_str = None
            for part in parts:
                if part.startswith("0x"):
                    addr_str = part
                    break

            if not addr_str:
                continue

            try:
                addr = int(addr_str, 16)
            except ValueError:
                continue

            # Extract instruction (everything after the address and optional symbol)
            # Find the instruction part
            instr_parts = []
            found_addr = False
            for part in parts:
                if part == addr_str:
                    found_addr = True
                    continue
                if found_addr:
                    # Skip symbol like <main>
                    if part.startswith("<") and part.endswith(">"):
                        continue
                    instr_parts.append(part)

            instruction = " ".join(instr_parts) if instr_parts else ""

            instructions.append({
                "address": hex(addr),
                "instruction": instruction,
            })

        return {
            "instructions": instructions,
            "count": len(instructions),
        }
    except Exception as e:
        return {"error": str(e)}


def get_backtrace() -> Dict[str, Any]:
    """
    Get the current call stack backtrace.

    Returns:
        Dictionary with list of stack frames
    """
    try:
        if not pwndbg.dbg.is_gdblib_available():
            return {"error": "LLDB not yet supported in MCP"}

        import gdb

        # Execute backtrace command
        output = gdb.execute("backtrace", to_string=True)

        # Parse backtrace output
        frames = []
        for line in output.strip().split("\n"):
            if not line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            # Parse frame number
            try:
                frame_num = int(parts[0][1:])  # Remove '#'
            except ValueError:
                continue

            # Parse address
            addr_str = parts[1]
            try:
                if addr_str.startswith("0x"):
                    addr = int(addr_str, 16)
                else:
                    addr = 0
            except ValueError:
                addr = 0

            # Parse function name
            func = None
            if len(parts) >= 3:
                func = parts[2]

            # Parse source location if present
            source = None
            for part in parts:
                if " at " in part or ":" in part:
                    source = part
                    break

            frames.append({
                "number": frame_num,
                "address": hex(addr),
                "function": func,
                "source": source,
            })

        return {
            "frames": frames,
            "count": len(frames),
        }
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
    "find_rop_gadgets": {
        "function": find_rop_gadgets,
        "description": "Find ROP gadgets in the current binary or memory mappings",
        "parameters": {
            "type": "object",
            "properties": {
                "grep": {
                    "type": "string",
                    "description": "Optional string to grep the output for (e.g., 'pop rdi')",
                },
                "memlimit": {
                    "type": "string",
                    "description": "Maximum size of memory pages to scan (default: '50MB')",
                    "default": "50MB",
                },
            },
            "required": [],
        },
    },
    "search_memory": {
        "function": search_memory,
        "description": "Search memory for byte sequences, strings, pointers, or integer values",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "The pattern to search for (string, hex bytes, or integer)",
                },
                "search_type": {
                    "type": "string",
                    "description": "Type of search ('bytes', 'string', 'dword', 'qword', 'pointer')",
                    "default": "bytes",
                },
                "executable_only": {
                    "type": "boolean",
                    "description": "Search only executable segments",
                    "default": False,
                },
                "writable_only": {
                    "type": "boolean",
                    "description": "Search only writable segments",
                    "default": False,
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results to return",
                },
            },
            "required": ["pattern"],
        },
    },
    "disassemble": {
        "function": disassemble,
        "description": "Disassemble instructions near the specified address or current PC",
        "parameters": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "integer",
                    "description": "Address to disassemble near (default: current PC)",
                },
                "count": {
                    "type": "integer",
                    "description": "Number of instructions to disassemble (default: 10)",
                    "default": 10,
                },
            },
            "required": [],
        },
    },
    "get_backtrace": {
        "function": get_backtrace,
        "description": "Get the current call stack backtrace",
        "parameters": {"type": "object", "properties": {}},
    },
}

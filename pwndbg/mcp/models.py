"""
Data models for pwndbg MCP Server
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class RegisterState:
    """Represents CPU register state"""
    registers: Dict[str, int]
    pc: int
    sp: int
    flags: Optional[Dict[str, bool]] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "registers": {k: hex(v) for k, v in self.registers.items()},
            "pc": hex(self.pc),
            "sp": hex(self.sp),
        }
        if self.flags:
            result["flags"] = self.flags
        return result


@dataclass
class MemoryRegion:
    """Represents a memory region"""
    start: int
    end: int
    permissions: str
    offset: int
    path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start": hex(self.start),
            "end": hex(self.end),
            "permissions": self.permissions,
            "offset": hex(self.offset),
            "path": self.path,
            "size": self.end - self.start,
        }


@dataclass
class MemoryContent:
    """Represents memory content"""
    address: int
    data: bytes
    ascii_repr: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "hex": self.data.hex(),
            "ascii": self.ascii_repr,
            "size": len(self.data),
        }


@dataclass
class HeapChunk:
    """Represents a heap chunk"""
    address: int
    size: int
    prev_size: int
    flags: Dict[str, bool]
    fd: Optional[int] = None
    bk: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "address": hex(self.address),
            "size": self.size,
            "prev_size": self.prev_size,
            "flags": self.flags,
        }
        if self.fd is not None:
            result["fd"] = hex(self.fd)
        if self.bk is not None:
            result["bk"] = hex(self.bk)
        return result


@dataclass
class HeapInfo:
    """Represents heap information"""
    chunks: List[HeapChunk]
    top: int
    system_mem: int
    max_system_mem: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chunks": [c.to_dict() for c in self.chunks],
            "top": hex(self.top),
            "system_mem": self.system_mem,
            "max_system_mem": self.max_system_mem,
        }


@dataclass
class StackFrame:
    """Represents a stack frame"""
    address: int
    function: Optional[str]
    offset: int
    source: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "address": hex(self.address),
            "function": self.function,
            "offset": self.offset,
        }
        if self.source:
            result["source"] = self.source
        return result


@dataclass
class Breakpoint:
    """Represents a breakpoint"""
    number: int
    address: int
    enabled: bool
    type: str
    location: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "number": self.number,
            "address": hex(self.address),
            "enabled": self.enabled,
            "type": self.type,
        }
        if self.location:
            result["location"] = self.location
        return result


@dataclass
class CommandResult:
    """Represents command execution result"""
    output: str
    error: Optional[str] = None
    return_code: int = 0

    def to_dict(self) -> Dict[str, Any]:
        result = {"output": self.output, "return_code": self.return_code}
        if self.error:
            result["error"] = self.error
        return result


@dataclass
class ExecutionState:
    """Represents execution state after continue"""
    stopped: bool
    reason: Optional[str] = None
    signal: Optional[str] = None
    address: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {"stopped": self.stopped}
        if self.reason:
            result["reason"] = self.reason
        if self.signal:
            result["signal"] = self.signal
        if self.address:
            result["address"] = hex(self.address)
        return result

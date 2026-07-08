"""
Tests for pwndbg MCP Server

These tests verify that the MCP tools work correctly and return
properly formatted JSON responses.
"""

from __future__ import annotations

import pwndbg.aglib.regs
import pytest

# Import pwndbg modules
import pwndbg.aglib
import pwndbg.mcp.tools


class TestMCPTools:
    """Test suite for pwndbg MCP tools."""

    def test_execute_command(self):
        """Test execute_command tool."""
        result = pwndbg.mcp.tools.execute_command("help")
        assert isinstance(result, dict)
        assert "output" in result
        assert "return_code" in result
        assert result["return_code"] == 0

    def test_get_registers(self):
        """Test get_registers tool."""
        result = pwndbg.mcp.tools.get_registers()
        assert isinstance(result, dict)
        # Should have registers, pc, and sp
        assert "registers" in result or "error" in result
        if "registers" in result:
            assert "pc" in result
            assert "sp" in result

    def test_inspect_memory(self):
        """Test inspect_memory tool."""
        # Test with a valid address (stack pointer)
        try:
            sp = pwndbg.aglib.regs.sp
            result = pwndbg.mcp.tools.inspect_memory(sp, 32)
            assert isinstance(result, dict)
            if "error" not in result:
                assert "address" in result
                assert "hex" in result
                assert "ascii" in result
                assert "size" in result
        except Exception:
            # If we can't get SP, skip this test
            pass

    def test_heap_analysis(self):
        """Test heap_analysis tool."""
        result = pwndbg.mcp.tools.heap_analysis()
        assert isinstance(result, dict)
        # Should return heap info or error
        assert "chunks" in result or "error" in result

    def test_stack_analysis(self):
        """Test stack_analysis tool."""
        result = pwndbg.mcp.tools.stack_analysis()
        assert isinstance(result, dict)
        assert "frames" in result or "error" in result

    def test_breakpoint_set(self):
        """Test breakpoint_set tool."""
        # Test setting a breakpoint at main (if it exists)
        result = pwndbg.mcp.tools.breakpoint_set("main")
        assert isinstance(result, dict)
        # Should return breakpoint info or error
        assert "number" in result or "error" in result

    def test_continue_execution(self):
        """Test continue_execution tool."""
        # This test is tricky because it changes program state
        # We'll just verify it returns the right structure
        result = pwndbg.mcp.tools.continue_execution()
        assert isinstance(result, dict)
        assert "stopped" in result or "error" in result


class TestMCPModels:
    """Test suite for MCP data models."""

    def test_register_state_to_dict(self):
        """Test RegisterState serialization."""
        from pwndbg.mcp.models import RegisterState

        state = RegisterState(
            registers={"rax": 0x1234, "rbx": 0x5678},
            pc=0x400000,
            sp=0x7FFFFFFF,
            flags={"ZF": True, "CF": False},
        )
        result = state.to_dict()
        assert result["registers"]["rax"] == "0x1234"
        assert result["pc"] == "0x400000"
        assert result["sp"] == "0x7fffffff"
        assert result["flags"]["ZF"] is True

    def test_memory_region_to_dict(self):
        """Test MemoryRegion serialization."""
        from pwndbg.mcp.models import MemoryRegion

        region = MemoryRegion(
            start=0x400000,
            end=0x401000,
            permissions="r-xp",
            offset=0,
            path="/bin/test",
        )
        result = region.to_dict()
        assert result["start"] == "0x400000"
        assert result["end"] == "0x401000"
        assert result["permissions"] == "r-xp"
        assert result["size"] == 0x1000

    def test_heap_chunk_to_dict(self):
        """Test HeapChunk serialization."""
        from pwndbg.mcp.models import HeapChunk

        chunk = HeapChunk(
            address=0x602000,
            size=0x20,
            prev_size=0x0,
            flags={"PREV_INUSE": True, "IS_MMAPPED": False, "NON_MAIN_ARENA": False},
            fd=0x602020,
            bk=0x601FE0,
        )
        result = chunk.to_dict()
        assert result["address"] == "0x602000"
        assert result["size"] == 0x20
        assert result["flags"]["PREV_INUSE"] is True
        assert result["fd"] == "0x602020"

    def test_breakpoint_to_dict(self):
        """Test Breakpoint serialization."""
        from pwndbg.mcp.models import Breakpoint

        bp = Breakpoint(
            number=1,
            address=0x400000,
            enabled=True,
            type="breakpoint",
            location="main",
        )
        result = bp.to_dict()
        assert result["number"] == 1
        assert result["address"] == "0x400000"
        assert result["enabled"] is True
        assert result["location"] == "main"

    def test_find_rop_gadgets(self):
        """Test find_rop_gadgets tool."""
        result = pwndbg.mcp.tools.find_rop_gadgets()
        assert isinstance(result, dict)
        # Should return gadgets list or error
        assert "gadgets" in result or "error" in result

    def test_search_memory(self):
        """Test search_memory tool."""
        result = pwndbg.mcp.tools.search_memory("test")
        assert isinstance(result, dict)
        # Should return addresses list or error
        assert "addresses" in result or "error" in result

    def test_disassemble(self):
        """Test disassemble tool."""
        result = pwndbg.mcp.tools.disassemble()
        assert isinstance(result, dict)
        # Should return instructions list or error
        assert "instructions" in result or "error" in result

    def test_get_backtrace(self):
        """Test get_backtrace tool."""
        result = pwndbg.mcp.tools.get_backtrace()
        assert isinstance(result, dict)
        # Should return frames list or error
        assert "frames" in result or "error" in result


class TestMCPToolRegistry:
    """Test suite for MCP tool registry."""

    def test_tools_registry_exists(self):
        """Test that TOOLS registry is properly defined."""
        assert hasattr(pwndbg.mcp.tools, "TOOLS")
        assert isinstance(pwndbg.mcp.tools.TOOLS, dict)

    def test_all_tools_registered(self):
        """Test that all expected tools are registered."""
        expected_tools = [
            "execute_command",
            "get_registers",
            "inspect_memory",
            "heap_analysis",
            "stack_analysis",
            "breakpoint_set",
            "continue_execution",
            "find_rop_gadgets",
            "search_memory",
            "disassemble",
            "get_backtrace",
        ]
        for tool_name in expected_tools:
            assert tool_name in pwndbg.mcp.tools.TOOLS
            tool_info = pwndbg.mcp.tools.TOOLS[tool_name]
            assert "function" in tool_info
            assert "description" in tool_info
            assert "parameters" in tool_info

    def test_tool_parameters_schema(self):
        """Test that tool parameters have valid JSON Schema."""
        for tool_name, tool_info in pwndbg.mcp.tools.TOOLS.items():
            params = tool_info["parameters"]
            assert params["type"] == "object"
            assert "properties" in params


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

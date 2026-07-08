"""
MCP Server for pwndbg

This module implements the MCP (Model Context Protocol) Server that exposes
pwndbg's debugging capabilities to AI Agents.

Usage:
    # In GDB with pwndbg loaded:
    source /path/to/pwndbg/mcp/server.py

    # Or start as standalone server:
    python -m pwndbg.mcp.server --stdio
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import pwndbg.mcp.tools

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
except ImportError:
    print("Error: MCP SDK not installed. Run: pip install mcp")
    sys.exit(1)


def create_mcp_server() -> Server:
    """
    Create and configure the MCP Server instance.

    Returns:
        Configured MCP Server with all pwndbg tools registered
    """
    server = Server("pwndbg-mcp-server")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        """List all available pwndbg tools."""
        tools = []
        for name, tool_info in pwndbg.mcp.tools.TOOLS.items():
            tools.append(
                Tool(
                    name=name,
                    description=tool_info["description"],
                    inputSchema=tool_info["parameters"],
                )
            )
        return tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        """Call a pwndbg tool with the given arguments."""
        if name not in pwndbg.mcp.tools.TOOLS:
            return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]

        tool_func = pwndbg.mcp.tools.TOOLS[name]["function"]

        try:
            # Call the tool function with arguments
            result = tool_func(**arguments)

            # Return result as JSON text
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({"error": str(e)}))]

    return server


async def run_stdio_server():
    """Run the MCP Server using stdio transport."""
    server = create_mcp_server()

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream)


def main():
    """Main entry point for the MCP Server."""
    parser = argparse.ArgumentParser(description="pwndbg MCP Server")
    parser.add_argument(
        "--stdio",
        action="store_true",
        help="Use stdio transport (default)",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="List available tools and exit",
    )

    args = parser.parse_args()

    if args.list_tools:
        print("Available pwndbg MCP tools:")
        for name, tool_info in pwndbg.mcp.tools.TOOLS.items():
            print(f"  - {name}: {tool_info['description']}")
        return

    # Default to stdio transport
    import asyncio
    asyncio.run(run_stdio_server())


if __name__ == "__main__":
    main()

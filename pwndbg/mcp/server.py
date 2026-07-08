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
from typing import Any, Dict

import pwndbg.mcp.tools

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
except ImportError:
    print("Error: MCP SDK not installed. Run: pip install mcp")
    sys.exit(1)

# Optional SSE/HTTP transport support
try:
    from mcp.server.sse import SseServerTransport
    SSE_AVAILABLE = True
except ImportError:
    SSE_AVAILABLE = False

try:
    from starlette.applications import Starlette
    from starlette.routing import Route
    import uvicorn
    HTTP_AVAILABLE = True
except ImportError:
    HTTP_AVAILABLE = False


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
    async def call_tool(name: str, arguments: Dict[str, Any]) -> list[TextContent]:
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


async def run_sse_server(host: str = "127.0.0.1", port: int = 8000):
    """Run the MCP Server using SSE transport."""
    if not SSE_AVAILABLE:
        print("Error: SSE transport not available. Install: pip install mcp[sse]")
        sys.exit(1)

    server = create_mcp_server()
    sse = SseServerTransport("/messages")

    async with sse.connect_sse() as (read_stream, write_stream):
        await server.run(read_stream, write_stream)


async def run_http_server(host: str = "127.0.0.1", port: int = 8000):
    """Run the MCP Server using HTTP transport with Starlette."""
    if not HTTP_AVAILABLE or not SSE_AVAILABLE:
        print("Error: HTTP transport not available. Install: pip install mcp[http]")
        sys.exit(1)

    server = create_mcp_server()
    sse = SseServerTransport("/messages")

    async def handle_sse(request):
        async with sse.connect_sse() as (read_stream, write_stream):
            await server.run(read_stream, write_stream)

    async def handle_messages(request):
        await sse.handle_post_message(request)

    app = Starlette(
        routes=[
            Route("/sse", endpoint=handle_sse),
            Route("/messages", endpoint=handle_messages, methods=["POST"]),
        ]
    )

    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    uvicorn_server = uvicorn.Server(config)
    await uvicorn_server.serve()


def main():
    """Main entry point for the MCP Server."""
    parser = argparse.ArgumentParser(description="pwndbg MCP Server")
    parser.add_argument(
        "--stdio",
        action="store_true",
        help="Use stdio transport (default)",
    )
    parser.add_argument(
        "--sse",
        action="store_true",
        help="Use SSE transport",
    )
    parser.add_argument(
        "--http",
        action="store_true",
        help="Use HTTP transport with Starlette",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host to bind to (for SSE/HTTP transport)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind to (for SSE/HTTP transport)",
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

    import asyncio

    # Select transport
    if args.sse:
        asyncio.run(run_sse_server(host=args.host, port=args.port))
    elif args.http:
        asyncio.run(run_http_server(host=args.host, port=args.port))
    else:
        # Default to stdio transport
        asyncio.run(run_stdio_server())


if __name__ == "__main__":
    main()

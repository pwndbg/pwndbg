"""
pwndbg MCP Server entry point

This module provides the command-line entry point for the pwndbg MCP Server.
"""

from __future__ import annotations

from .server import main

if __name__ == "__main__":
    main()

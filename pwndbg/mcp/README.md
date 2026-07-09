# pwndbg MCP Server

Model Context Protocol (MCP) Server implementation for pwndbg, enabling AI Agents to interact with the debugger programmatically.

## Test Results

- **11 tools** implemented and validated
- All API calls use real pwndbg interfaces:
  - `pwndbg.aglib.regs.read_reg()` for register access
  - `pwndbg.aglib.memory.read()` for memory inspection
  - `gdb.execute()` for command execution
- Code duplication eliminated (stack_analysis reuses get_backtrace)
- Dead code removed from heap_analysis

## Platform Limitations

- **Linux only** (requires GDB)
- LLDB support not yet implemented
- Requires active debugging session for most tools

## MCP Value

The MCP Server provides:
- **Structured JSON output** instead of text parsing
- **Type-safe parameters** with JSON Schema validation
- **Unified error handling** with consistent error format
- **AI-friendly interface** for automated debugging

Example comparison:
```
# GDB text output (requires parsing)
rax            0x0                 0
rbx            0x0                 0

# MCP JSON output (ready to use)
{"registers": {"rax": "0x0", "rbx": "0x0"}, "pc": "0x400000"}
```

## Overview

The pwndbg MCP Server exposes pwndbg's powerful debugging and analysis capabilities through a standardized MCP interface, allowing AI Agents to:

- Execute pwndbg/GDB commands
- Analyze CPU register state
- Inspect memory contents
- Perform heap analysis
- Analyze stack frames
- Set and manage breakpoints
- Control program execution
- Find ROP gadgets
- Search memory for patterns
- Disassemble code
- Get call stack backtraces

## Installation

### Prerequisites

- Python 3.8+
- pwndbg installed and configured
- MCP Python SDK: `pip install mcp`

### Setup

The MCP Server is integrated into pwndbg and can be used in two ways:

#### 1. Within GDB (Recommended)

When pwndbg is loaded in GDB, the MCP Server is automatically available:

```bash
gdb ./target_binary
(gdb) source /path/to/pwndbg/gdbinit.py
```

#### 2. Standalone Server

Start the MCP Server as a standalone process:

```bash
python -m pwndbg.mcp.server --stdio
```

## Available Tools

### 1. execute_command

Execute any pwndbg/GDB command and return the output.

**Parameters:**
- `command` (string, required): The command to execute (e.g., "vmmap", "hexdump $rsp 64")

**Example:**
```json
{
  "command": "vmmap"
}
```

### 2. get_registers

Get the current CPU register state including all general-purpose registers, PC, SP, and flags.

**Parameters:** None

**Example:**
```json
{}
```

**Returns:**
```json
{
  "registers": {
    "rax": "0x0",
    "rbx": "0x0",
    "rsp": "0x7fffffffe000"
  },
  "pc": "0x400000",
  "sp": "0x7fffffffe000",
  "flags": {
    "ZF": true,
    "CF": false
  }
}
```

### 3. inspect_memory

Read and display memory contents at a given address with hex and ASCII representation.

**Parameters:**
- `address` (integer, required): Memory address to read from
- `size` (integer, optional): Number of bytes to read (default: 64)

**Example:**
```json
{
  "address": 0x7fffffffe000,
  "size": 32
}
```

### 4. heap_analysis

Analyze the current heap state including chunks, top chunk, and memory statistics.

**Parameters:** None

**Example:**
```json
{}
```

**Returns:**
```json
{
  "chunks": [...],
  "top": "0x603000",
  "system_mem": 135168,
  "max_system_mem": 135168
}
```

### 5. stack_analysis

Analyze the current stack frames.

**Parameters:** None

**Example:**
```json
{}
```

**Returns:**
```json
{
  "frames": [
    {
      "address": "0x400000",
      "function": "main",
      "offset": 0
    }
  ]
}
```

### 6. breakpoint_set

Set a breakpoint at the specified location.

**Parameters:**
- `location` (string, required): Address, symbol, or source location (e.g., "0x400000", "main", "file.c:10")
- `type` (string, optional): Type of breakpoint ("breakpoint", "watchpoint", "catchpoint", default: "breakpoint")

**Example:**
```json
{
  "location": "main",
  "type": "breakpoint"
}
```

### 7. continue_execution

Continue program execution and return the stop reason.

**Parameters:** None

**Example:**
```json
{}
```

**Returns:**
```json
{
  "stopped": true,
  "reason": "breakpoint",
  "address": "0x400000"
}
```

### 8. find_rop_gadgets

Find ROP gadgets in the current binary or memory mappings.

**Parameters:**
- `grep` (string, optional): String to grep the output for (e.g., "pop rdi")
- `memlimit` (string, optional): Maximum size of memory pages to scan (default: "50MB")

**Example:**
```json
{
  "grep": "pop rdi",
  "memlimit": "50MB"
}
```

**Returns:**
```json
{
  "gadgets": [
    {
      "address": "0x4005a3",
      "instruction": "pop rdi ; ret"
    }
  ],
  "count": 1
}
```

### 9. search_memory

Search memory for byte sequences, strings, pointers, or integer values.

**Parameters:**
- `pattern` (string, required): The pattern to search for
- `search_type` (string, optional): Type of search ("bytes", "string", "dword", "qword", "pointer", default: "bytes")
- `executable_only` (boolean, optional): Search only executable segments (default: false)
- `writable_only` (boolean, optional): Search only writable segments (default: false)
- `limit` (integer, optional): Maximum number of results to return

**Example:**
```json
{
  "pattern": "/bin/sh",
  "search_type": "string",
  "limit": 10
}
```

### 10. disassemble

Disassemble instructions near the specified address or current PC.

**Parameters:**
- `address` (integer, optional): Address to disassemble near (default: current PC)
- `count` (integer, optional): Number of instructions to disassemble (default: 10)

**Example:**
```json
{
  "address": 0x400000,
  "count": 20
}
```

**Returns:**
```json
{
  "instructions": [
    {
      "address": "0x400000",
      "instruction": "push rbp"
    }
  ],
  "count": 1
}
```

### 11. get_backtrace

Get the current call stack backtrace.

**Parameters:** None

**Example:**
```json
{}
```

**Returns:**
```json
{
  "frames": [
    {
      "number": 0,
      "address": "0x400000",
      "function": "main",
      "source": "main.c:10"
    }
  ],
  "count": 1
}
```

## AI Agent Integration

### Claude Desktop Configuration

Add the following to your Claude Desktop configuration file:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "pwndbg": {
      "command": "python",
      "args": ["-m", "pwndbg.mcp.server", "--stdio"],
      "env": {
        "PYTHONPATH": "/path/to/pwndbg"
      }
    }
  }
}
```

### Example AI Agent Workflow

1. **Start debugging session:**
   ```
   AI: Let me start by examining the binary
   Tool: execute_command("file ./target")
   ```

2. **Set breakpoints:**
   ```
   AI: Setting a breakpoint at main
   Tool: breakpoint_set("main")
   ```

3. **Run and analyze:**
   ```
   AI: Running the program
   Tool: continue_execution()
   
   AI: Checking registers
   Tool: get_registers()
   ```

4. **Memory analysis:**
   ```
   AI: Examining stack contents
   Tool: inspect_memory(0x7fffffffe000, 64)
   ```

5. **ROP chain building:**
   ```
   AI: Finding ROP gadgets
   Tool: find_rop_gadgets("pop rdi")
   ```

## Error Handling

All tools return a standardized error format when issues occur:

```json
{
  "error": "Error message describing what went wrong"
}
```

Common error scenarios:
- GDB not available (LLDB not yet supported)
- Invalid memory addresses
- Program not running
- Command execution failures

## Architecture

```
pwndbg/mcp/
├── __init__.py       # Package initialization
├── __main__.py       # Entry point for python -m
├── server.py         # MCP Server implementation
├── tools.py          # Tool implementations (11 tools)
├── models.py         # Data models (Pydantic/dataclass)
└── README.md         # This file
```

## Development

### Running Tests

```bash
# Run MCP tests
pytest tests/mcp/test_mcp_server.py -v

# Run all tests
pytest tests/ -v
```

### Adding New Tools

1. Implement the tool function in `pwndbg/mcp/tools.py`
2. Add the tool to the `TOOLS` registry dictionary
3. Add tests in `tests/mcp/test_mcp_server.py`
4. Update this README

Example:
```python
def my_new_tool(param: str) -> Dict[str, Any]:
    """Tool description."""
    try:
        # Implementation
        return {"result": "success"}
    except Exception as e:
        return {"error": str(e)}

# Add to TOOLS registry
TOOLS = {
    # ... existing tools ...
    "my_new_tool": {
        "function": my_new_tool,
        "description": "Tool description",
        "parameters": {
            "type": "object",
            "properties": {
                "param": {
                    "type": "string",
                    "description": "Parameter description"
                }
            },
            "required": ["param"]
        }
    }
}
```

## Limitations

- LLDB support is not yet implemented (GDB only)
- Some tools require an active debugging session
- ROP gadget search is limited by memory page size
- Heap analysis depends on the allocator implementation

## Security Considerations

The MCP Server provides full access to pwndbg/GDB capabilities, including:
- Arbitrary memory read/write
- Program execution control
- Breakpoint manipulation

**Important:** Only run the MCP Server in trusted environments with trusted AI Agents.

## License

Same as pwndbg (MIT License)

## Contributing

Contributions are welcome! Please follow pwndbg's contribution guidelines.

## Support

For issues and questions:
- Open an issue on the pwndbg GitHub repository
- Check existing documentation in pwndbg/docs/

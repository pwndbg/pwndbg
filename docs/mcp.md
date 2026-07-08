# pwndbg MCP Server

The pwndbg MCP (Model Context Protocol) Server enables AI Agents to interact with pwndbg programmatically through a standardized interface.

## Overview

MCP is an open standard that allows AI models to securely connect to external tools and data sources. The pwndbg MCP Server exposes pwndbg's core debugging capabilities as MCP tools, enabling:

- AI-assisted exploit development
- Automated vulnerability analysis
- Programmatic debugging workflows
- Integration with AI Agent frameworks

## Installation

The MCP Server is included with pwndbg and requires the MCP Python SDK:

```bash
pip install mcp
```

## Usage

### Starting the MCP Server

The MCP Server can be started in two ways:

#### 1. Within GDB (with pwndbg loaded)

```bash
gdb ./binary
(gdb) source /path/to/pwndbg/gdbinit.py
(gdb) python -m pwndbg.mcp.server --stdio
```

#### 2. Standalone mode

```bash
python -m pwndbg.mcp.server --stdio
```

### Listing Available Tools

```bash
python -m pwndbg.mcp.server --list-tools
```

Output:
```
Available pwndbg MCP tools:
  - execute_command: Execute a pwndbg/GDB command and return the output
  - get_registers: Get the current CPU register state
  - inspect_memory: Read and display memory contents at the given address
  - heap_analysis: Analyze the current heap state
  - stack_analysis: Analyze the current stack frames
  - breakpoint_set: Set a breakpoint at the specified location
  - continue_execution: Continue program execution
```

## Available Tools

### execute_command

Execute any pwndbg or GDB command and return the output.

**Parameters:**
- `command` (string, required): The command to execute

**Example:**
```json
{
  "command": "vmmap"
}
```

**Response:**
```json
{
  "output": "Start              End                Perm     Size   Offset File\n0x400000           0x401000           r-xp     1000   0      /bin/test\n...",
  "return_code": 0
}
```

### get_registers

Get the current CPU register state.

**Parameters:** None

**Example:**
```json
{}
```

**Response:**
```json
{
  "registers": {
    "rax": "0x0",
    "rbx": "0x0",
    "rcx": "0x7fffffffe3a8",
    "rdx": "0x7fffffffe3a8",
    "rsi": "0x7fffffffe3a8",
    "rdi": "0x1",
    "rbp": "0x400080",
    "rsp": "0x7fffffffe2b8",
    "r8": "0x7ffff7dd4040",
    "r9": "0x7ffff7f9f840",
    "r10": "0x0",
    "r11": "0x246",
    "r12": "0x400050",
    "r13": "0x7fffffffe3a0",
    "r14": "0x0",
    "r15": "0x0",
    "rip": "0x400080"
  },
  "pc": "0x400080",
  "sp": "0x7fffffffe2b8",
  "flags": {
    "CF": false,
    "PF": false,
    "AF": false,
    "ZF": true,
    "SF": false,
    "TF": false,
    "IF": true,
    "DF": false,
    "OF": false
  }
}
```

### inspect_memory

Read and display memory contents at a given address.

**Parameters:**
- `address` (integer, required): Memory address to read from (in hex or decimal)
- `size` (integer, optional, default: 64): Number of bytes to read

**Example:**
```json
{
  "address": "0x7fffffffe2b8",
  "size": 32
}
```

**Response:**
```json
{
  "address": "0x7fffffffe2b8",
  "hex": "a8e3ffffff7f0000010000000000000040004000000000000000000000000000",
  "ascii": "........@.@.....",
  "size": 32
}
```

### heap_analysis

Analyze the current heap state, including all chunks and their metadata.

**Parameters:** None

**Example:**
```json
{}
```

**Response:**
```json
{
  "chunks": [
    {
      "address": "0x602000",
      "size": 32,
      "prev_size": 0,
      "flags": {
        "PREV_INUSE": true,
        "IS_MMAPPED": false,
        "NON_MAIN_ARENA": false
      },
      "fd": "0x602020",
      "bk": "0x601fe0"
    }
  ],
  "top": "0x602060",
  "system_mem": 135168,
  "max_system_mem": 135168
}
```

### stack_analysis

Analyze the current stack frames (backtrace).

**Parameters:** None

**Example:**
```json
{}
```

**Response:**
```json
{
  "frames": [
    {
      "address": "0x400080",
      "function": "main",
      "offset": 0
    },
    {
      "address": "0x7ffff7a2d830",
      "function": "__libc_start_main",
      "offset": 1
    },
    {
      "address": "0x400069",
      "function": "_start",
      "offset": 2
    }
  ]
}
```

### breakpoint_set

Set a breakpoint at a specified location.

**Parameters:**
- `location` (string, required): Address, symbol, or source location (e.g., "0x400000", "main", "file.c:10")
- `type` (string, optional, default: "breakpoint"): Type of breakpoint ("breakpoint", "watchpoint", "catchpoint")

**Example:**
```json
{
  "location": "main",
  "type": "breakpoint"
}
```

**Response:**
```json
{
  "number": 1,
  "address": "0x400080",
  "enabled": true,
  "type": "breakpoint",
  "location": "main"
}
```

### continue_execution

Continue program execution until the next breakpoint or signal.

**Parameters:** None

**Example:**
```json
{}
```

**Response:**
```json
{
  "stopped": true,
  "reason": "breakpoint",
  "signal": null,
  "address": "0x400090"
}
```

## Integration with AI Agents

### Using with Claude (Anthropic)

Add pwndbg to your Claude MCP configuration:

```json
{
  "mcpServers": {
    "pwndbg": {
      "command": "python",
      "args": ["-m", "pwndbg.mcp.server", "--stdio"],
      "env": {}
    }
  }
}
```

### Using with Other AI Frameworks

The MCP Server uses the standard MCP protocol over stdio, making it compatible with any MCP client implementation.

## Example Workflow

Here's an example of using pwndbg MCP with an AI Agent for exploit development:

1. **Start debugging session:**
   ```bash
   gdb ./vulnerable_binary
   (gdb) source /path/to/pwndbg/gdbinit.py
   (gdb) run
   ```

2. **Start MCP Server:**
   ```bash
   (gdb) python -m pwndbg.mcp.server --stdio
   ```

3. **AI Agent connects and analyzes:**
   - Calls `get_registers()` to inspect CPU state
   - Calls `heap_analysis()` to examine heap layout
   - Calls `inspect_memory()` to read specific memory regions
   - Calls `breakpoint_set()` to set strategic breakpoints
   - Calls `continue_execution()` to step through code

4. **AI Agent provides exploit guidance:**
   - Identifies buffer overflow vulnerabilities
   - Suggests ROP chain construction
   - Recommends exploit mitigation bypasses

## Error Handling

All tools return JSON responses. Errors are indicated by an "error" field:

```json
{
  "error": "Invalid memory address: 0xdeadbeef"
}
```

## Requirements

- Python 3.10+
- pwndbg
- MCP Python SDK (`pip install mcp`)

## Contributing

Contributions to the pwndbg MCP Server are welcome! Please see the main pwndbg contributing guide.

## License

Same as pwndbg (MIT License)

## References

- [Model Context Protocol](https://modelcontextprotocol.io/)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [pwndbg Documentation](https://pwndbg.re/)

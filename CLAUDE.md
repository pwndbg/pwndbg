# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Pwndbg is a GDB and LLDB plugin that enhances debugging for low-level software developers, reverse engineers, and exploit developers. It's a Python module providing a suite of utilities and commands that make debugging less painful.

**Key Facts:**
- Multi-debugger support: Both GDB and LLDB (LLDB support is experimental)
- Python 3.10+ required for GDB, Python 3.12+ for LLDB
- Uses `uv` for dependency management
- Monorepo structure with extensive test suite

## Development Setup

### Initial Setup
```bash
# Install dependencies and set up virtual environment
./setup.sh

# For development dependencies (includes lint, test, docs groups)
./setup-dev.sh
```

The setup creates a `.venv` virtual environment. You can customize the venv location with `PWNDBG_VENV_PATH` environment variable.

### Running Pwndbg
```bash
# Launch GDB with pwndbg
pwndbg

# Launch LLDB with pwndbg (experimental)
pwndbg-lldb
```

## Common Development Commands

### Linting and Formatting
```bash
# Run all linters (ruff, mypy, vermin, shfmt)
./lint.sh

# Auto-fix issues where possible
./lint.sh --fix
```

Linting includes:
- `ruff` for Python formatting and linting
- `mypy` for type checking
- `vermin` for Python version compatibility checks (3.10+)
- `shfmt` for shell script formatting

### Testing

Tests are organized into groups under `tests/`:
- `tests/binaries/` - Test binaries
- `tests/unit_tests/` - Unit tests
- `tests/host/` - Integration test framework
- `tests/library/` - Test libraries

```bash
# Run all tests (uses pytest)
uv run --group dev --group tests --all-extras pytest tests/

# Run specific test group
python tests/tests.py tests              # Standard tests
python tests/tests.py unit-tests         # Unit tests only
python tests/tests.py qemu-user-tests    # QEMU user-space tests
python tests/tests.py qemu-system-tests  # QEMU system tests

# Run with coverage
python tests/tests.py tests --cov

# Run specific test file
uv run --group dev --group tests --all-extras pytest tests/unit_tests/test_specific.py

# Debug tests with pdb
python tests/tests.py tests --pdb

# Run tests in serial
python tests/tests.py tests --serial
```

### Building Documentation
```bash
# Generate documentation
./scripts/generate-docs.sh

# Live preview with auto-reload
./scripts/docs-live.sh

# Verify documentation builds
./scripts/verify-docs.sh
```

Documentation is built with MkDocs and published at https://pwndbg.re/

## Architecture

### Multi-Debugger Support Architecture

Pwndbg supports both GDB and LLDB through a **debugger abstraction layer**:

#### Key Modules

1. **`pwndbg.dbg`** - Debugger abstraction layer (interface)
   - Located in `pwndbg/dbg_mod/`
   - Provides debugger-agnostic primitives
   - Contains `pwndbg.dbg.gdb/` and `pwndbg.dbg.lldb/` implementations
   - **IMPORTANT**: Use this instead of raw `gdb` or `lldb` modules when possible

2. **`pwndbg.aglib`** - Debugger-agnostic library
   - Located in `pwndbg/aglib/`
   - Built on top of `pwndbg.dbg` primitives
   - Contains shared functionality: heap analysis, ELF parsing, disassembly, QEMU handling
   - **Replacement for legacy `gdblib`** - prefer `aglib` over `gdblib`

3. **`pwndbg.gdblib`** - Legacy GDB-specific library
   - Located in `pwndbg/gdblib/`
   - **Being phased out** - use `aglib` instead when possible
   - See [issue #2489](https://github.com/pwndbg/pwndbg/issues/2489)

4. **`pwndbg.commands`** - Command implementations
   - Located in `pwndbg/commands/`
   - 100+ command files
   - Uses `@pwndbg.commands.Command` decorator pattern

5. **`pwndbginit`** - Initialization and entry points
   - Located in `pwndbginit/`
   - Contains `gdbinit.py` and `lldbinit.py`
   - Handles venv setup and module loading

### Command Implementation Pattern

Commands use a decorator pattern:

```python
from __future__ import annotations
import argparse
import pwndbg.commands
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Command description")
parser.add_argument("arg", help="Argument help")

@pwndbg.commands.Command(parser, category=CommandCategory.MISC)
@pwndbg.commands.OnlyWhenRunning  # Optional: only when process is running
def mycommand(arg) -> None:
    """Command implementation"""
    # Use pwndbg.aglib for cross-debugger functionality
    # Use pwndbg.dbg for debugger primitives
    pass
```

### Event System

Pwndbg has an event system for responding to debugger events:
- Event types defined in `EventType` enum in `pwndbg/dbg/__init__.py`
- Register handlers with `@pwndbg.dbg.event_handler` decorator
- Events: stop, exit, continue, new_objfile, start, etc.

### Caching/Memoization

Memory and computation caching is handled through decorators in `pwndbg/lib/cache.py`:
- Cache is invalidated on debugger events
- Used extensively for performance optimization

## Important Development Rules

### Multi-Debugger Compatibility

1. **DO NOT** access `gdb` or `lldb` modules directly outside of `pwndbg/dbg/`
2. **DO** use `pwndbg.aglib` instead of `pwndbg.gdblib` when possible
3. **DO** use `pwndbg.dbg` for debugger primitives (memory read/write, breakpoints, etc.)
4. When adding to Debugger API, implement for **both** GDB and LLDB

### Code Style

1. **MUST** include `from __future__ import annotations` as first import (enforced by ruff)
2. **MUST** use single-line imports (ruff isort config)
3. **MUST** pass Python 3.10+ compatibility check (vermin)
4. Line length: 100 characters max
5. Type hints encouraged (mypy enabled with strict optional)

### Memory Access

- Use `pwndbg/aglib/memory.py` functions for all memory operations
- Never read memory directly via debugger API from commands

### Process Information

- Use `pwndbg.aglib.proc` module for process properties
- Example: `pwndbg.aglib.proc.pid()` for current process PID

### Configuration

- Use `pwndbg.config.Parameter` for user-configurable options
- See docs on "Adding a Configuration Option"

### Testing Requirements

- Tests use pytest framework (version 8.0.2)
- All tests must work with Nix build system
- Test binaries compiled from source in `tests/binaries/`
- QEMU tests supported for user-space and system-level debugging

## Project Structure

```
pwndbg/
├── pwndbg/              # Main Python package
│   ├── __init__.py      # Global config object
│   ├── dbg_mod/         # Debugger abstraction layer
│   │   ├── __init__.py  # Interface definitions
│   │   ├── gdb/         # GDB implementation
│   │   └── lldb/        # LLDB implementation
│   ├── aglib/           # Debugger-agnostic library (preferred)
│   ├── gdblib/          # Legacy GDB-specific (being removed)
│   ├── commands/        # 100+ command implementations
│   ├── lib/             # Utilities (cache, config, etc.)
│   ├── color/           # Color/theming
│   ├── emu/             # Emulation support
│   └── integration/     # Decompiler integrations
├── pwndbginit/          # Entry points and initialization
├── tests/               # Test suite
│   ├── tests.py         # Test runner
│   ├── binaries/        # Test binaries
│   ├── unit_tests/      # Unit tests
│   └── library/         # Test libraries
├── scripts/             # Build and utility scripts
├── docs/                # Documentation (MkDocs)
├── nix/                 # Nix build configuration
├── gdbinit.py           # GDB entry point
├── lint.sh              # Linting script
└── setup.sh             # Setup script
```

## Special Notes

### UV Environment Variables

The project uses UV-specific environment variables (defined in `scripts/common.sh`):
- `UV_RUN` - Base uv run command
- `UV_RUN_TEST` - UV with test dependencies
- `UV_RUN_LINT` - UV with lint dependencies
- `UV_RUN_DOCS` - UV with docs dependencies
- `UV_RUN_MYPY` - UV with mypy dependencies
- `PWNDBG_NO_UV=1` - Disable UV, use system Python

### Platform Support

- **Primary**: Ubuntu 22.04/24.04 with GDB (battle-tested)
- **Experimental**: LLDB support (track issues with "LLDB Port" label)
- **QEMU**: User-space (8.1+) and system (6.2+) debugging supported
- **Architectures**: x86_64, ARM, RISC-V, and more

### Decompiler Integration

Pwndbg integrates with decompilers via `decomp2dbg`:
- Auto-syncing with decompiler views
- Configured in `pwndbg/commands/integration.py`
- Requires `decomp2dbg==3.14.0`

### Dependencies

Key dependencies (see `pyproject.toml`):
- `capstone` - Disassembly
- `unicorn` - Emulation
- `pwntools` - Binary exploitation utilities
- `pyelftools` - ELF parsing
- `ziglang` - For `cymbol` command and assembly
- `ropgadget` - ROP gadget finder
- `ipython` - For `ipi` command

## Development Workflow

1. Make changes to code
2. Run linter: `./lint.sh --fix`
3. Add tests if needed (in `tests/`)
4. Run tests: `./unit-tests.sh`
5. Check type hints on modified files: `uv run mypy --strict <modified_files>`
6. Verify docs if relevant: `./scripts/verify-docs.sh`
7. Commit following project conventions

### PR Preparation

Use the `/complete` command to run all PR checks automatically. This will:
- Run linting checks (`./lint.sh`)
- Run unit tests (`./unit-tests.sh`)
- Run mypy --strict on modified files
- Verify documentation
- Show git status summary

The command identifies modified files using:
```bash
git diff dev --name-only --diff-filter=AM | grep '\.py$'
```

## Resources

- Documentation: https://pwndbg.re/
- Contributing Guide: https://pwndbg.re/dev/contributing/
- Discord: https://discord.gg/x47DssnGwm
- Issues: https://github.com/pwndbg/pwndbg/issues

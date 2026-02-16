# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Pwndbg is a GDB and LLDB plugin that enhances debugging for low-level software developers, reverse engineers, and exploit developers. It's written in Python and supports both GDB (mature, battle-tested) and LLDB (experimental, early-stage).

**Important**: Read the developer documentation in `docs/contributing/` for comprehensive guidance. This file highlights critical information for AI-assisted development.

## Quick Reference

### Essential Commands

```bash
# Setup
./setup.sh              # Install pwndbg
./setup-dev.sh          # Setup dev environment with pre-push hooks

# Testing (CRITICAL: use dbg tests for dual-debugger support!)
./tests.sh -d gdb -g dbg              # Run dual-debugger tests with GDB
./tests.sh -d lldb -g dbg             # Run dual-debugger tests with LLDB
./tests.sh -d gdb -g gdb              # GDB-specific tests 
./tests.sh -d gdb -g cross-arch-user  # Cross-architecture tests
./kernel-tests.sh                     # Kernel tests
./unit-tests.sh                       # Unit tests (no debugger)

# Linting
./lint.sh              # Run all checks
./lint.sh -f           # Fix formatting + run checks
./lint.sh -fo          # Fix formatting only (faster)

# Documentation
./scripts/generate-docs.sh    # Update auto-generated docs (requires GDB + LLDB)
./scripts/verify-docs.sh      # Check docs match source code
./scripts/docs-live.sh        # Preview docs at http://127.0.0.1:8000/pwndbg/

# Run custom Python code wit Pwndbg+GDB
./.venv/bin/gdb /bin/ls --ex 'entry' --ex 'source code.py'  # if Pwndbg is sourced in ~/.gdbinit
./.venv/bin/pwndbg /bin/ls --ex 'entry' --ex 'source code.py'  # if Pwndbg is not sourced
```

### Running Single Tests

```bash
# Use ./tests.sh with a filter (matches test names by regex)
./tests.sh -d gdb -g dbg test_config           # Run tests matching "test_config"
./tests.sh -d gdb -g dbg heap                  # Run all heap-related tests
./tests.sh -d gdb -g gdb test_symbol           # Run GDB-specific tests matching "test_symbol"

# Other useful options: -v (verbose), -s (serial), -p (pdb on failure)
# See ./tests.sh --help for all options

# For debugging cross-arch: see docs/contributing/testing-crossarch.md
```

## Architecture Overview

**Read `docs/contributing/dev-notes.md` and `docs/contributing/common-pitfalls.md` for detailed architecture information.**

### Module Hierarchy (with strict import rules)

```
pwndbg/commands/     -> User-facing commands (NOT an API, don't import!)
    ↓ (can import from)
pwndbg/aglib/        -> Debugger-agnostic library (complex operations)
    ↓ (can import from)
pwndbg/dbg_mod/      -> Debugger abstraction layer (provides pwndbg.dbg)
    |                   ├── gdb/  (GDB implementations)
    |                   └── lldb/ (LLDB implementations)
    ↓ (can import from)
pwndbg/lib/          -> Generic utilities, NO debugger dependencies
                        (lib can ONLY import from lib)
```

### Critical Import Rules

From `docs/contributing/common-pitfalls.md`:

1. **`pwndbg/lib/` only imports `pwndbg/lib/`** - No debugger dependencies allowed
2. **`pwndbg/dbg_mod/` never imports `aglib`** - Dependency goes the other way
3. **`pwndbg/dbg_mod/__init__.py` never imports debugger-specific code** - Breaks abstraction
4. **Never import commands** - Refactor shared logic into `aglib/`
5. **Import at top of file** - Function-level imports suggest refactoring needed
6. **Don't do `from pwndbg.aglib import arch/regs`** - These are runtime-swapped objects
   - Always use: `pwndbg.aglib.arch.whatever()` and `pwndbg.aglib.regs.whatever()`

### Key Architectural Concepts

- **Debugger API**: Terse set of debugging primitives in `pwndbg/dbg_mod/`
  - Get Process object: `pwndbg.dbg.selected_inferior()`
  - Think of it as debugger-agnostic version of `gdb`/`lldb` Python modules
- **aglib**: Builds complex functionality on debugger primitives (vmmap, heap, disasm, etc.)
- **gdblib**: Legacy GDB code being phased out - avoid touching, use `aglib` instead
- **Events**: Custom system with `@pwndbg.dbg.event_handler` decorator
- **Caching**: Memoization via `@cache_until` decorators in `pwndbg/lib/cache.py`
  - Be careful when adding caching since it may introduce subtle bugs (when cache is not cleared as often as it should be)

## Adding Commands

**Read `docs/contributing/adding-a-command.md` for full details.**

Create `pwndbg/commands/my_command.py`, then import in `pwndbg/commands/__init__.py`:

```python
import argparse
import pwndbg.commands

parser = argparse.ArgumentParser(description="Brief description.")
parser.add_argument("arg", type=int, help="Argument help")

@pwndbg.commands.Command(
    parser,
    category=pwndbg.commands.CommandCategory.MISC,
    aliases=["alias"],
    examples="usage examples here",
    notes="additional notes",
    # For debugger-specific commands:
    # only_debuggers={pwndbg.dbg_mod.DebuggerType.GDB},
)
@pwndbg.commands.OnlyWhenRunning  # Use appropriate decorators
def my_command(arg: int) -> None:
    """Command implementation"""
    print(f"Got: {arg}")
```

A command should never use gdb/lldb directly and only use aglib.

Key decorators: `OnlyWhenRunning`, `OnlyWhenLocal`, `OnlyWithFile`, `OnlyWhenQemuKernel`, `OnlyWhenHeapIsInitialized`, `OnlyWithArch` (from `pwndbg/aglib/proc.py`).

## Adding Configuration Parameters

**Read `docs/contributing/adding-a-parameter.md` for full details.**

```python
param = pwndbg.config.add_param(
    "my-param-name",
    default_value,
    "lowercase noun phrase without ending punctuation",
    help_docstring="Detailed markdown explanation...",
    param_class=pwndbg.lib.config.PARAM_ENUM,  # Most restrictive that fits
    enum_sequence=["value1", "value2"],
    scope=pwndbg.lib.config.Scope.config  # config, theme, or heap
)
```

For theme colors: use `pwndbg.color.theme.add_color_param()`

The parameters can be set inside of a debugger with `set <param> <value>` or shown with `show <param> <value>`. They are also displayed in `config`, `theme` or `heap_config` commands.

## Writing Tests

**CRITICAL**: Write tests in `tests/library/dbg/tests/` for dual-debugger support (both GDB and LLDB). Only write debugger-specific tests in `tests/library/gdb/tests/` as a last resort when functionality is truly debugger-specific.

**Read `docs/contributing/writing-tests.md` for full details.**

### Dual-Debugger Tests

Use this for new GDB/LLDB tests and for any architecture-agnostic things.

```python
# tests/library/dbg/tests/test_my_feature.py
from __future__ import annotations
from ....host import Controller
from . import get_binary, pwndbg_test

BINARY = get_binary("reference-binary.native.out")

@pwndbg_test
async def test_my_feature(ctrl: Controller) -> None:
    await ctrl.launch(BINARY)
    result = await ctrl.execute_and_capture("my-command")
    assert "expected" in result
```

Run with: `./tests.sh -d gdb -g dbg` (GDB) or `./tests.sh -d lldb -g dbg` (LLDB)

### GDB-Only Tests

Only for truly GDB-specific functionality:

```python
# tests/library/gdb/tests/test_gdb_specific.py
import gdb
import pwndbg
import tests

BINARY = tests.get_binary("test.out")

def test_gdb_only_feature(start_binary):
    start_binary(BINARY)
    assert pwndbg.aglib.regs.read_regs("rsp") > 0
```

## Linting and Type Checking

**Read `docs/contributing/index.md#linting` for full details.**

- Runs: ruff, shfmt, vermin (Python 3.10+ compat), mypy, custom-lint.py
- Both `mypy` and `mypy --strict` must pass (or not increase error count)
- Use type checker in your editor (mypy --strict, pyright, etc.)
- Pre-push hook runs lint automatically after `./setup-dev.sh`

## Documentation

**Read `docs/contributing/index.md#updating-documentation` for full details.**

- Auto-generated: `docs/commands/`, `docs/functions/`, `docs/configuration/`
- After user-facing changes, run: `./scripts/generate-docs.sh` (needs GDB + LLDB)
- CI checks with: `./scripts/verify-docs.sh`
- Manual docs: Edit markdown in `docs/`, avoid auto-generated sections

## Compatibility

- **Python**: 3.10+ (Ubuntu 22.04 baseline)
- **GDB**: 12.1+
- **LLDB**: 19+ (requires Python 3.12+)
- `vermin` enforces Python 3.10 compatibility in lint

## Common Patterns

```python
# NEVER do this since those objects are runtime-swapped
from pwndbg.aglib import regs  # INSTEAD access regs via: pwndbg.aglib.regs.read_regs("<register>")
from pwndbg.aglib import arch  # INSTEAD access current arch via: pwndbg.aglib.arch

# Getting register values
sp = pwndbg.aglib.regs.read_reg("rsp")  # get arch specific register
sp = pwndbg.aglib.regs.read_reg(pwndbg.aglib.regs.stack)  # get arch agnostic stack pointer register
sp = pwndbg.aglib.regs.sp  # get arch agnistic register, works only with "sp" and "pc"

# Getting process object
inf = pwndbg.dbg.selected_inferior()

# Reading memory contents
data = pwndbg.aglib.memory.read(address, size)
# We can also read specific int-sized values
val = pwndbg.aglib.memory.u64(address)


# Writing memory contents
pwndbg.aglib.memory.write(address, data_bytes)

# Process info
pid = pwndbg.aglib.proc.pid()
```

## Additional Resources

Essential docs to read:
- `docs/contributing/dev-notes.md` - Architecture and systems
- `docs/contributing/common-pitfalls.md` - Import rules and anti-patterns
- `docs/contributing/adding-a-command.md` - Command creation details
- `docs/contributing/adding-a-parameter.md` - Configuration parameters
- `docs/contributing/writing-tests.md` - Testing guide
- `docs/contributing/testing-crossarch.md` - Cross-architecture testing
- `README.md` - Project overview
- `docs/setup.md` - Installation instructions

# Integrating Binary Ninja with pwndbg
## Requirements
You need at least the personal edition of Binary Ninja (only tested on version 4.0+) that runs at least Python 3.10 for plugins.

## Setup
Copy (or symlink) [`binja_script.py`](https://raw.githubusercontent.com/pwndbg/pwndbg/refs/heads/dev/binja_script.py) to your [plugins directory](https://docs.binary.ninja/guide/plugins.html).

## Usage
To start the Binary Ninja integration, open the binary you want to debug in Binary Ninja, then go to `Plugins > pwndbg > Start integration on current view`. This will start the XMLRPC server that pwndbg queries for information.

Then, inside GDB, run `set integration-provider binja`, which will start the integration. You can run `set integration-provider none` to disable it again.

## Features
The integration currently syncs symbol names, comments, decompilation, function type signatures, and stack variables.

## Commands
- `bn-sync`: Navigate the Binary Ninja view to the current instruction
- `decomp ADDR NLINES`: Displays the decompilation for `NLINES` lines at address `ADDR`.

## Config Options
- `bn-autosync`: If set to `yes`, every step will automatically run `bn-sync`
- `bn-il-level`: Sets the IL level to use for decompilation. Valid values are: `disasm`, `llil`, `mlil`, `hlil`
- `bn-rpc-host`/`bn-rpc-port`: The host and port to connect to for the XMLRPC server
- `bn-timeout`: The amount, in seconds, to wait for the XMLRPC server to connect

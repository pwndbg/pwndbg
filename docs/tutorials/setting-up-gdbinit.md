# Configuration GDB with .gdbinit

GDB automatically reads a configuration file on startup, which is [normally found at `~/.gdbinit`](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Initialization-Files.html). This file is simply a list of GDB commands, the same as the ones you would type during a GDB session.

This is where you can globally configure GDB as well as pwndbg-specific settings and themes. While in a GDB session, you can run `config` and `theme` to display all the different pwndbg settings you can use.



## pwndbg settings in .gdbinit

When using GDB as the underlying debugger, `pwndbg` can be launched in two ways
1. Using the `pwndbg` command, which invokes gdb under the hood.
2. Through an explicit `source /path/to/pwndbg/gdbinit.py` within your `.gdbinit` file. This is the classic "pwndbg as a plugin" setup.

Either way, whenever GDB runs, the `.gdbinit` file will be read. It is recommended to gate your pwndbg-specific configuration behind a check to ensure pwndbg really is currently loaded. Otherwise, if you ever run `gdb` without pwndbg loaded, it will throw errors on startup when it cannot find the settings pwndbg registers with GDB.

```sh
# Check that pwndbg is loaded in the current session
if ! $_isvoid($pwndbg_plugin_enabled)
    # Put pwndbg-specific configuration setup in here
    # Run `config` and `theme` to get a full list of pwndbg settings

    # Here are some examples
    set context-disasm-lines 15
    set show-flags on

    # Enable full stacktraces on errors
    set exception-verbose on
    set exception-debugger on
end

# Put non-pwndbg specific GDB settings outside of that block.
# For example:
set history size unlimited
set print nibbles on
set print asm-demangle on
```

The [GDB docs](https://www.sourceware.org/gdb/documentation/) contains the extensive list of all GDB settings available.

Note that on startup, `pwndbg` sets a handful of GDB settings to more sane defaults, such as registering some signal handlers and disabling unnecessary GDB prompts.

## Custom GDB command hooks

If you have a set of commands you run repeatedly, you can [register a custom command](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Define.html) in your `.gdbinit` file.

For example, you can define a command like `getinfo`
```sh
define getinfo
    info registers pc sp
    x/4i $pc
    backtrace 3
end
```

You can even [register custom hooks](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Hooks.html), which run every time some event occurs or some command is executed.

You can hook any specific command. The `hookpost-` prefix lets you run something AFTER another command is run
```sh
define hookpost-vmmap
    echo "You just ran VMMAP"
end
```

The `hook-stop` is a special hook which runs whenever the process stops (such as when hitting breakpoints or just stepping)
```sh
define hook-stop
    echo "Process stopped"
end
```


## .gdbearlyinit

GDB also reads a `.gdbearlyinit` earlier in the startup process. Currently, theres only one interesting configuration to put here:

```sh
set startup-quietly on
```

This silences the multiline boilerplate that GDB outputs by default on startup.

Another common way to achieve this is to set an alias in your shell init files, such as
```sh
alias gdb="gdb -q"
```


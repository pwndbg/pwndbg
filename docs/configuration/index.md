# Configuration

There are three "scopes" of configuration parameters currently:

1. [the config scope](./config.md) - for generic parameters
2. [the heap scope](./heap.md) - for heap-related parameters
3. [the theme scope](./theme.md) - for pwndbg theming

To see the parameters belonging to these scopes, use the [`config`](../commands/pwndbg/config.md), [`heap-config`](../commands/pwndbg/heap-config.md), and [`theme`](../commands/pwndbg/theme.md) commands respectively. You can also use the [`configfile`](../commands/pwndbg/configfile.md) and [`themefile`](../commands/pwndbg/themefile.md) commands to save your live configuration to a file which you can then load in your `~/.(gdb/lldb)init` file (after sourcing pwndbg!).

To see the value of any parameter, use `show param-name`. To set the value, use `set param-name param-value`. To see a more detailed description of the parameter use `help set param-name`.

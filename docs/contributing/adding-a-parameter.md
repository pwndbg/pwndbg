# Adding a Configuration Option
Configuration options are also called "parameters" in the source. Let's take a look at an existing parameter `gdb-workaround-stop-event` defined in `pwndbg/gdblib/events.py`.
```python
DISABLED = "disabled"
DISABLED_DEADLOCK = "disabled-deadlock"
ENABLED = "enabled"

gdb_workaround_stop_event = config.add_param(
    "gdb-workaround-stop-event",
    DISABLED,
    "asynchronous stop events to improve 'commands' functionality",
    help_docstring=f"""
Note that this may cause unexpected behavior with Pwndbg or gdb.execute.

Values explained:

+ `{DISABLED}` - Disable the workaround (default).
+ `{DISABLED_DEADLOCK}` - Disable only deadlock detection; deadlocks may still occur.
+ `{ENABLED}` - Enable asynchronous stop events; gdb.execute may behave unexpectedly (asynchronously).
    """,
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=[DISABLED, DISABLED_DEADLOCK, ENABLED],
)
```
To understand it, let's also look at the signature of the `Config.add_param` function defined in `pwndbg/lib/config.py`:
```python
    def add_param(
        self,
        name: str,
        default: Any,
        set_show_doc: str,
        *,
        help_docstring: str = "",
        param_class: int | None = None,
        enum_sequence: Sequence[str] | None = None,
        scope: Scope = Scope.config,
    ) -> Parameter:
	    # ...
```
So, the first argument specifies the name by which the parameter will be used inside the debugger. The second argument specifies the default value of the parameter.
## set_show_doc
The third argument is a very brief description of what the parameter is for. The argument is called `set_show_doc` due to how it is used in GDB.
```text
pwndbg> set gdb-workaround-stop-event enabled
Set asynchronous stop events to improve 'commands' functionality to 'enabled'.
   |------------------------------------------------------------|
```
```text
pwndbg> show gdb-workaround-stop-event
Asynchronous stop events to improve 'commands' functionality is 'enabled'. [...]
|-----------------------------------------------------------|
```
It is therefore recommended to use a noun phrase rather than describe an action. However, it sometimes may be necessary to break this rule to retain the brevity of the description.

The `set_show_doc` argument should be short because it is displayed with the `config` family of commands.
```text
pwndbg> config
Name                               Documentation                                                            Value (Default)
----------------------------------------------------------------------------------------------------------------------------
ai-anthropic-api-key               Anthropic API key                                                        ''
ai-history-size                    maximum number of questions and answers to keep in the prompt            3
ai-max-tokens                      the maximum number of tokens to return in the response                   100
ai-model                           the name of the large language model to query                            'gpt-3.5-turbo'
ai-ollama-endpoint                 Ollama API endpoint                                                      ''
ai-openai-api-key                  OpenAI API key                                                           ''
ai-show-usage                      whether to show how many tokens are used with each OpenAI API call       off
ai-stack-depth                     rows of stack context to include in the prompt for the ai command        16
ai-temperature                     the temperature specification for the LLM query                          0
attachp-resolution-method          how to determine the process to attach when multiple candidates exists   'ask'
auto-explore-auxv                  stack exploration for AUXV information; it may be really slow            'warn'
auto-explore-pages                 whether to try to infer page permissions when memory maps are missing    'warn'
auto-explore-stack                 stack exploration; it may be really slow                                 'warn'
auto-save-search                   automatically pass --save to "search" command                            off
bn-autosync                        whether to automatically run bn-sync every step                          off
[...]
```
Because of the various contexts in which a parameter can be show, the first letter of the `set_show_doc` string should be lowercase (unless the first word is a name or an abbreviation) and there should be no punctuation at the end. This way, Pwndbg and GDB can more easily modify the string to fit it into these contexts.
## help_docstring
While `help_docstring` is not mandatory, it is highly recommended to use it. Put a detailed explanation of what the parameter does here, and explain any caveats. This string does not have a size limit and is shown with the following command in GDB and LLDB:
```text
pwndbg> help set gdb-workaround-stop-event
Set asynchronous stop events to improve 'commands' functionality.
Note that this may cause unexpected behavior with Pwndbg or gdb.execute.

Values explained:

+ `disabled` - Disable the workaround (default).
+ `disabled-deadlock` - Disable only deadlock detection; deadlocks may still occur.
+ `enabled` - Enable asynchronous stop events; gdb.execute may behave unexpectedly (asynchronously).

Default: 'disabled'
Valid values: 'disabled', 'disabled-deadlock', 'enabled'
```
Note that the last two lines are automatically generated by Pwndbg.

When writing this explanation, it is important to take into account how it will be displayed [in the documentation](https://pwndbg.re/pwndbg/dev/configuration/) after being parsed as markdown. See what `gdb-workaround-stop-event` looks like here: https://pwndbg.re/pwndbg/dev/configuration/config/#gdb-workaround-stop-event . If there wasn't an empty line between `Values explained:` and ``+ `disabled`..`` the list wouldn't have rendered properly.
## param_class
This argument describes the type of the parameter. It will be used by GDB to perform input validation when the parameter is being set so it is important to set this to the correct value. The possible values are defined in `pwndbg/lib/config.py`, use the most restrictive one that fits:
```python
# Boolean value. True or False, same as in Python.
PARAM_BOOLEAN = 0
# Boolean value, or 'auto'.
PARAM_AUTO_BOOLEAN = 1
# Signed integer value. Disallows zero.
PARAM_INTEGER = 2
# Signed integer value.
PARAM_ZINTEGER = 3
# Unsigned integer value. Disallows zero.
PARAM_UINTEGER = 4
# Unsigned integer value.
PARAM_ZUINTEGER = 5
# Unlimited ZUINTEGER.
PARAM_ZUINTEGER_UNLIMITED = 6
# String value. Accepts escape sequences.
PARAM_STRING = 7
# String value, accepts only one of a number of possible values, specified at
# parameter creation.
PARAM_ENUM = 8
# String value corresponding to the name of a file, if present.
PARAM_OPTIONAL_FILENAME = 9
```
For more information (for instance about what `None` or `"unlimited"` mean) see https://sourceware.org/gdb/current/onlinedocs/gdb.html/Parameters-In-Python.html .
### enum_sequence
If the `param_class` is set to `pwndbg.lib.config.PARAM_ENUM` then the `enum_sequence` argument must be supplied as well. It should constitute an array of legal values. GDB and (our) LLDB (driver) won't allow setting the parameter to any other value. The legal values will be automatically displayed at the end of `help_docstring` as previously shown.

If it isn't immediately obvious what the enum values do, explain them in `help_docstring` using same format that `gdb-workaround-stop-event` uses.
## scope
The `scope` argument has the default value of `pwndbg.lib.config.Scope.config` and is used to group parameters. The legal values are:
```python
class Scope(Enum):
    # If you want to add another scope here, don't forget to add
    # a command which prints it!
    config = 1
    theme = 2
    heap = 3
```
The parameters of each scope are printed using a different command. The `config` scope is printed with [`config`](https://pwndbg.re/pwndbg/dev/commands/pwndbg/config/), the `heap` scope is printed with [`heap-config`](https://pwndbg.re/pwndbg/dev/commands/pwndbg/heap-config/) and the `theme` scope is printed with [`theme`](https://pwndbg.re/pwndbg/dev/commands/pwndbg/theme/). The `config` and `theme` scopes also have corresponding [`configfile`](https://pwndbg.re/pwndbg/dev/commands/pwndbg/configfile/) and [`themefile`](https://pwndbg.re/pwndbg/dev/commands/pwndbg/themefile/) commands which export the values of all the parameters from those scopes.
### The `theme` scope
You should never directly pass this scope to `pwndbg.config.add_param`. Instead use the `pwndbg.color.theme.add_param` and `pwndbg.color.theme.add_color_param` wrapper commands like this:
```python
# pwndbg/aglib/nearpc.py
nearpc_branch_marker = pwndbg.color.theme.add_param(
    "nearpc-branch-marker", "    ↓", "branch marker line for nearpc command"
)
```
```python
# pwndbg/color/context.py
config_highlight_color = theme.add_color_param(
    "highlight-color", "green,bold", "color added to highlights like source/pc"
)
```
## Using the parameter in code
Usually when a parameter is defined its value is also set to a variable, for instance `gdb_workaround_stop_event = ...` in the initial example. This isn't necessary, as all registered parameters are available as `pwndbg.config.<parameter_name_except_with_underscores>` so in our example, we could also access the `gdb-workaround-stop-event` parameter as `pwndbg.config.gdb_workaround_stop_event`.

That being said, defining the variable can reduce code verbosity:
```python
# pwndbg/aglib/godbg.py
line_width = pwndbg.config.add_param(
    "go-dump-line-width", 80, "the soft line width for go-dump pretty printing"
)
```
Since the variable is scoped to the `godbg.py` file, its name can be short, and we don't have to write `pwndbg.config.go_dump_line_width` every time.
### Using color parameters
Note that the `theme.add_color_param()` function returns a `ColorParameter` object instead of a `Parameter`. The parameter should be used via its `color_function()` method:
```python
# pwndbg/aglib/godbg.py
def fmt_debug(self, val: str, default: str = "") -> str:
	if self.debug:
		return debug_color.color_function(val)
	else:
		return default
```
Though you will also see `generateColorFunction(debug_color)(val)` being used in the code to the same effect.

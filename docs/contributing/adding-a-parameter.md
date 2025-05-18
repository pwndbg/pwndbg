# Adding a Configuration Option

```python
import pwndbg

pwndbg.config.add_param("config-name", False, "example configuration option")
```

`pwndbg.config.config_name` will now refer to the value of the configuration option, and it will default to `False` if not set.

## Configuration Docstrings (GDB)

TODO: There are many places GDB shows docstrings, and they show up slightly differently in each place, we should give examples of this

* When using `pwndbg.config.add_param` to add a new config, there are a few things to keep in mind:
  * For the `set_show_doc` parameter, it is best to use a noun phrase like "the value of something" to ensure that the output is grammatically correct.
  * For the `help_docstring` parameter, you can use the output of `help set follow-fork-mode` as a guide for formatting the documentation string if the config is an enum type.
  * For the `param_class` parameter
    * See the [documentation](https://sourceware.org/gdb/onlinedocs/gdb/Parameters-In-Python.html) for more information.
    * If you use `gdb.PARAM_ENUM` as `param_class`, you must pass a list of strings to the `enum_sequence` parameter.

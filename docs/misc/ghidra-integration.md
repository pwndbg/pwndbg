# Ghidra Integration

With the help of [radare2](https://github.com/radareorg/radare2) or [rizin](https://github.com/rizinorg/rizin) it is possible to show the decompiled source code of the ghidra decompiler.

However, this comes with some prerequisites.

* First: you have to have installed radare2 or rizin and it must be found by gdb (within path)
* Second: you have to install the ghidra plugin for radare2
  [r2ghidra](https://github.com/radareorg/r2ghidra) or install the ghidra plugin for rizin [rz-ghidra](https://github.com/rizinorg/rz-ghidra)
* Third: r2pipe has to be installed in the python-context gdb is using (or if you are using rizin, install rzpipe instead)

The decompiled source be shown as part of the context by adding `ghidra` to `set context-sections`
or by calling `ctx-ghidra [function]` manually.

Be warned, the first call to both radare2/r2ghidra and rizin/rz-ghidra are rather slow! Subsequent requests for decompiled
source will be faster. And it does take up some resources as the radare2/rizin instance is kept by r2pipe/rzpipe
to enable faster subsequent analysis.

With those performance penalties it is reasonable to not have it launch always. Therefore it includes
an option to only start it when required with `set context-ghidra`:

* `set context-ghidra always`: always trigger the ghidra context
* `set context-ghidra never`: never trigger the ghidra context except when called manually
* `set context-ghidra if-no-source`: invoke ghidra if no source code is available

Remark: the plugin tries to guess the correct current line and mark it with "-->", but it might
get it wrong.

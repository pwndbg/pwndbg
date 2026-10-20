# pwndbg-themes [![license](https://img.shields.io/github/license/mashape/apistatus.svg?maxAge=2592000)](https://github.com/pwndbg/pwndbg-themes/blob/master/LICENSE)

Collection of beautiful Pwndbg themes. Open a PR to add yours!

## How to use a theme

You may try out different themes with the `theme-try` command.

To set a theme long term, source the `*.pwndbg` theme file from your `.gdbinit` or `.lldbinit`.

If you're using the `pwndbg` CLI command, put the source command wherever in your `.gdbinit`,
but if you're sourcing Pwndbg in your `.gdbinit` make sure the source of the theme itself
happens after you source Pwndbg.

Example:
```gdb
source /usr/share/pwndbg/gdbinit.py
source /usr/share/pwndbg/themes/anthraxx.pwndbg
```

## How to make and submit a theme

Run the `pwndbg> theme` command to see which options are available.

Only theme related style options should be set, any usage of other config options
like the amount of printed lines (f.e. `set nearpc-lines 20`), screen clearing,
show flags or other behaviour should not be altered within a theme.

After setting the options you want, you may easily generate a theme file by copying the output
of the `pwndbg> themefile` command.

The filename should end with the `.pwndbg` extension. When you open a PR to add a theme, you
must provide a couple of screenshots so we can see what your theme looks like. 


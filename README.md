
This is a work-in-progress replacement for PEDA. 
I was originally just going to use the [GEF code from Hugsy](https://github.com/hugsy/re-stuff.git)
but then I went a bit overboard.

In particular, it's designed to be fast*, failure-tolerant**, and eventually portable
to Python27/Python3 as well as GDB/LLDB.

Currently it works on GDB with Python3.

\* Lots of use of `gdb.event` to manage cache lifetimes.
\*\* Automatic exploration of process maps when you're doing e.g. remote debugging
     of a QEMU user stub and `/proc/$$/pids` is broken for `${reasons}`.
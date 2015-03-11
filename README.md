
# pwndbg

A PEDA replacement.

- Speed
- Resiliency
- Clean code

Best supported on Ubuntu 14.04 with default `gdb` or `gdb-multiarch` (e.g. with Python3).

## Installation

Pretty easy.

1. Clone the repo: `git clone https://github.com/zachriggle/pwndbg`
2. Add to `~/.gdbinit`: `source ~/pwndbg/gdbinit.py`

## Screenshots

Here's a screenshot of `pwndbg` working on an aarch64 binary running under `qemu-user`. 

![a](caps/a.png?raw=1)

Here's a screenshot of `PEDA`.  That it's aarch64 doesn't matter -- it chokes in the same way for everything qemu-user.

![c](caps/b.png?raw=1)

And here's a screenshot of GDB's built-in commands failing horribly.  Note that while, yes, it gives output -- the addresses it does give are all wrong, and are just file offsets.

![c](caps/c.png?raw=1)

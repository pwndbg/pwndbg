# BETA SOFTWARE

This is barely a beta.  There are currently no versioned releases, only `master`.  I push to master with impunity.  There are no tests.  If anything works at all, consider yourself lucky.

Feature contributions and bugfixes are both very welcome :)

# pwndbg

A PEDA replacement.  In the spirit of our good friend `windbg`, `pwndbg` is pronounced `pwnd-bag`.

- Speed
- Resiliency
- Clean code

Best supported on Ubuntu 14.04 with default `gdb` or `gdb-multiarch` (e.g. with Python3).

## Installation

```sh
git clone https://github.com/zachriggle/pwndbg
cd pwndbg
./setup.sh
```

## Features

Does most things that PEDA does.  Doesn't do things that PEDA does that [pwntools](https://github.com/Gallopsled/pwntools) or [binjitsu](https://binjit.su) (my fork of pwntools) do better.

Also has a basic windbg compat layer for e.g. `dd`, `eb`, `da`, `dps`.  Now you can even [`eb eip 90`](https://twitter.com/ebeip90)!

For most standard function calls, it knows how many arguments there are and can print out the function call args.

## Screenshots

Here's a few screenshots of some of the cool things pwndbg does.

![e](caps/e.png?raw=1)  
*Function arguments*

![f](caps/f.png?raw=1)  
*Conditional jump evaluation and jump following*

![g](caps/g.png?raw=1)  
*More dump following*

![h](caps/h.png?raw=1)  
*RET following, useful for ROP*

Here's a screenshot of `pwndbg` working on an aarch64 binary running under `qemu-user`.

![a](caps/a.png?raw=1)

Here's a screenshot of `PEDA`.  That it's aarch64 doesn't matter -- it chokes in the same way for everything qemu-user.

![c](caps/b.png?raw=1)

And here's a screenshot of GDB's built-in commands failing horribly.  Note that while, yes, it gives output -- the addresses it does give are all wrong, and are just file offsets.

![c](caps/c.png?raw=1)


This is a work-in-progress replacement for PEDA. 
I was originally just going to use the [GEF code from Hugsy](https://github.com/hugsy/re-stuff.git)
but then I went a bit overboard.

In particular, it's designed to be fast\*, failure-tolerant\*\*, and eventually portable
to Python27/Python3 as well as GDB/LLDB.

Currently it works on GDB with Python3.

\* Lots of use of `gdb.event` to manage cache lifetimes.  
\*\* Automatic exploration of process maps when you're doing e.g. remote debugging
     of a QEMU user stub and `/proc/$$/pids` is broken for `${reasons}`.


Snazzy features which may not work:


### Type Printing

Hurray windbg.  This works without any loaded symbols, and is architecture-appropriate.

```
geef> show arch
The target architecture is set automatically (currently i386:x86-64)
geef> dt hostent
hostent
    +0x0000 h_name               : char *
    +0x0008 h_aliases            : char **
    +0x0010 h_addrtype           : int
    +0x0014 h_length             : int
    +0x0018 h_addr_list          : char **
geef> dt passwd
passwd
    +0x0000 pw_name              : char *
    +0x0008 pw_passwd            : char *
    +0x0010 pw_uid               : __uid_t
    +0x0014 pw_gid               : __gid_t
    +0x0018 pw_gecos             : char *
    +0x0020 pw_dir               : char *
    +0x0028 pw_shell             : char *
```
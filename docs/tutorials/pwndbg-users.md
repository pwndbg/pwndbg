# Pwndbg in the wild

Here is a non-exhaustive list of Pwndbg mentions found in the wild. Feel free to open a PR to add more if you find them!

## Talks
+ [EuroPython 2025 - Pwndbg: Low level debugging and exploit development with Python](https://ep2025.europython.eu/session/pwndbg-low-level-debugging-and-exploit-development-with-python) ([slides](https://docs.google.com/presentation/d/1m9yYOeHxkKznseTakYeKixOUcCEjk7e-goirNE93ISs/), [video](https://www.youtube.com/watch?v=hRvjre7AH-o&t=7100s))
+ [OffensiveCon24 - How to Fuzz Your Way to Android Universal Root: Attacking Android Binder - by Eugene Rodionov, Zi Fan Tan and Gulshan Singh](https://www.youtube.com/watch?v=U-xSM159YLI&t=1859s)

## Blog posts
+ [Oops Safari, I think You Spilled Something! @ Exodus Intelligence](https://blog.exodusintel.com/2025/08/04/oops-safari-i-think-you-spilled-something/)
+ [“Unstripping” binaries: Restoring debugging information in GDB with Pwndbg by Jason An @ Trail of Bits](https://blog.trailofbits.com/2024/09/06/unstripping-binaries-restoring-debugging-information-in-gdb-with-pwndbg/)
+ [A Winter’s Tale: Improving messages and types in GDB’s Python API by Matheus Branco Borella @ Trail of Bits](https://blog.trailofbits.com/2023/04/18/a-winters-tale-improving-types-and-messages-in-gdbs-python-api/)
+ [Patch-gapping Google Chrome @ Exodus Intelligence](https://blog.exodusintel.com/2019/09/09/patch-gapping-chrome/)
+ [Inspecting rdtsc with pwndbg by John Shaughnessy](https://www.johnshaughnessy.com/blog/posts/rdtsc_and_pwndbg)

## Videos
+ [Intro to pwndbg - CTF Cookbook by SloppyJoePirates CTF Writeups](https://www.youtube.com/watch?v=5judobmDBKI)
+ [Intro to Binary Exploitation (Pwn) by CryptoCat](https://youtu.be/wa3sMSdLyHw?list=PLHUKi1UlEgOIc07Rfk2Jgb5fZbxDPec94&t=730)
+ [Bug A Day #8 - pwndbg #2 by Bug-A-Day](https://www.youtube.com/watch?v=mmkewHlDv9I)

## Scripts
+ [CVE-2022-24834 exploit by ptr-yudai](https://github.com/RICSecLab/exploit-poc-public/blob/main/CVE-2022-24834/exploit.py#L49)

## Magazine articles
+ ["Programista" polish programming magazine - Low level debugging with Pwndbg (in polish)](https://programistamag.pl/programista-42023-109-wrzesienpazdziernik-2023-debugowanie-niskopoziomowe-z-pwndbg/)

## Software
+ [ghidra2dwarf](https://github.com/cesena/ghidra2dwarf) shows Pwndbg in its README.md example
+ [decomp2dbg implements a Pwndbg client](https://github.com/mahaloz/decomp2dbg/blob/36d4b5bbb0ec1d3751d1b4a0e011a4fabf59f26c/decomp2dbg/clients/gdb/pwndbg_client.py) (though we implement our own integration now :) )
+ [An (outdated :( ) pwndbg plugin for scudo exploitation](https://github.com/HexHive/scudo-exploitation/blob/main/gdb-plugin/scudo-pwndbg.py)
+ [gdb-peda-pwndbg-gef](https://github.com/apogiatzis/gdb-peda-pwndbg-gef) - A script that installs those tools
+ [splitmind](https://github.com/jerdna-regeiz/splitmind) - Better organization of Pwndbg contexts via tmux splits
+ [hyperpwn](https://github.com/bet4it/hyperpwn) - Similar as splitmind, but for the hypr terminal
+ [epictreasure](https://github.com/praetorian-inc/epictreasure) - A [vagrant](https://developer.hashicorp.com/vagrant) box that includes Pwndbg
+ [pwn-init-env](https://github.com/giantbranch/pwn-env-init) - A pwn environment that includes Pwndbg
+ [gdbw](https://github.com/iilegacyyii/gdbw) - A scriptable CLI debugger for windows inspired by Pwndbg
+ [pwndbg-gui](https://github.com/AlEscher/pwndbg-gui) - A Pwndbg GUI wrapper
+ [pwnmux](https://github.com/joaogodinho/pwnmux) - A Pwndbg configuration to use tmux panes
+ [GEP](https://github.com/lebr0nli/GEP) - A GDB plugin that allows fuzzy searching the GDB history, compatible with Pwndbg
+ [217gdb](https://github.com/cebrusfs/217gdb) - Modifies the Pwndbg UI for better usage
+ And [many more](https://github.com/search?q=pwndbg&type=repositories)

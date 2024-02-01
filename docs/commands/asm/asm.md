



# asm

## Description


Assemble shellcode into bytes
## Usage:


```bash
usage: asm [-h] [-f {hex,string}]
           [--arch {powerpc64,aarch64,powerpc,riscv32,riscv64,sparc64,mips64,msp430,alpha,amd64,sparc,thumb,cris,i386,ia64,m68k,mips,s390,none,avr,arm,vax}] [-v AVOID] [-n]
           [-z] [-i INFILE]
           [shellcode ...]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`shellcode`|Assembler code to assemble (default: %(default)s)|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
|`-f`|`--format`|`hex`|Output format (default: %(default)s)|
||`--arch`|`i386`|Target architecture (default: %(default)s)|
|`-v`|`--avoid`|`None`|Encode the shellcode to avoid the listed bytes (provided as hex)|
|`-n`|`--newline`|`None`|Encode the shellcode to avoid newlines|
|`-z`|`--zero`|`None`|Encode the shellcode to avoid NULL bytes|
|`-i`|`--infile`|`None`|Specify input file|

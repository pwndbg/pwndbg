



# vmmap

## Description


Print virtual memory map pages.

Unnamed mappings are named as [anon_%#x] where %#x is high part of their start address. This is useful for filtering with `vmmap` or `search` commands.

Known issues with vmmap:
For QEMU user targets, the QEMU's gdbstub does not provide memory maps information to GDB until [0] is finished & merged. We try to deal with it without parsing the QEMU process' /proc/$pid/maps file, but if our approach fails, we simply create a [0, 0xffff...] vmmap which is not great and may result in lack of proper colors or inability to search memory with the `search` command.

For QEMU kernel, we use gdb-pt-dump that parses page tables from the guest by reading /proc/$pid/mem of QEMU process. If this does not work for you, use `set kernel-vmmap-via-page-tables off` to refer to our old method of reading vmmap info from `monitor info mem` command exposed by QEMU. Note that the latter may be slower and will not give full vmmaps permission information.

For coredump debugging, GDB also lacks all vmmap info but we do our best to get it back by using the `info proc mappings` and `maintenance info sections` commands.

As a last resort, we sometimes try to explore the addresses in CPU registers and if they are readable by GDB, we determine their bounds and create an "<explored>" vmmap. However, this method is slow and is not used on each GDB stop.

Memory pages can also be added manually with the use of vmmap_add, vmmap_clear and vmmap_load commands. This may be useful for bare metal debugging.

[0] https://lore.kernel.org/all/20220221030910.3203063-1-dominik.b.czarnota@gmail.com/
## Usage:


```bash
usage: vmmap [-h] [-w] [-x] [-A LINES_AFTER] [-B LINES_BEFORE] [gdbval_or_str]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`gdbval_or_str`|Address or module name filter|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
|`-w`|`--writable`||Display writable maps only (default: %(default)s)|
|`-x`|`--executable`||Display executable maps only (default: %(default)s)|
|`-A`|`--lines-after`|`1`|Number of pages to display after result (default: %(default)s)|
|`-B`|`--lines-before`|`1`|Number of pages to display before result (default: %(default)s)|

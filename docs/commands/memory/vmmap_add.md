



# vmmap_add

## Description


Add virtual memory map page.
## Usage:


```bash
usage: vmmap_add [-h] start size [flags] [offset]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`start`|Starting virtual address|
|`size`|Size of the address space, in bytes|
|`flags`|Flags set by the ELF file, see PF_X, PF_R, PF_W (default: %(default)s)|
|`offset`|Offset into the original ELF file that the data is loaded from (default: %(default)s)|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|

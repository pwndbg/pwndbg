## Command: vmmap_add ##
```
usage: vmmap_add [-h] start size [flags] [offset]
```
Add Print virtual memory map page.  

| Positional Argument | Info |
|---------------------|------|
| start | Starting virtual address |
| size | Size of the address space, in bytes |
| flags | Flags set by the ELF file, see PF_X, PF_R, PF_W (default: ) |
| offset | Offset into the original ELF file that the data is loaded from (default: 0) |

| Optional Argument | Info |
|---------------------|------|
| --help | show this help message and exit |



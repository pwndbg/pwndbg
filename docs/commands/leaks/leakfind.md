## Command: leakfind ##
```
usage: leakfind [-h] [-p [PAGE_NAME]] [-o [MAX_OFFSET]] [-d [MAX_DEPTH]] [-s [STEP]] [--negative_offset [NEGATIVE_OFFSET]] address
```
Attempt to find a leak chain given a starting address. Scans memory near the given address, looks for pointers, and continues that process to attempt to find leaks. Example: leakfind $rsp --page_name=filename --max_offset=0x48 --max_depth=6. This would look for any chains of leaks that point to a section in filename which begin near $rsp, are never 0x48 bytes further from a known pointer, and are a maximum length of 6  

| Positional Argument | Info |
|---------------------|------|
| address | Starting address to find a leak chain from |

| Optional Argument | Info |
|---------------------|------|
| --help | show this help message and exit |
| --page_name | Substring required to be part of the name of any found pages |
| --max_offset | Max offset to add to addresses when looking for leak (default: 72) |
| --max_depth | Maximum depth to follow pointers to (default: 4) |
| --step | Step to add between pointers so they are considered. For example, if this is 4 it would only consider pointers at an offset divisible by 4 from the starting pointer (default: 1) |
| --negative_offset | Max negative offset to search before an address when looking for a leak (default: 0) |



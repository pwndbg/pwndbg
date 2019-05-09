## Command: rop ##
```
usage: rop [-h] [--grep GREP] [argument [argument ...]]
```
Dump ROP gadgets with Jon Salwan's ROPgadget tool.  

| Positional Argument | Info |
|---------------------|------|
| argument | Arguments to pass to ROPgadget |

| Optional Argument | Info |
|---------------------|------|
| --help | show this help message and exit |
| --grep | String to grep the output for |


Example: rop --grep 'pop rdi' -- --nojop


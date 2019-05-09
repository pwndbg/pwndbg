## Command: search ##
```
usage: search [-h] [-t {byte,short,word,dword,qword,pointer,string,bytes}] [-1] [-2] [-4] [-8] [-p] [-x] [-s] [-e] [-w] [--save] [--no-save] [-n] value [mapping_name]
```
Search memory for byte sequences, strings, pointers, and integer values  

| Positional Argument | Info |
|---------------------|------|
| value | Value to search for |
| mapping_name | Mapping to search [e.g. libc] |

| Optional Argument | Info |
|---------------------|------|
| --help | show this help message and exit |
| --type {byte,short,word,dword,qword,pointer,string,bytes} | Size of search target (default: bytes) |
| --byte | Search for a 1-byte integer |
| --word,short |  Search for a 2-byte integer |
| --dword | Search for a 4-byte integer |
| --qword | Search for an 8-byte integer |
| --pointer | Search for a pointer-width integer |
| --hex | Target is a hex-encoded (for bytes/strings) (default: False) |
| --string | Target is a raw string (default: False) |
| --executable | Search executable segments only (default: False) |
| --writable | Search writable segments only (default: False) |
| --save | Save results for --resume. Default comes from config 'auto_save_search' |
| --no-save | Invert --save |
| --next | Search only locations returned by previous search with --save (default: False) |



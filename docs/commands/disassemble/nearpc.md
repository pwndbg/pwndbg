



# nearpc

## Description


Disassemble near a specified address.
## Usage:


```bash
usage: nearpc [-h] [-e] [pc] [lines]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`pc`|Address to disassemble near. If this is the only argument and the value provided is small enough, it is interpreted as lines instead.|
|`lines`|Number of lines to show on either side of the address.|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
|`-e`|`--emulate`||Whether to emulate instructions to find the next ones or just linearly disassemble. (default: %(default)s)|





# contextoutput

## Description


Sets the output of a context section.
## Usage:


```bash
usage: contextoutput [-h] section path clearing [banner] [width]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`section`|The section which is to be configured. ('regs', 'disasm', 'code', 'stack', 'backtrace', and/or 'args')|
|`path`|The path to which the output is written|
|`clearing`|Indicates weather to clear the output|
|`banner`|Where a banner should be placed: both, top , bottom, none (default: %(default)s)|
|`width`|Sets a fixed width (used for banner). Set to None for auto|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|

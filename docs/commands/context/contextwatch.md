



# contextwatch

## Description



Adds an expression to be shown on context.

To remove an expression, see `cunwatch`.

## Usage:


```bash
usage: contextwatch [-h] [{eval,execute}] expression

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`cmd`|Command to be used with the expression. - eval: the expression is parsed and evaluated as in the debugged language. - execute: the expression is executed as a GDB command. (default: %(default)s)|
|`expression`|The expression to be evaluated and shown in context|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|

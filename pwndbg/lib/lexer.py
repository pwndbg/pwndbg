from __future__ import annotations

WHITESPACE = " \t\n\r\f\v"

# See libiberty/argv.c:buildargv() which backs


def lex_debugger_command(commandline: str) -> list[str]:
    """
    Lexes a command line (splits it into tokens (individual arguments)) to be passed to
    further argument parsing.

    gdb.string_to_argv() is unsuitable for this, because it strips single quotes i.e.
    it turns "dist 'A::foo(int, int)' 1" into ["dist", "A::foo(int, int)", "1"].

    The rules of this lex are:
    + Whitespace is only escaped inside '' and "", otherwise, whitespace denotes a new token
    + <backslash><some-character> means <some-character> inside '' and ""
    + Single quotes are kept, double quotes are stripped

    Examples:
    + cmd 1 2                         -> ['cmd', '1', '2']
    + cmd 'A::foo(int, int)' "1 + 1"  -> ['cmd', "'A::foo(int, int)'", '1 + 1']
    + cmd 'A::foo(int, int)'+3 ((int*)func())+4
                                      -> ['cmd', "'A::foo(int, int)'+3", '((int*)func())+4']
    + cmd 1+"1 + 1" &'a wa'+3         -> ['cmd', '1+1 + 1', "&'a wa'+3"]
    + cmd 'operator"" _km(unsigned int)'
                                      -> ['cmd', '\'operator"" _km(unsigned long long)\'']
    + cmd 'apply_twice(int)::'lambda'(int)::operator()(int) const' b
                                      -> ['cmd', "'apply_twice(int)::'lambda'(int)::operator()(int) const'", 'b']
    FIXME: ^^^ won't work for LLDB because the inner 'lambda' needs to be escaped

    See #4189 for more info on why we do this.

    Returns:
        A list of tokens to be given to argparse and parse_command_argument().
    """
    tokens: list[str] = []
    token: list[str] = []
    in_token = False
    quote: str | None = None

    i = 0
    while i < len(commandline):
        c = commandline[i]
        if quote == "'":
            # Add single quotes to the token because GDB handles them as
            # symbol names in expressions.
            token.append(c)
            if c == "\\" and i + 1 < len(commandline):
                # If we're in a quote \x means x
                i += 1
                token.append(commandline[i])
            elif c == "'":
                # End the quote
                quote = None
        elif quote == '"':
            if c == "\\" and i + 1 < len(commandline):
                # If we're in a quote \x means x
                i += 1
                token.append(commandline[i])
            elif c == '"':
                # End the quote
                quote = None
            else:
                # Double quotes are not added to the token which allows both
                # "1 + 1" to work as an argument (goes through expression evaluation)
                # and "my string" (because the underlying command should not get the
                # double quotes when it asks for a string argument).
                token.append(c)
        elif c in WHITESPACE:
            if in_token:
                # Terminate token
                tokens.append("".join(token))
                token = []
                in_token = False
        else:
            in_token = True
            if c in "'\"":
                # Start quote
                quote = c
            if c != '"':
                # Add to token if not double quote
                token.append(c)
        i += 1

    if in_token:
        tokens.append("".join(token))
    return tokens

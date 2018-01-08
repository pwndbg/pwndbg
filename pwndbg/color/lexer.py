from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import re

import six
from pygments.lexer import RegexLexer
from pygments.lexer import bygroups
from pygments.lexer import include
from pygments.token import Comment
from pygments.token import Name
from pygments.token import Number
from pygments.token import Operator
from pygments.token import Other
from pygments.token import Punctuation
from pygments.token import String
from pygments.token import Text

__all__ = ['PwntoolsLexer']

# Text        Token.Text            for any type of text data
# Whitespace  Token.Text.Whitespace for specially highlighted whitespace
# Error       Token.Error           represents lexer errors
# Other       Token.Other           special token for data not matched by a parser (e.g. HTML markup in PHP code)
# Keyword     Token.Keyword         any kind of keywords
# Name        Token.Name            variable/function names
# Literal     Token.Literal         Any literals
# String      Token.Literal.String  string literals
# Number      Token.Literal.Number  number literals
# Operator    Token.Operator        operators (+, not...)
# Punctuation Token.Punctuation     punctuation ([, (...)
# Comment     Token.Comment         any kind of comments
# Generic     Token.Generic         generic tokens (have a look at the explanation below)
class PwntoolsLexer(RegexLexer):
    """
    Fork foom pwntools
    https://github.com/Gallopsled/pwntools/blob/7860eecf025135380b137dd9df85dd02a2fd1667/pwnlib/lexer.py
    """
    name = 'PwntoolsLexer'
    filenames = ['*.s', '*.S', '*.asm']

    #: optional Comment or Whitespace
    string = r'"(\\"|[^"])*"'
    char = r'[\w$.@-]'
    identifier = r'(?:[a-zA-Z$_]' + char + '*|\.' + char + '+|or)'
    number = r'(?:0[xX][a-zA-Z0-9]+|\d+)'
    memory = r'(?:[\]\[])'
    bad = r'(?:\(bad\))'

    tokens = {
        'root': [
            include('whitespace'),
            (identifier + ':', Name.Label),
            (r'\.' + identifier, Name.Attribute, 'directive-args'),
            (r'lock|rep(n?z)?|data\d+', Name.Attribute),
            (identifier, Name.Function, 'instruction-args'),
            (r'[\r\n]+', Text),
            (bad, Text)
        ],

        'directive-args': [
            (identifier, Name.Constant),
            (string, String),
            ('@' + identifier, Name.Attribute),
            (number, Number.Integer),
            (r'[\r\n]+', Text, '#pop'),

            (r'#.*?$', Comment, '#pop'),

            include('punctuation'),
            include('whitespace')
        ],
        'instruction-args': [
            # For objdump-disassembled code, shouldn't occur in
            # actual assembler input
            ('([a-z0-9]+)( )(<)('+identifier+')(>)',
                bygroups(Number.Hex, Text, Punctuation, Name.Constant,
                         Punctuation)),
            ('([a-z0-9]+)( )(<)('+identifier+')([-+])('+number+')(>)',
                bygroups(Number.Hex, Text, Punctuation, Name.Constant,
                         Punctuation, Number.Integer, Punctuation)),

            # Fun things
            (r'([\]\[]|BYTE|DWORD|PTR|\+|\-|}|{|\^|>>|<<|&)', Text),

            # Address constants
            (identifier, Name.Constant),
            (number, Number.Integer),
            # Registers
            ('%' + identifier, Name.Variable),
            ('$' + identifier, Name.Variable),
            # Numeric constants
            ('$'+number, Number.Integer),
            ('#'+number, Number.Integer),
            (r"$'(.|\\')'", String.Char),
            (r'[\r\n]+', Text, '#pop'),
            include('punctuation'),
            include('whitespace')
        ],
        'whitespace': [
            (r'\n', Text),
            (r'\s+', Text),
            (r'/\*.*?\*/', Comment),
            (r';.*$', Comment)
        ],
        'punctuation': [
            (r'[-*,.():]+', Punctuation)
        ]
    }

    def analyse_text(text):
        if re.match(r'^\.(text|data|section)', text, re.M):
            return True
        elif re.match(r'^\.\w+', text, re.M):
            return 0.1

if six.PY2:
    # XXX: convert all unicode() to str() if in Python2.7 since unicode_literals is enabled
    #   The pygments<=2.2.0 (lastest stable when commit) in Python2.7 use 'str' type in rules matching
    #   We must convert all unicode back to str()
    def _to_str(obj):
        typ = type(obj)
        if typ is tuple:
            return tuple(map(_to_str, obj))
        elif typ is list:
            return map(_to_str, obj)
        elif typ is unicode:
            return str(obj)
        return obj

    PwntoolsLexer.tokens = {
        _to_str(k): _to_str(v)
        for k, v in PwntoolsLexer.tokens.iteritems()
    }

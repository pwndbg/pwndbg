# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import re

import six
from pygments.lexer import RegexLexer
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

class PwntoolsLexer(RegexLexer):
    """
    Fork from pwntools
    https://github.com/Gallopsled/pwntools/blob/7860eecf025135380b137dd9df85dd02a2fd1667/pwnlib/lexer.py

    Edit:
        * Remove Objdump rules
        * Merge pygments-arm (https://github.com/heia-fr/pygments-arm)
    """
    name = 'PwntoolsLexer'
    filenames = ['*.s', '*.S', '*.asm']

    #: optional Comment or Whitespace
    string = r'"(\\"|[^"])*"'
    char = r'[\w$.@-]'
    identifier = r'(?:[a-zA-Z$_]' + char + '*|\.' + char + '+|or)'
    number = r'(?:0[xX][a-zA-Z0-9]+|\d+)'
    memory = r'(?:[\]\[])'

    eol = r'[\r\n]+'

    tokens = {
        'root': [
            include('whitespace'),

            # Label
            (identifier + ':', Name.Label),
            (number + ':', Name.Label),

            # AT&T directive
            (r'\.' + identifier, Name.Attribute, 'directive-args'),
            (r'lock|rep(n?z)?|data\d+', Name.Attribute),

            # Instructions
            (identifier, Name.Function, 'instruction-args'),

            (r'[\r\n]+', Text),
        ],
        'directive-args': [
            (identifier, Name.Constant),
            (string, String),
            ('@' + identifier, Name.Attribute),
            (number, Number.Integer),

            (eol, Text, '#pop'),
            (r'#.*?$', Comment, '#pop'),

            include('punctuation'),
            include('whitespace')
        ],
        'instruction-args': [
            # Fun things
            (r'([\]\[]|BYTE|DWORD|PTR|\+|\-|}|{|\^|>>|<<|&)', Text),

            # Address constants
            (identifier, Name.Constant),
            ('=' + identifier, Name.Constant), # ARM symbol
            (number, Number.Integer),

            # Registers
            ('%' + identifier, Name.Variable),
            ('$' + identifier, Name.Variable),

            # Numeric constants
            ('$' + number, Number.Integer),
            ('#' + number, Number.Integer),

            # ARM predefined constants
            ('#' + identifier, Name.Constant),

            (r"$'(.|\\')'", String.Char),

            (eol, Text, '#pop'),

            include('punctuation'),
            include('whitespace')
        ],
        'whitespace': [
            (r'\n', Text),
            (r'\s+', Text),

            # Block comments
            # /* */ (AT&T)
            (r'/\*.*?\*/', Comment),

            # Line comments
            # //    (AArch64)
            # #     (AT&T)
            # ;     (NASM/intel, LLVM)
            # @     (ARM)
            (r'(//|[#;@]).*$', Comment.Single)
        ],
        'punctuation': [
            (r'[-*,.():]+', Punctuation)
        ]
    }

# Note: convert all unicode() to str() if in Python2.7 since unicode_literals is enabled
# The pygments<=2.2.0 (latest stable when commit) in Python2.7 use 'str' type in rules matching
# We must convert all unicode back to str()
if six.PY2:
    def _to_str(obj):
        type_ = type(obj)
        if type_ in (tuple, list):
            return type_(map(_to_str, obj))
        elif type_ is unicode:
            return str(obj)
        return obj

    PwntoolsLexer.tokens = {
        _to_str(k): _to_str(v)
        for k, v in PwntoolsLexer.tokens.iteritems()
    }

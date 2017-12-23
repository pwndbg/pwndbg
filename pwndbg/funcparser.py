#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import collections

from pycparser import CParser
from pycparser import c_ast


def extract_type_and_name(n, defaultName=None):
    if isinstance(n, c_ast.EllipsisParam):
        return 'int', 0, 'vararg'

    t = n.type
    d = 0

    while isinstance(t, (c_ast.PtrDecl, c_ast.ArrayDecl)):
        d += 1
        children = dict(t.children())
        t = children['type']

    if isinstance(t, c_ast.FuncDecl):
        return extract_type_and_name(t)

    if isinstance(t.type, (c_ast.Struct, c_ast.Union, c_ast.Enum)):
        typename = t.type.name
    else:
        typename = t.type.names[0]

    if typename == 'void' and d == 0 and not t.declname:
        return None

    name = t.declname or defaultName or ''

    return typename.lstrip('_'), d, name.lstrip('_')

Function = collections.namedtuple('Function', ('type', 'derefcnt', 'name', 'args'))
Argument = collections.namedtuple('Argument', ('type', 'derefcnt', 'name'))


def stringify(X):
    return '%s %s %s' % (X.type, X.derefcnt * '*', X.name)


def extract_func_decl(node, verbose=False):
    # The function name needs to be dereferenced.
    ftype, fderef, fname = extract_type_and_name(node)

    if not fname:
        print("Skipping function without a name!")
        print(node.show())
        return

    fargs = []
    for i, (argName, arg) in enumerate(node.args.children()):
        defname = 'arg%i' % i
        argdata = extract_type_and_name(arg, defname)
        if argdata is not None:
            a = Argument(*argdata)
            fargs.append(a)

    Func = Function(ftype, fderef, fname, fargs)

    if verbose:
        print(stringify(Func) + '(' + ','.join(stringify(a) for a in Func.args) + ');')

    return Func


def extract_all_func_decls(ast, verbose=False):
    Functions = {}

    class FuncDefVisitor(c_ast.NodeVisitor):
        def visit_FuncDecl(self, node, *a):
            f = extract_func_decl(node, verbose)
            Functions[f.name] = f

    FuncDefVisitor().visit(ast)

    return Functions


def extract_func_decl_from_source(source):
    try:
        p     = CParser()
        ast   = p.parse(source + ';')
        funcs = extract_all_func_decls(ast)
        for name, func in funcs.items():
            return func
    except Exception as e:
        import traceback
        traceback.print_exc()
        # eat it

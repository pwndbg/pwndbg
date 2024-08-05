from __future__ import annotations

from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union

from pycparser import CParser  # type: ignore # noqa: PGH003
from pycparser import c_ast

from pwndbg.lib.functions import Argument
from pwndbg.lib.functions import Function

CAstNode = Union[
    c_ast.EllipsisParam,
    c_ast.PtrDecl,
    c_ast.ArrayDecl,
    c_ast.FuncDecl,
    c_ast.Struct,
    c_ast.Union,
    c_ast.Enum,
]


def extractTypeAndName(
    n: CAstNode, defaultName: Optional[str] = None
) -> Optional[Tuple[str, int, str]]:
    if isinstance(n, c_ast.EllipsisParam):
        return ("int", 0, "vararg")

    t = n.type
    d = 0

    while isinstance(t, (c_ast.PtrDecl, c_ast.ArrayDecl)):
        d += 1
        children = dict(t.children())
        t = children["type"]

    if isinstance(t, c_ast.FuncDecl):
        return extractTypeAndName(t)

    if isinstance(t.type, (c_ast.Struct, c_ast.Union, c_ast.Enum)):
        typename = t.type.name
    else:
        typename = t.type.names[0]

    if typename == "void" and d == 0 and not t.declname:
        return None

    name = t.declname or defaultName or ""
    return typename.lstrip("_"), d, name.lstrip("_")


def Stringify(X: Function | Argument) -> str:
    return f"{X.type} {X.derefcnt * '*'} {X.name}"


def ExtractFuncDecl(node: CAstNode, verbose: bool = False) -> Function | None:
    # The function name needs to be dereferenced.
    result = extractTypeAndName(node)
    if result is None:
        return None

    ftype, fderef, fname = result

    if not fname:
        print("Skipping function without a name!")
        print(node.show())
        return None

    fargs: List[Argument] = []
    for i, (argName, arg) in enumerate(node.args.children()):
        defname = "arg%i" % i
        argdata = extractTypeAndName(arg, defname)
        if argdata is not None:
            a = Argument(*argdata)
            fargs.append(a)

    Func = Function(ftype, fderef, fname, fargs)

    if verbose:
        print(Stringify(Func) + "(" + ",".join(Stringify(a) for a in Func.args) + ");")

    return Func


def ExtractAllFuncDecls(ast: CAstNode, verbose: bool = False):
    Functions: Dict[str, Function] = {}

    class FuncDefVisitor(c_ast.NodeVisitor):
        def visit_FuncDecl(self, node: CAstNode, *a: Any) -> None:
            f = ExtractFuncDecl(node, verbose)
            Functions[f.name] = f

    FuncDefVisitor().visit(ast)

    return Functions


def ExtractFuncDeclFromSource(source: str) -> Function | None:
    try:
        p = CParser()
        ast: CAstNode = p.parse(source + ";")
        funcs = ExtractAllFuncDecls(ast)
        for name, func in funcs.items():
            return func
    except Exception:
        import traceback

        traceback.print_exc()
        # eat it
    return None

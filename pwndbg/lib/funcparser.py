import collections

from pycparser import CParser  # type: ignore
from pycparser import c_ast


def extractTypeAndName(n, defaultName=None):
    if isinstance(n, c_ast.EllipsisParam):
        return ("int", 0, "vararg")

    t = n.type
    d = 0

    while isinstance(t, c_ast.PtrDecl) or isinstance(t, c_ast.ArrayDecl):
        d += 1
        children = dict(t.children())
        t = children["type"]

    if isinstance(t, c_ast.FuncDecl):
        return extractTypeAndName(t)

    if (
        isinstance(t.type, c_ast.Struct)
        or isinstance(t.type, c_ast.Union)
        or isinstance(t.type, c_ast.Enum)
    ):
        typename = t.type.name
    else:
        typename = t.type.names[0]

    if typename == "void" and d == 0 and not t.declname:
        return None

    name = t.declname or defaultName or ""
    return typename.lstrip("_"), d, name.lstrip("_")


Function = collections.namedtuple("Function", ("type", "derefcnt", "name", "args"))
Argument = collections.namedtuple("Argument", ("type", "derefcnt", "name"))


def Stringify(X):
    return "%s %s %s" % (X.type, X.derefcnt * "*", X.name)


def ExtractFuncDecl(node, verbose=False):
    # The function name needs to be dereferenced.
    ftype, fderef, fname = extractTypeAndName(node)

    if not fname:
        print("Skipping function without a name!")
        print(node.show())
        return

    fargs = []
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


def ExtractAllFuncDecls(ast, verbose=False):
    Functions = {}

    class FuncDefVisitor(c_ast.NodeVisitor):
        def visit_FuncDecl(self, node, *a):
            f = ExtractFuncDecl(node, verbose)
            Functions[f.name] = f

    FuncDefVisitor().visit(ast)

    return Functions


def ExtractFuncDeclFromSource(source):
    try:
        p = CParser()
        ast = p.parse(source + ";")
        funcs = ExtractAllFuncDecls(ast)
        for name, func in funcs.items():
            return func
    except Exception as e:
        import traceback

        traceback.print_exc()
        # eat it

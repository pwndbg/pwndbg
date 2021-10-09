# This mocks the GDB module for test generation
import types as _types

ARCH_FRAME = 5
class Architecture: pass
BP_ACCESS_WATCHPOINT = 9
BP_BREAKPOINT = 1
BP_HARDWARE_WATCHPOINT = 7
BP_NONE = 0
BP_READ_WATCHPOINT = 8
BP_WATCHPOINT = 6
class Block: pass
class BlockIterator: pass
class Breakpoint: pass
class BreakpointEvent: pass
COMMAND_BREAKPOINTS = 6
COMMAND_DATA = 1
COMMAND_FILES = 3
COMMAND_MAINTENANCE = 11
COMMAND_NONE = -1
COMMAND_OBSCURE = 10
COMMAND_RUNNING = 0
COMMAND_STACK = 2
COMMAND_STATUS = 5
COMMAND_SUPPORT = 4
COMMAND_TRACEPOINTS = 7
COMMAND_USER = 14
COMPLETE_COMMAND = 3
COMPLETE_EXPRESSION = 5
COMPLETE_FILENAME = 1
COMPLETE_LOCATION = 2
COMPLETE_NONE = 0
COMPLETE_SYMBOL = 4
class ClearObjFilesEvent: pass
class Command: pass
class ContinueEvent: pass
DUMMY_FRAME = 1
class Event: pass
class EventRegistry: pass
class ExitedEvent: pass
FRAME_UNWIND_INNER_ID = 4
FRAME_UNWIND_MEMORY_ERROR = 7
FRAME_UNWIND_NO_REASON = 0
FRAME_UNWIND_NO_SAVED_PC = 6
FRAME_UNWIND_NULL_ID = 1
FRAME_UNWIND_OUTERMOST = 2
FRAME_UNWIND_SAME_ID = 5
FRAME_UNWIND_UNAVAILABLE = 3
class Field: pass
class FinishBreakpoint: pass
class Frame: pass
FrameDecorator = object() # module 'gdb.FrameDecorator' from '/usr/local/Cellar/gdb/7.12_1/share/gdb/python/gdb/FrameDecorator.pyc'>
FrameIterator = object() # module 'gdb.FrameIterator' from '/usr/local/Cellar/gdb/7.12_1/share/gdb/python/gdb/FrameIterator.pyc'>
class Function: pass
class GdbError: pass
class GdbOutputErrorFile: pass
class GdbOutputFile: pass
def GdbSetPythonDirectory(*a, **kw): pass
HOST_CONFIG = 'x86_64-apple-darwin16.3.0'
INLINE_FRAME = 2
class Inferior: pass
class InferiorCallPostEvent: pass
class InferiorCallPreEvent: pass
class InferiorThread: pass
class LineTable: pass
class LineTableEntry: pass
class LineTableIterator: pass
class Membuf: pass
class MemoryChangedEvent: pass
class MemoryError: pass
NORMAL_FRAME = 0
class NewObjFileEvent: pass
class Objfile: pass
PARAM_AUTO_BOOLEAN = 1
PARAM_BOOLEAN = 0
PARAM_ENUM = 11
PARAM_FILENAME = 7
PARAM_INTEGER = 3
PARAM_OPTIONAL_FILENAME = 6
PARAM_STRING = 4
PARAM_STRING_NOESCAPE = 5
PARAM_UINTEGER = 2
PARAM_ZINTEGER = 8
PYTHONDIR = '/usr/local/Cellar/gdb/7.12_1/share/gdb/python'
class Parameter: pass
class PendingFrame: pass
class Progspace: pass
class RegisterChangedEvent: pass
SENTINEL_FRAME = 6
SIGTRAMP_FRAME = 4
STDERR = 1
STDLOG = 2
STDOUT = 0
SYMBOL_FUNCTIONS_DOMAIN = 1
SYMBOL_LABEL_DOMAIN = 4
SYMBOL_LOC_ARG = 4
SYMBOL_LOC_BLOCK = 10
SYMBOL_LOC_COMPUTED = 14
SYMBOL_LOC_CONST = 1
SYMBOL_LOC_CONST_BYTES = 11
SYMBOL_LOC_LABEL = 9
SYMBOL_LOC_LOCAL = 7
SYMBOL_LOC_OPTIMIZED_OUT = 13
SYMBOL_LOC_REF_ARG = 5
SYMBOL_LOC_REGISTER = 3
SYMBOL_LOC_REGPARM_ADDR = 6
SYMBOL_LOC_STATIC = 2
SYMBOL_LOC_TYPEDEF = 8
SYMBOL_LOC_UNDEF = 0
SYMBOL_LOC_UNRESOLVED = 12
SYMBOL_STRUCT_DOMAIN = 2
SYMBOL_TYPES_DOMAIN = 2
SYMBOL_UNDEF_DOMAIN = 0
SYMBOL_VARIABLES_DOMAIN = 0
SYMBOL_VAR_DOMAIN = 1
class SignalEvent: pass
class StopEvent: pass
class Symbol: pass
class Symtab: pass
class Symtab_and_line: pass
TAILCALL_FRAME = 3
TARGET_CONFIG = 'x86_64-apple-darwin16.3.0'
TYPE_CODE_ARRAY = 2
TYPE_CODE_BITSTRING = -1
TYPE_CODE_BOOL = 20
TYPE_CODE_CHAR = 19
TYPE_CODE_COMPLEX = 21
TYPE_CODE_DECFLOAT = 24
TYPE_CODE_ENUM = 5
TYPE_CODE_ERROR = 14
TYPE_CODE_FLAGS = 6
TYPE_CODE_FLT = 9
TYPE_CODE_FUNC = 7
TYPE_CODE_INT = 8
TYPE_CODE_INTERNAL_FUNCTION = 26
TYPE_CODE_MEMBERPTR = 17
TYPE_CODE_METHOD = 15
TYPE_CODE_METHODPTR = 16
TYPE_CODE_NAMESPACE = 23
TYPE_CODE_PTR = 1
TYPE_CODE_RANGE = 12
TYPE_CODE_REF = 18
TYPE_CODE_SET = 11
TYPE_CODE_STRING = 13
TYPE_CODE_STRUCT = 3
TYPE_CODE_TYPEDEF = 22
TYPE_CODE_UNION = 4
TYPE_CODE_VOID = 10
class ThreadEvent: pass
class Type: pass
class TypeIterator: pass
class UnwindInfo: pass
VERSION = '7.12'
class Value: pass
WP_ACCESS = 2
WP_READ = 1
WP_WRITE = 0
class _GdbFile: pass
__doc__ = None
__file__ = '/usr/local/Cellar/gdb/7.12_1/share/gdb/python/gdb/__init__.pyc'
__name__ = 'gdb'
__package__ = 'gdb'
__path__ = ['/usr/local/Cellar/gdb/7.12_1/share/gdb/python/gdb']
def auto_load_packages(*a, **kw): pass
command = object() # module 'gdb.command' from '/usr/local/Cellar/gdb/7.12_1/share/gdb/python/gdb/command/__init__.pyc'>
class error: pass
def execute_unwinders(*a, **kw): pass
frame_filters = {}
frame_unwinders = []
frames = object() # module 'gdb.frames' from '/usr/local/Cellar/gdb/7.12_1/share/gdb/python/gdb/frames.pyc'>
function = object() # module 'gdb.function' from '/usr/local/Cellar/gdb/7.12_1/share/gdb/python/gdb/function/__init__.pyc'>
os = object() # module 'os' from '/System/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/os.pyc'>
printer = object() # module 'gdb.printer' from '/usr/local/Cellar/gdb/7.12_1/share/gdb/python/gdb/printer/__init__.pyc'>
printing = object() # module 'gdb.printing' from '/usr/local/Cellar/gdb/7.12_1/share/gdb/python/gdb/printing.pyc'>
prompt = object() # module 'gdb.prompt' from '/usr/local/Cellar/gdb/7.12_1/share/gdb/python/gdb/prompt.pyc'>
def prompt_hook(*a, **kw): pass
traceback = object() # module 'traceback' from '/System/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/traceback.pyc'>
type_printers = []
types = object() # module 'gdb.types' from '/usr/local/Cellar/gdb/7.12_1/share/gdb/python/gdb/types.pyc'>


# ===================================
class Command:
    def __init__(self, *a, **kw):
        pass
class Parameter:
    def __init__(self, *a, **kw):
        pass
class _event:
    def connect(*a, **kw): pass
class _events(_types.ModuleType):
    exited = _event()
    cont = _event()
    new_objfile = _event()
    stop = _event()
events = _events('events')

class _type():
    sizeof = 4
    def pointer(*a, **kw): return _type()
def lookup_type(*a, **kw): return _type()

class Value:
    def __init__(*a, **kw): pass
    def cast(*a, **kw): return Value()

def execute(*a, **kw): return ''

class Function:
    def __init__(*a, **kw): pass

def selected_inferior(): pass
def selected_thread(): pass

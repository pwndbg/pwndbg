from ctypes import *


class _DEBUG_TYPED_DATA(Structure):
    # Describes typed data in the memory of the target.
    # https://github.com/MicrosoftDocs/windows-driver-docs-ddi/blob/b3e1ec3d46d4231c7b1c514f27507e461a6b3b4d/wdk-ddi-src/content/wdbgexts/ns-wdbgexts-_debug_typed_data.md
    _fields_ = [
        ("ModBase", c_ulonglong),
        ("Offset", c_ulonglong),
        ("EngineHandle", c_ulonglong),
        ("Data", c_ulonglong),
        ("Size", c_ulong),
        ("Flags", c_ulong),
        ("TypeId", c_ulong),
        ("BaseTypeId", c_ulong),
        ("Tag", c_ulong),
        ("Register", c_ulong),
        ("Internal", c_ulonglong * 9),
    ]

assert sizeof(_DEBUG_TYPED_DATA) == 128


class _EXT_TYPED_DATA(Structure):
    # Describes the input and output parameters for the Request operation.
    # https://github.com/MicrosoftDocs/windows-driver-docs-ddi/blob/b3e1ec3d46d4231c7b1c514f27507e461a6b3b4d/wdk-ddi-src/content/wdbgexts/ns-wdbgexts-_ext_typed_data.md
    _fields_ = [
        ("Operation", c_ulong),
        ("Flags", c_ulong),
        ("InData", _DEBUG_TYPED_DATA),
        ("OutData", _DEBUG_TYPED_DATA),
        ("InStrIndex", c_ulong),
        ("In32", c_ulong),
        ("Out32", c_ulong),
        ("In64", c_ulonglong),
        ("Out64", c_ulonglong),
        ("StrBufferIndex", c_ulong),
        ("StrBufferChars", c_ulong),
        ("StrCharsNeeded", c_ulong),
        ("DataBufferIndex", c_ulong),
        ("DataBufferBytes", c_ulong),
        ("DataBytesNeeded", c_ulong),
        ("Status", c_ulong),
        ("Reserved", c_ulonglong * 8),
    ]

assert sizeof(_EXT_TYPED_DATA) == 392

import ctypes


oleaut32 = ctypes.OleDLL("oleaut32.dll")


def bstr_to_str(bstr) -> str:
    length = oleaut32.SysStringLen(bstr)
    return ctypes.wstring_at(bstr, length)

def free_bstr(bstr) -> None:
    oleaut32.SysFreeString(bstr)

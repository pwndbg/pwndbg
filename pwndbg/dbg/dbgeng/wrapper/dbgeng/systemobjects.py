from ctypes import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _Pointer

import comtypes.gen.DbgEng as DbgEng


class DebugSystemObjects:
    def __init__(self, inner: "_Pointer[DbgEng.IDebugSystemObjects]"):
        self.inner = inner

    def GetProcessIdBySystemId(self, system_id: int) -> int | None:
        pid = c_ulong()
        self.inner.GetProcessIdBySystemId(system_id, byref(pid))
        return pid.value

    def GetCurrentThreadId(self) -> int:
        tid = c_ulong()
        self.inner.GetCurrentThreadId(byref(tid))
        return tid.value

    def SetCurrentThreadId(self, thread_id: int) -> None:
        self.inner.SetCurrentThreadId(thread_id)

    def GetCurrentProcessId(self) -> int:
        pid = c_ulong()
        self.inner.GetCurrentProcessId(byref(pid))
        return pid.value

    def SetCurrentProcessId(self, process_id: int) -> None:
        self.inner.SetCurrentProcessId(process_id)
    
    def GetCurrentProcessSystemId(self) -> int:
        sys_id = c_ulong()
        self.inner.GetCurrentProcessSystemId(byref(sys_id))
        return sys_id.value

    def GetNumberProcesses(self) -> int:
        number = c_ulong()
        self.inner.GetNumberProcesses(byref(number))
        return number.value

    def GetNumberThreads(self) -> int:
        number = c_ulong()
        self.inner.GetNumberThreads(byref(number))
        return number.value

    def GetProcessIdsByIndex(self) -> tuple[list[int], list[int]]:
        count = self.GetNumberProcesses()
        ids = (c_ulong * count)()
        sys_ids = (c_ulong * count)()
        self.inner.GetProcessIdsByIndex(0, count, byref(ids), byref(sys_ids))
        return [ids[i] for i in range(count)], [sys_ids[i] for i in range(count)]

    def GetThreadIdsByIndex(self, start=0, count=None) -> tuple[list[int], list[int]]:
        if count is None:
            count = self.GetNumberThreads()
        ids = (c_ulong * count)()
        sys_ids = (c_ulong * count)()
        self.inner.GetThreadIdsByIndex(start, count, byref(ids), byref(sys_ids))
        return [ids[i] for i in range(count)], [sys_ids[i] for i in range(count)]

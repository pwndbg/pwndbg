from typing import Callable, Dict, List, TypeVar

from comtypes import COMObject
from comtypes.hresult import S_OK, E_NOINTERFACE

from pwndbg.dbg_mod import EventType, EventHandlerPriority
from pwndbg.dbg_mod.dbgeng.wrapper.dbgeng import DbgEng as COM_DbgEng

T = TypeVar("T")


class EventCallback(COMObject):
    _com_interfaces_ = [COM_DbgEng.IDebugEventCallbacks]

    # Event handlers and the list of suspended events are maintained here
    event_handlers: Dict[EventType, Dict[EventHandlerPriority, List[Callable[..., T]]]]
    suspended_events: set[EventType]

    def __init__(self):
        super().__init__()
        self.event_handlers = {}
        self.suspended_events = set()

    def _register_event(self, event: EventType, priority: EventHandlerPriority, handler: Callable[..., T]) -> None:
        if event not in self.event_handlers:
            self.event_handlers[event] = {}
        if priority not in self.event_handlers[event]:
            self.event_handlers[event][priority] = []

        self.event_handlers[event][priority].append(handler)
    
    def _trigger_event(self, event: EventType):
        if event in self.event_handlers and event not in self.suspended_events and EventType.SUSPEND_ALL not in self.suspended_events:
            for priority in EventHandlerPriority:
                if priority in self.event_handlers[event]:
                    for handler in self.event_handlers[event][priority]:
                        handler()

    def IUnknown_QueryInterface(self, this, riid, ppvObject):
        return E_NOINTERFACE

    def IUnknown_AddRef(self, this):
        return 1

    def IUnknown_Release(self, this):
        return 0

    def IDebugEventCallbacks_Breakpoint(self, this, bp):
        return S_OK

    def IDebugEventCallbacks_ChangeDebuggeeState(self, this, flags, argument):
        if flags == COM_DbgEng.DEBUG_CDS_REGISTERS:
            self._trigger_event(EventType.REGISTER_CHANGED)
        if flags == COM_DbgEng.DEBUG_CDS_DATA:
            self._trigger_event(EventType.MEMORY_CHANGED)
        return S_OK


    def IDebugEventCallbacks_ChangeEngineState(self, this, flags, argument):
        if flags == COM_DbgEng.DEBUG_CES_EXECUTION_STATUS:
            if argument == COM_DbgEng.DEBUG_STATUS_BREAK:
                self._trigger_event(EventType.STOP)
            if argument in (COM_DbgEng.DEBUG_STATUS_STEP_INTO,
                            COM_DbgEng.DEBUG_STATUS_STEP_BRANCH,
                            COM_DbgEng.DEBUG_STATUS_STEP_OVER,
                            COM_DbgEng.DEBUG_STATUS_GO):
                self._trigger_event(EventType.CONTINUE)
        return S_OK

    def IDebugEventCallbacks_ChangeSymbolState(self, this, flags, argument):
        return S_OK

    def IDebugEventCallbacks_CreateProcess(self, this, image_file_handle, handle, base_offset, module_size, module_name, image_name, check_sum, time_date_stamp, initial_thread_handle, thread_data_offset, start_offset):
        self._trigger_event(EventType.START)
        return S_OK

    def IDebugEventCallbacks_CreateThread(self, this, handle, data_offset, start_offset):
        return S_OK

    def IDebugEventCallbacks_Exception(self, this, exception, first_chance):
        return S_OK

    def IDebugEventCallbacks_ExitProcess(self, this, exit_code):
        self._trigger_event(EventType.EXIT)
        return S_OK

    def IDebugEventCallbacks_ExitThread(self, this, exit_code):
        return S_OK

    def IDebugEventCallbacks_GetInterestMask(self, this, mask):
        mask.contents.value = (COM_DbgEng.DEBUG_EVENT_CHANGE_DEBUGGEE_STATE
                               | COM_DbgEng.DEBUG_EVENT_CHANGE_ENGINE_STATE
                               | COM_DbgEng.DEBUG_EVENT_CREATE_PROCESS
                               | COM_DbgEng.DEBUG_EVENT_EXIT_PROCESS
                               | COM_DbgEng.DEBUG_EVENT_LOAD_MODULE)
        return S_OK

    def IDebugEventCallbacks_LoadModule(self, this, image_file_handle, base_offset, module_size, module_name, image_name, check_sum, time_date_stamp):
        self._trigger_event(EventType.NEW_MODULE)
        return S_OK

    def IDebugEventCallbacks_SessionStatus(self, this, status):
        return S_OK

    def IDebugEventCallbacks_SystemError(self, this, error, level):
        return S_OK

    def IDebugEventCallbacks_UnloadModule(self, this, image_base_name, base_offset):
        return S_OK

from ctypes import *
from typing import TYPE_CHECKING, Optional

from pwndbg.dbg_mod.dbgeng.wrapper.dbgmodel.debughostcontext import DebugHostContext
from pwndbg.dbg_mod.dbgeng.wrapper.dbgmodel.debughosttype import DebugHostType
from pwndbg.dbg_mod.dbgeng.wrapper.dbgmodel.keystore import KeyStore
from pwndbg.dbg_mod.dbgeng.wrapper.constants import E_BOUNDS

if TYPE_CHECKING:
    from ctypes import _Pointer

from comtypes import COMError, BSTR
from comtypes.automation import VARIANT, VARTYPE
import comtypes.gen.DbgMod as DbgModel


class KeyEnumerator:
    def __init__(self, inner: "_Pointer[DbgModel.IKeyEnumerator]"):
        self.inner = inner
    
    def GetNext(self) -> Optional[tuple[str, "ModelObject", KeyStore]]:
        key = BSTR()
        value = POINTER(DbgModel.IModelObject)()
        metadata = POINTER(DbgModel.IKeyStore)()
        try:
            self.inner.GetNext(byref(key), byref(value), byref(metadata))
            return key.value, ModelObject(value), KeyStore(metadata)
        except COMError as e:
            if e.hresult == E_BOUNDS:
                return None
            raise


class ModelIterator:
    def __init__(self, inner: "_Pointer[DbgModel.IModelIterator]"):
        self.inner = inner

    def GetNext(self) -> Optional["ModelObject"]:
        obj = POINTER(DbgModel.IModelObject)()
        try:
            self.inner.GetNext(byref(obj), 0, None, None)
            return ModelObject(obj)
        except COMError as e:
            if e.hresult == E_BOUNDS:
                return None
            raise


class IterableConcept:
    def __init__(self, inner: "_Pointer[DbgModel.IIterableConcept]"):
        self.inner = inner

    def GetIterator(self, context: "ModelObject") -> ModelIterator:
        iterator = POINTER(DbgModel.IModelIterator)()
        self.inner.GetIterator(context.inner, byref(iterator))
        return ModelIterator(iterator)


class IndexableConcept:
    def __init__(self, inner: "_Pointer[DbgModel.IIndexableConcept]"):
        self.inner = inner

    def GetAt(self, context: "ModelObject", indexers: list["ModelObject"]) -> Optional[tuple["ModelObject", KeyStore]]:
        object = POINTER(DbgModel.IModelObject)()
        meta = POINTER(DbgModel.IKeyStore)()
        indexer_arr = (POINTER(DbgModel.IModelObject) * len(indexers))(*map(lambda o: o.inner, indexers))
        try:
            self.inner.GetAt(context.inner, len(indexers), indexer_arr, byref(object), byref(meta))
            return ModelObject(object), KeyStore(meta)
        except COMError as e:
            if e.hresult == E_BOUNDS:
                return None
            raise e


class ModelObject:
    def __init__(self, inner: "_Pointer[DbgModel.IModelObject]"):
        self.inner = inner

    def IndexableConcept(self) -> tuple[IndexableConcept, KeyStore]:
        concept = POINTER(DbgModel.IIndexableConcept)()
        meta = POINTER(DbgModel.IKeyStore)()
        self.inner.GetConcept(byref(DbgModel.IIndexableConcept._iid_), byref(concept), byref(meta))
        return IndexableConcept(concept), KeyStore(meta)

    def IterableConcept(self) -> tuple[IterableConcept, KeyStore]:
        concept = POINTER(DbgModel.IIterableConcept)()
        meta = POINTER(DbgModel.IKeyStore)()
        self.inner.GetConcept(byref(DbgModel.IIterableConcept._iid_), byref(concept), byref(meta))
        return IterableConcept(concept), KeyStore(meta)

    def GetTypeInfo(self) -> Optional[DebugHostType]:
        type_info = POINTER(DbgModel.IDebugHostType)()
        self.inner.GetTypeInfo(byref(type_info))
        if not type_info:
            return None
        return DebugHostType(type_info)

    def GetKeyValue(self, key: str) -> Optional[tuple["ModelObject", KeyStore]]:
        buffer = create_unicode_buffer(key)
        value = POINTER(DbgModel.IModelObject)()
        metadata = POINTER(DbgModel.IKeyStore)()
        try:
            self.inner.GetKeyValue(cast(buffer, POINTER(c_ushort)), byref(value), byref(metadata))
            return ModelObject(value), KeyStore(metadata)
        except COMError as e:
            if e.hresult == E_BOUNDS:
                return None
            raise e

    def GetIntrinsicValue(self) -> VARIANT:
        variant = VARIANT()
        self.inner.GetIntrinsicValue(byref(variant))
        return variant

    def GetIntrinsicValueAs(self, vt: VARTYPE) -> VARIANT:
        variant = VARIANT()
        self.inner.GetIntrinsicValueAs(vt, byref(variant))
        return variant

    def EnumerateKeyValues(self) -> KeyEnumerator:
        enumerator = POINTER(DbgModel.IKeyEnumerator)()
        self.inner.EnumerateKeyValues(byref(enumerator))
        return KeyEnumerator(enumerator)

    def GetContext(self) -> DebugHostContext:
        context = POINTER(DbgModel.IDebugHostContext)()
        self.inner.GetContext(byref(context))
        return DebugHostContext(context)

    def GetLocation(self) -> DbgModel._Location:
        location = DbgModel._Location()
        self.inner.GetLocation(byref(location))
        return DbgModel._Location

    def GetKind(self) -> DbgModel.ModelObjectKind:
        kind = DbgModel.ModelObjectKind()
        self.inner.GetKind(byref(kind))
        return kind

    def GetRawReference(self, kind: int, name: str, flags: int = 0) -> "ModelObject":
        buffer = create_unicode_buffer(name)
        obj = POINTER(DbgModel.IModelObject)()
        self.inner.GetRawReference(kind, cast(buffer, POINTER(c_ushort)), flags, byref(obj))
        return ModelObject(obj)

    def GetRawValue(self, kind: int, name: str, flags: int = 0) -> "ModelObject":
        buffer = create_unicode_buffer(name)
        obj = POINTER(DbgModel.IModelObject)()
        self.inner.GetRawValue(kind, cast(buffer, POINTER(c_ushort)), flags, byref(obj))
        return obj

    def Dereference(self) -> "ModelObject":
        obj = POINTER(DbgModel.IModelObject)()
        self.inner.Dereference(byref(obj))
        return ModelObject(obj)

from __future__ import annotations

import functools
from typing import Iterator
from typing import List
from typing import Optional

import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo
import pwndbg.dbg
from pwndbg.aglib.kernel.macros import container_of
from pwndbg.aglib.kernel.macros import for_each_entry

NFPROTO_INET = 1
NFPROTO_IPV4 = 2
NFPROTO_ARP = 3
NFPROTO_NETDEV = 5
NFPROTO_BRIDGE = 7
NFPROTO_IPV6 = 10

nftables_table_family = {
    "inet": NFPROTO_INET,
    "ip": NFPROTO_IPV4,
    "arp": NFPROTO_ARP,
    "netdev": NFPROTO_NETDEV,
    "bridge": NFPROTO_BRIDGE,
    "ip6": NFPROTO_IPV6,
}


def catch_error(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (pwndbg.dbg_mod.Error, UnicodeDecodeError) as e:
            return f"<unavailable: {e}>"

    return wrapper


class NftFields(object):
    @catch_error
    def __getattr__(self, name: str):
        t = self.__annotations__.get(name)
        if t == "str":
            return self._addr[name].string()
        elif t == "int":
            return int(self._addr[name])

        raise AttributeError(f"'{t}' this type hint is not supported on field '{name}'")

    @classmethod
    def get_hook_list_dev_names(cls, hook_list: pwndbg.dbg_mod.Value) -> List[str]:
        devs = []
        for hook in for_each_entry(hook_list, "struct nft_hook", "list"):
            dev_name = hook["ops"]["dev"]["name"].string()
            devs.append(dev_name)
        return devs

    def print_fields(self, nested: int = 0, keys: List[str] = None):
        pad = " " * ((nested + 1) * 2)
        if keys is None:
            keys = self.__annotations__.keys()
        for key in keys:
            val = getattr(self, key)
            if hasattr(val, "nested_print"):
                print(f"{pad}{key}:")
                val.nested_print(nested=nested + 1)
                continue

            print(f"{pad}{key}: {val}")


class Expr:
    expr_name: str

    def __init__(self, addr: pwndbg.dbg_mod.Value):
        self._addr = addr  # struct nft_expr *

    @property
    def expr_name(self) -> str:
        return self._addr["ops"]["type"]["name"].string()

    def print_expr_iptables(self, expr_name: str):
        typel = pwndbg.aglib.typeinfo.lookup_types(f"struct xt_{expr_name}")
        expr = pwndbg.aglib.memory.get_typed_pointer(typel, int(self._addr["ops"]["data"]))

        if expr_name == "match":
            size = int(expr["matchsize"])
        elif expr_name == "target":
            size = int(expr["targetsize"])
        else:
            assert False

        try:
            info = pwndbg.aglib.memory.read(int(self._addr["data"].address), size)
        except pwndbg.dbg_mod.Error as e:
            info = bytearray(f"<unavailable: {e}>".encode())
        print(
            {
                "name": expr["name"].string(),
                "rev": int(expr["revision"]),
                "size": size,
                "info": info,
            }
        )

    def print_expr_nftables(self, expr_name: str):
        typel = pwndbg.aglib.typeinfo.lookup_types(
            f"struct nft_{expr_name}",
            f"struct nft_{expr_name}_expr",
        )
        expr = pwndbg.aglib.memory.get_typed_pointer(typel, int(self._addr["data"].address))
        print(expr.dereference().value_to_human_readable())

    def print(self, print_nested: bool = True):
        expr_name = self.expr_name
        addr = int(self._addr["data"].address)
        print(f"{expr_name} @ 0x{addr:x}")

        if not print_nested:
            return

        if int(self._addr["ops"]["dump"].address) == 0:
            # No dump method, skip
            return

        if expr_name in ("match", "target"):
            self.print_expr_iptables(expr_name)
        else:
            self.print_expr_nftables(expr_name)


class Rule(NftFields):
    handle: int  # NFTA_RULE_HANDLE
    userdata: bytearray  # NFTA_RULE_USERDATA

    def __init__(self, addr: pwndbg.dbg_mod.Value, chain: "Chain"):
        self._addr = addr  # struct nft_rule *
        self._chain = chain

    @property
    @catch_error
    def userdata(self) -> bytearray:
        if int(self._addr["udata"]) == 0:
            return bytearray(b"")

        ptr = int(self._addr["data"].address) + int(self._addr["dlen"])
        userdata = pwndbg.aglib.memory.get_typed_pointer("struct nft_userdata", ptr)
        userdata_str = pwndbg.aglib.memory.string(
            int(userdata["data"].address), int(userdata["len"])
        )
        return userdata_str

    @classmethod
    def find(
        cls,
        table_name: str,
        table_family: int,
        chain_name: str,
        rule_id: int,
        nsid: Optional[int] = None,
    ) -> Iterator["Rule"]:
        for nft in Chain.find(
            table_name=table_name, table_family=table_family, chain_name=chain_name, nsid=nsid
        ):
            for rule in nft.iter_rules():
                if rule.handle == rule_id or rule_id is None:
                    yield rule

    def iter_exprs(self) -> Iterator[Expr]:
        start = int(self._addr["data"].address)
        end = start + int(self._addr["dlen"])
        current = start

        while current < end:
            ptr = pwndbg.aglib.memory.get_typed_pointer("struct nft_expr", current)
            yield Expr(ptr)
            current += int(ptr["ops"]["size"])

    def print(self, print_nested: bool = True):
        print()
        print(f"nft_rule @ 0x{int(self._addr):x}")
        self.print_fields()

        if not print_nested:
            return
        for expr in self.iter_exprs():
            expr.print()


class ChainHook(NftFields):
    hooknum: int  # NFTA_HOOK_HOOKNUM
    priority: int  # NFTA_HOOK_PRIORITY

    # custom types
    dev: str  # NFTA_HOOK_DEV
    devs: List[str]  # NFTA_HOOK_DEVS

    def __init__(self, parent: "Chain"):
        basechain = parent.basechain
        if basechain is None:
            self._addr = None
            self._parent = None
            return

        self._addr = basechain["ops"]
        self._parent = parent

    @property
    @catch_error
    def dev(self) -> str:
        devs = self.get_netdevs()
        if len(devs) == 1:
            return devs[0]
        return ""

    @property
    @catch_error
    def devs(self) -> List[str]:
        return self.get_netdevs()

    def is_netdev(self) -> bool:
        NF_INET_INGRESS = 5
        family = self._parent.table.family
        hooknum = self.hooknum
        return family == NFPROTO_NETDEV or (family == NFPROTO_INET and hooknum == NF_INET_INGRESS)

    def get_netdevs(self) -> List[str]:
        basechain = self._parent.basechain
        if basechain is None:
            return []

        if not self.is_netdev():
            return []

        return self.get_hook_list_dev_names(basechain["hook_list"])

    def nested_print(self, nested: int = 0):
        self.print_fields(nested=nested)


class Chain(NftFields):
    bound: int  # internal field
    genmask: int  # internal field

    handle: int  # NFTA_CHAIN_HANDLE
    use: int  # NFTA_CHAIN_USE
    flags: int  # NFTA_CHAIN_FLAGS
    name: str  # NFTA_CHAIN_NAME

    # custom types
    hook: ChainHook  # NFTA_CHAIN_HOOK
    table: "Table"  # NFTA_CHAIN_TABLE
    userdata: bytearray  # NFTA_CHAIN_USERDATA
    policy: int  # NFTA_CHAIN_POLICY
    type: str  # NFTA_CHAIN_TYPE
    # TODO: implement: counters # NFTA_CHAIN_COUNTERS chain->basechain->stats (struct nft_stats __percpu *stats;)

    def __init__(self, addr: pwndbg.dbg_mod.Value):
        self._addr = addr  # struct nft_chain *
        self.hook = ChainHook(self)

    @property
    @catch_error
    def userdata(self) -> bytearray:
        udata = self._addr["udata"]
        if int(udata) == 0:
            return bytearray(b"")

        return pwndbg.aglib.memory.string(int(udata.address), int(self._addr["udlen"]))

    @property
    @catch_error
    def policy(self) -> int:
        return int(self.basechain["policy"])

    @property
    @catch_error
    def type(self) -> str:
        return self.basechain["type"]["name"].string()

    @property
    @catch_error
    def table(self) -> "Table":
        return Table(self._addr["table"])

    @property
    @catch_error
    def basechain(self) -> Optional[pwndbg.dbg_mod.Value]:
        NFT_CHAIN_BINDING = 1 << 2
        if self.flags & NFT_CHAIN_BINDING:
            return None

        return container_of(int(self._addr), "struct nft_base_chain", "chain")

    @classmethod
    def find(
        cls,
        table_family: Optional[int] = None,
        table_name: Optional[str] = None,
        chain_name: Optional[str] = None,
        nsid: Optional[int] = None,
    ) -> Iterator["Chain"]:
        for nft in Table.find(table_name=table_name, table_family=table_family, nsid=nsid):
            for chain in nft.iter_chains():
                if chain_name is None or chain.name == chain_name:
                    yield chain

    def iter_rules(self) -> Iterator[Rule]:
        for rule in for_each_entry(self._addr["rules"], "struct nft_rule", "list"):
            yield Rule(rule, self)

    def print(self, print_nested: bool = True):
        print()
        print(f"nft_chain @ 0x{int(self._addr):x}")
        self.print_fields()

        if not print_nested:
            return
        for rule in self.iter_rules():
            rule.print()


class Set(NftFields):
    use: int  # internal field
    dead: int  # internal field
    genmask: int  # internal field
    field_count: int  # internal field
    num_exprs: int  # internal field

    name: str  # NFTA_SET_NAME
    flags: int  # NFTA_SET_FLAGS
    ktype: int  # NFTA_SET_KEY_TYPE
    klen: int  # NFTA_SET_KEY_LEN
    dtype: int  # NFTA_SET_DATA_TYPE
    dlen: int  # NFTA_SET_DATA_LEN
    policy: int  # NFTA_SET_POLICY
    timeout: int  # NFTA_SET_TIMEOUT
    gc_int: int  # NFTA_SET_GC_INTERVAL
    objtype: int  # NFTA_SET_OBJ_TYPE
    handle: int  # NFTA_SET_HANDLE

    # custom fields
    nelems: int  # internal field
    table: "Table"  # NFTA_SET_TABLE
    userdata: bytearray  # NFTA_SET_USERDATA
    desc_size: int  # NFTA_SET_DESC_SIZE
    desc_concat: int  # NFTA_SET_DESC_CONCAT
    # iter_exprs  # NFTA_SET_EXPR
    # iter_exprs  # NFTA_SET_EXPRESSIONS

    def __init__(self, addr: pwndbg.dbg_mod.Value):
        self._addr = addr  # struct nft_set *

    @property
    @catch_error
    def nelems(self) -> int:
        return int(self._addr["nelems"]["counter"])

    @property
    @catch_error
    def desc_size(self) -> int:
        return int(self._addr["size"])

    @property
    @catch_error
    def desc_concat(self) -> List[int]:
        field_count = self.field_count
        if not (field_count > 1):
            return []

        out = []
        for i in range(field_count):
            val = int(self._addr["field_len"][i])  # todo: htonl?
            out.append(val)
        return out

    @property
    @catch_error
    def table(self) -> "Table":
        return Table(self._addr["table"])

    @property
    @catch_error
    def userdata(self) -> bytearray:
        if int(self._addr["udata"]) == 0:
            return bytearray(b"")

        return pwndbg.aglib.memory.string(
            int(self._addr["udata"].address), int(self._addr["udlen"])
        )

    def iter_expr(self) -> Iterator[Expr]:
        for i in range(self.num_exprs):
            yield Expr(self._addr["exprs"][i])

    def iter_elems(self) -> Iterator[None]:
        # TODO: implement nft_get_set_elem
        raise NotImplementedError("todo implement nft_get_set_elem")

    def print(self, print_nested: bool = True):
        print()
        print(f"nft_set @ 0x{int(self._addr):x}")
        self.print_fields()

        for expr in self.iter_expr():
            expr.print()


# Object can only be used for:
# - nft_connlimit
# - nft_ct
# - nft_limit
# - nft_quota
# - nft_synproxy
# - nft_tunnel
class Object(NftFields):
    genmask: int  # internal field

    use: int  # NFTA_OBJ_USE
    handle: int  # NFTA_OBJ_HANDLE

    # custom fields
    table: "Table"  # NFTA_OBJ_TABLE
    name: str  # NFTA_OBJ_NAME
    type: int  # NFTA_OBJ_TYPE
    userdata: bytearray  # NFTA_OBJ_USERDATA
    # iter_data  # NFTA_OBJ_DATA

    def __init__(self, addr: pwndbg.dbg_mod.Value):
        self._addr = addr  # struct nft_object *

    @property
    @catch_error
    def type(self) -> int:
        return int(self._addr["ops"]["type"]["type"])

    @property
    @catch_error
    def name(self) -> str:
        return self._addr["key"]["name"].string()

    @property
    @catch_error
    def table(self) -> "Table":
        return Table(self._addr["key"]["table"])

    @property
    @catch_error
    def userdata(self) -> bytearray:
        if int(self._addr["udata"]) == 0:
            return bytearray(b"")

        return pwndbg.aglib.memory.string(
            int(self._addr["udata"].address), int(self._addr["udlen"])
        )

    def iter_data(self) -> Iterator[None]:
        # TODO: implement nft_object_dump
        raise NotImplementedError("todo implement nft_object_dump")

    def print(self, print_nested: bool = True):
        print()
        print(f"nft_object @ 0x{int(self._addr):x}")
        self.print_fields()


class FlowtableHook(NftFields):
    hooknum: int  # NFTA_FLOWTABLE_HOOK_NUM
    priority: int  # NFTA_FLOWTABLE_HOOK_PRIORITY
    devs: List[str]  # NFTA_FLOWTABLE_HOOK_DEVS

    def __init__(self, parent: "Flowtable"):
        self._addr = parent._addr

    @property
    @catch_error
    def hooknum(self) -> int:
        return int(self._addr["hooknum"])

    @property
    @catch_error
    def priority(self) -> int:
        return int(self._addr["data"]["priority"])

    @property
    @catch_error
    def devs(self) -> List[str]:
        return self.get_hook_list_dev_names(self._addr["hook_list"])

    def nested_print(self, nested: int = 0):
        self.print_fields(nested=nested)


class Flowtable(NftFields):
    genmask: int  # internal field

    name: str  # NFTA_FLOWTABLE_NAME
    use: int  # NFTA_FLOWTABLE_USE
    handle: int  # NFTA_FLOWTABLE_HANDLE

    # custom fields
    table: "Table"  # NFTA_FLOWTABLE_TABLE
    flags: int  # NFTA_FLOWTABLE_FLAGS
    hook: FlowtableHook  # NFTA_FLOWTABLE_HOOK

    def __init__(self, addr: pwndbg.dbg_mod.Value):
        self._addr = addr  # struct nft_flowtable *
        self.hook = FlowtableHook(self)

    @property
    @catch_error
    def table(self) -> "Table":
        return Table(self._addr["table"])

    @property
    @catch_error
    def flags(self) -> int:
        return int(self._addr["data"]["flags"])

    def print(self, print_nested: bool = True):
        print()
        print(f"nft_flowtable @ 0x{int(self._addr):x}")
        self.print_fields()


class Table(NftFields):
    family: int  # internal field
    genmask: (
        int  # internal nft transaction number (maybe useful to checking errors in commit phase)
    )
    name: str  # NFTA_TABLE_NAME
    handle: int  # NFTA_TABLE_HANDLE
    use: int  # NFTA_TABLE_USE
    flags: int  # NFTA_TABLE_FLAGS
    nlpid: int  # NFTA_TABLE_OWNER

    def __init__(self, addr: pwndbg.dbg_mod.Value):
        self._addr = addr  # struct nft_table *

    @classmethod
    def find(
        cls,
        table_name: Optional[str] = None,
        table_family: Optional[int] = None,
        nsid: Optional[int] = None,
    ) -> Iterator["Table"]:
        nft = Nftables.find(nsid=nsid)
        if nft is None:
            return
        for table in nft.iter_tables():
            if (table.family == table_family or table_family is None) and (
                table.name == table_name or table_family is None
            ):
                yield table

    def iter_chains(self) -> Iterator[Chain]:
        for chain in for_each_entry(self._addr["chains"], "struct nft_chain", "list"):
            yield Chain(chain)

    def iter_sets(self) -> Iterator[Set]:
        for nft_set in for_each_entry(self._addr["sets"], "struct nft_set", "list"):
            yield Set(nft_set)

    def iter_flowtables(self) -> Iterator[Flowtable]:
        for flowtable in for_each_entry(self._addr["flowtables"], "struct nft_flowtable", "list"):
            yield Flowtable(flowtable)

    def iter_objects(self) -> Iterator[Object]:
        for nft_object in for_each_entry(self._addr["objects"], "struct nft_flowtable", "list"):
            yield Object(nft_object)

    def nested_print(self, nested: int = 0):
        self.print_fields(nested=nested, keys=["name"])

    def print(self, print_nested: bool = True):
        print()
        print(f"nft_table @ 0x{int(self._addr):x}")
        self.print_fields()

        if not print_nested:
            return
        for chain in self.iter_chains():
            chain.print()


class Nftables:
    def __init__(self, addr: pwndbg.dbg_mod.Value):
        self._addr = addr  # struct net *

    @classmethod
    def find(cls, nsid: Optional[int] = None) -> Optional["Nftables"]:
        if nsid is None:
            addr = get_init_net_namespace()
        else:
            # See kernel: `struct net *get_net_ns_by_id(const struct net *net, int id)`
            raise NotImplementedError("todo implement search netns by id")

        return Nftables(addr)

    def iter_tables(self) -> Iterator[Table]:
        for table in for_each_entry(self._addr["nft"]["tables"], "struct nft_table", "list"):
            yield Table(table)

    def print(self):
        for table in self.iter_tables():
            table.print()


def get_init_net_namespace() -> pwndbg.dbg_mod.Value:
    return pwndbg.aglib.symbol.lookup_symbol("init_net")


# TODO: List what is missing:
# - pretty printing expressions
# - listing nested expressions eg. in "dynset" expression or expresions inside setelem
# - bug with printing "counter", because there are percpu struct
# - printing/parser xtable (iptables) expressions
# - missing listing set elements: `knft-list-set-elements [-nsid <nsid>] <table_family> <table_name> <set_id>`
# - missing info about ebpf nft hooks
# - listing network namespaces
# - printing netns tables

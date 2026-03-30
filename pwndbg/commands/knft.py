from __future__ import annotations

import argparse

import pwndbg.aglib.kernel.nftables
import pwndbg.commands
from pwndbg.commands import CommandCategory


def parse_nft_family(s: str) -> int:
    val = pwndbg.aglib.kernel.nftables.nftables_table_family.get(s)
    if val is None:
        allowed = ",".join(set(pwndbg.aglib.kernel.nftables.nftables_table_family.keys()))
        raise argparse.ArgumentTypeError(f"Incorrect family '{s}', only '{allowed}'")
    return val


def knft_dump(nsid: int | None = None) -> None:
    nft = pwndbg.aglib.kernel.nftables.Nftables.find(nsid=nsid)
    if nft is None:
        print("No netns found")
        return

    nft.print()


def knft_list_tables(nsid: int | None = None) -> None:
    nft = pwndbg.aglib.kernel.nftables.Nftables.find(nsid=nsid)
    if nft is None:
        print("No netns found")
        return

    for table in nft.iter_tables():
        table.print(print_nested=False)


def knft_list_chains(
    table_family: int | None = None, table_name: str | None = None, nsid: int | None = None
) -> None:
    is_any = False
    for nft in pwndbg.aglib.kernel.nftables.Table.find(
        nsid=nsid, table_family=table_family, table_name=table_name
    ):
        is_any = True
        for chain in nft.iter_chains():
            chain.print(print_nested=False)

    if not is_any:
        print("No nftables table found")


def knft_list_rules(
    table_family: int | None = None,
    table_name: str | None = None,
    chain_name: str | None = None,
    nsid: int | None = None,
) -> None:
    is_any = False
    for nft in pwndbg.aglib.kernel.nftables.Chain.find(
        nsid=nsid, table_family=table_family, table_name=table_name, chain_name=chain_name
    ):
        is_any = True
        for rule in nft.iter_rules():
            rule.print(print_nested=False)
    if not is_any:
        print("No nftables chain found")


def knft_list_exprs(
    table_family: int | None = None,
    table_name: str | None = None,
    chain_name: str | None = None,
    rule_id: int | None = None,
    nsid: int | None = None,
) -> None:
    is_any = False
    for nft in pwndbg.aglib.kernel.nftables.Rule.find(
        nsid=nsid,
        table_family=table_family,
        table_name=table_name,
        chain_name=chain_name,
        rule_id=rule_id,
    ):
        is_any = True
        for expr in nft.iter_exprs():
            expr.print(print_nested=True)
    if not is_any:
        print("No nftables rule found")


def knft_list_sets(
    table_family: int | None = None, table_name: str | None = None, nsid: int | None = None
) -> None:
    is_any = False
    for nft in pwndbg.aglib.kernel.nftables.Table.find(
        nsid=nsid, table_family=table_family, table_name=table_name
    ):
        is_any = True
        for nft_set in nft.iter_sets():
            nft_set.print(print_nested=True)
    if not is_any:
        print("No nftables table found")


def knft_list_objects(
    table_family: int | None = None, table_name: str | None = None, nsid: int | None = None
) -> None:
    is_any = False
    for nft in pwndbg.aglib.kernel.nftables.Table.find(
        nsid=nsid, table_family=table_family, table_name=table_name
    ):
        is_any = True
        for nft_object in nft.iter_objects():
            nft_object.print(print_nested=True)
    if not is_any:
        print("No nftables table found")


def knft_list_flowtables(
    table_family: int | None = None, table_name: str | None = None, nsid: int | None = None
) -> None:
    is_any = False
    for nft in pwndbg.aglib.kernel.nftables.Table.find(
        nsid=nsid, table_family=table_family, table_name=table_name
    ):
        is_any = True
        for flowtable in nft.iter_flowtables():
            flowtable.print(print_nested=True)
    if not is_any:
        print("No nftables table found")


parser = argparse.ArgumentParser(
    description="Utility for inspecting the kernel netfilter subsystem."
)
subparsers = parser.add_subparsers(dest="command")
subparsers.required = True

list_flowtables_parser = subparsers.add_parser(
    "list-flowtables",
    description="Dump netfilter flowtables from a specific table",
    help="Dump netfilter flowtables from a specific table",
)
list_flowtables_parser.add_argument("-n", "--nsid", type=int, help="Network Namespace ID")
list_flowtables_parser.add_argument(
    "table_family",
    nargs="?",
    type=parse_nft_family,
    help="Netfilter table family (inet, ip, ip6, netdev, bridge, arp)",
)
list_flowtables_parser.add_argument("table_name", nargs="?", type=str, help="Table name")

list_objects_parser = subparsers.add_parser(
    "list-objects",
    description="Dump netfilter objects from a specific table",
    help="Dump netfilter objects from a specific table",
)
list_objects_parser.add_argument("-n", "--nsid", type=int, help="Network Namespace ID")
list_objects_parser.add_argument(
    "table_family",
    nargs="?",
    type=parse_nft_family,
    help="Table family, eg: inet, ip, ip6, netdev, bridge, arp",
)
list_objects_parser.add_argument("table_name", nargs="?", type=str, help="Table name")

list_sets_parser = subparsers.add_parser(
    "list-sets",
    description="Dump netfilter sets from a specific table",
    help="Dump netfilter sets from a specific table",
)
list_sets_parser.add_argument("-n", "--nsid", type=int, help="Network Namespace ID")
list_sets_parser.add_argument(
    "table_family",
    nargs="?",
    type=parse_nft_family,
    help="Table family, eg: inet, ip, ip6, netdev, bridge, arp",
)
list_sets_parser.add_argument("table_name", nargs="?", type=str, help="Table name")

list_exprs_parser = subparsers.add_parser(
    "list-exprs",
    description="Dump only expressions from specific rule",
    help="Dump only expressions from specific rule",
)
list_exprs_parser.add_argument("-n", "--nsid", type=int, help="Network Namespace ID")
list_exprs_parser.add_argument(
    "table_family",
    nargs="?",
    type=parse_nft_family,
    help="Table family, eg: inet, ip, ip6, netdev, bridge, arp",
)
list_exprs_parser.add_argument("table_name", nargs="?", type=str, help="Table name")
list_exprs_parser.add_argument("chain_name", nargs="?", type=str, help="Chain name")
list_exprs_parser.add_argument("rule_id", nargs="?", type=int, help="Rule Handle ID")

list_rules_parser = subparsers.add_parser(
    "list-rules",
    description="Dump netfilter rules from a specific chain",
    help="Dump netfilter rules from a specific chain",
)
list_rules_parser.add_argument("-n", "--nsid", type=int, help="Network Namespace ID")
list_rules_parser.add_argument(
    "table_family",
    nargs="?",
    type=parse_nft_family,
    help="Table family, eg: inet, ip, ip6, netdev, bridge, arp",
)
list_rules_parser.add_argument("table_name", nargs="?", type=str, help="Table name")
list_rules_parser.add_argument("chain_name", nargs="?", type=str, help="Chain name")

list_chains_parser = subparsers.add_parser(
    "list-chains",
    description="Dump netfilter chains from a specific table",
    help="Dump netfilter chains from a specific table",
)
list_chains_parser.add_argument("-n", "--nsid", type=int, help="Network Namespace ID")
list_chains_parser.add_argument(
    "table_family",
    nargs="?",
    type=parse_nft_family,
    help="Table family, eg: inet, ip, ip6, netdev, bridge, arp",
)
list_chains_parser.add_argument("table_name", nargs="?", type=str, help="Table name")

list_tables_parser = subparsers.add_parser(
    "list-tables",
    description="Dump netfilter tables from a specific network namespace",
    help="Dump netfilter tables from a specific network namespace",
)
list_tables_parser.add_argument("-n", "--nsid", type=int, help="Network Namespace ID")

dump_parser = subparsers.add_parser(
    "dump",
    description="Dump all nftables: tables, chains, rules, expressions",
    help="Dump all nftables: tables, chains, rules, expressions",
)
dump_parser.add_argument("nsid", type=int, nargs="?", help="Network Namespace ID")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugInfo
@pwndbg.commands.OnlyWhenPagingEnabled
def knft(
    command: str,
    table_family: int | None = None,
    table_name: str | None = None,
    nsid: int | None = None,
    chain_name: str | None = None,
    rule_id: int | None = None,
) -> None:
    match command:
        case "list-flowtables":
            knft_list_flowtables(table_family, table_name, nsid)
        case "list-objects":
            knft_list_objects(table_family, table_name, nsid)
        case "list-sets":
            knft_list_sets(table_family, table_name, nsid)
        case "list-exprs":
            knft_list_exprs(table_family, table_name, chain_name, rule_id, nsid)
        case "list-rules":
            knft_list_rules(table_family, table_name, chain_name, nsid)
        case "list-chains":
            knft_list_chains(table_family, table_name, nsid)
        case "list-tables":
            knft_list_tables(nsid)
        case "dump":
            knft_dump(nsid)

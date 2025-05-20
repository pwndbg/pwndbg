from __future__ import annotations

import argparse
from typing import Optional

import pwndbg.aglib.kernel.nftables
import pwndbg.commands
from pwndbg.commands import CommandCategory


def parse_nft_family(s: str) -> int:
    val = pwndbg.aglib.kernel.nftables.nftables_table_family.get(s)
    if val is None:
        allowed = ",".join(set(pwndbg.aglib.kernel.nftables.nftables_table_family.keys()))
        raise argparse.ArgumentTypeError(f"Incorrect family '{s}', only '{allowed}'")
    return val


parser = argparse.ArgumentParser(
    description="Dump all nftables: tables, chains, rules, expressions"
)
parser.add_argument("nsid", type=int, nargs="?", help="Network Namespace ID")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def knft_dump(nsid: Optional[int] = None):
    nft = pwndbg.aglib.kernel.nftables.Nftables.find(nsid=nsid)
    if nft is None:
        print("No netns found")
        return

    nft.print()


parser = argparse.ArgumentParser(
    description="Dump netfliter tables from a specific network namespace"
)
parser.add_argument("--nsid", "-n", type=int, help="Network Namespace ID")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def knft_list_tables(nsid: Optional[int] = None):
    nft = pwndbg.aglib.kernel.nftables.Nftables.find(nsid=nsid)
    if nft is None:
        print("No netns found")
        return

    for table in nft.iter_tables():
        table.print(print_nested=False)


parser = argparse.ArgumentParser(description="Dump netfilter chains form a specific table")
parser.add_argument("--nsid", "-n", type=int, help="Network Namespace ID")
parser.add_argument(
    "table_family",
    nargs="?",
    type=parse_nft_family,
    help="Netfilter table family (inet, ip, ip6, netdev, bridge, arp)",
)
parser.add_argument("table_name", nargs="?", type=str, help="Table name")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def knft_list_chains(
    table_family: Optional[int] = None, table_name: Optional[str] = None, nsid: Optional[int] = None
):
    is_any = False
    for nft in pwndbg.aglib.kernel.nftables.Table.find(
        nsid=nsid, table_family=table_family, table_name=table_name
    ):
        is_any = True
        for chain in nft.iter_chains():
            chain.print(print_nested=False)

    if not is_any:
        print("No nftables table found")


parser = argparse.ArgumentParser(description="Dump netfilter rules form a specific chain")
parser.add_argument("--nsid", "-n", type=int, help="Network Namespace ID")
parser.add_argument(
    "table_family",
    nargs="?",
    type=parse_nft_family,
    help="Table family, eg: inet, ip, ip6, netdev, bridge, arp",
)
parser.add_argument("table_name", nargs="?", type=str, help="Table name")
parser.add_argument("chain_name", nargs="?", type=str, help="Chain name")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def knft_list_rules(
    table_family: Optional[int] = None,
    table_name: Optional[str] = None,
    chain_name: Optional[str] = None,
    nsid: Optional[int] = None,
):
    is_any = False
    for nft in pwndbg.aglib.kernel.nftables.Chain.find(
        nsid=nsid, table_family=table_family, table_name=table_name, chain_name=chain_name
    ):
        is_any = True
        for rule in nft.iter_rules():
            rule.print(print_nested=False)
    if not is_any:
        print("No nftables chain found")


parser = argparse.ArgumentParser(description="Dump only expressions from specific rule")
parser.add_argument("--nsid", "-n", type=int, help="Network Namespace ID")
parser.add_argument(
    "table_family",
    nargs="?",
    type=parse_nft_family,
    help="Table family, eg: inet, ip, ip6, netdev, bridge, arp",
)
parser.add_argument("table_name", nargs="?", type=str, help="Table name")
parser.add_argument("chain_name", nargs="?", type=str, help="Chain name")
parser.add_argument("rule_id", nargs="?", type=int, help="Rule Handle ID")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def knft_list_exprs(
    table_family: Optional[int] = None,
    table_name: Optional[str] = None,
    chain_name: Optional[str] = None,
    rule_id: Optional[int] = None,
    nsid: Optional[int] = None,
):
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


parser = argparse.ArgumentParser(description="Dump netfilter sets from a specific table")
parser.add_argument("--nsid", "-n", type=int, help="Network Namespace ID")
parser.add_argument(
    "table_family",
    nargs="?",
    type=parse_nft_family,
    help="Table family, eg: inet, ip, ip6, netdev, bridge, arp",
)
parser.add_argument("table_name", nargs="?", type=str, help="Table name")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def knft_list_sets(
    table_family: Optional[int] = None, table_name: Optional[str] = None, nsid: Optional[int] = None
):
    is_any = False
    for nft in pwndbg.aglib.kernel.nftables.Table.find(
        nsid=nsid, table_family=table_family, table_name=table_name
    ):
        is_any = True
        for nft_set in nft.iter_sets():
            nft_set.print(print_nested=True)
    if not is_any:
        print("No nftables table found")


parser = argparse.ArgumentParser(description="Dump netfilter objects from a specific table")
parser.add_argument("--nsid", "-n", type=int, help="Network Namespace ID")
parser.add_argument(
    "table_family",
    nargs="?",
    type=parse_nft_family,
    help="Table family, eg: inet, ip, ip6, netdev, bridge, arp",
)
parser.add_argument("table_name", nargs="?", type=str, help="Table name")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def knft_list_objects(
    table_family: Optional[int] = None, table_name: Optional[str] = None, nsid: Optional[int] = None
):
    is_any = False
    for nft in pwndbg.aglib.kernel.nftables.Table.find(
        nsid=nsid, table_family=table_family, table_name=table_name
    ):
        is_any = True
        for nft_object in nft.iter_objects():
            nft_object.print(print_nested=True)
    if not is_any:
        print("No nftables table found")


parser = argparse.ArgumentParser(description="Dump netfilter flowtables from a specific table")
parser.add_argument("--nsid", "-n", type=int, help="Network Namespace ID")
parser.add_argument(
    "table_family",
    nargs="?",
    type=parse_nft_family,
    help="Netfilter table family (inet, ip, ip6, netdev, bridge, arp)",
)
parser.add_argument("table_name", nargs="?", type=str, help="Table name")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def knft_list_flowtables(
    table_family: Optional[int] = None, table_name: Optional[str] = None, nsid: Optional[int] = None
):
    is_any = False
    for nft in pwndbg.aglib.kernel.nftables.Table.find(
        nsid=nsid, table_family=table_family, table_name=table_name
    ):
        is_any = True
        for flowtable in nft.iter_flowtables():
            flowtable.print(print_nested=True)
    if not is_any:
        print("No nftables table found")

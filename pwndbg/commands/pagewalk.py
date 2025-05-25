#
# from __future__ import annotations
#
# import argparse
#
# import pwndbg.aglib.kernel
#
# parser = argparse.ArgumentParser(description="Performs pagewalk.")
# parser.add_argument("-a", "--address", type: int, help="A value or expression that represents the physical address to resolve")
# parser.add_argument("-l", "--level", type:str, choices=["pgd", "p4d", "pud", "pmd", "pte"], help="level of the pagetable address")
#
#
# def level_idx(level: str) -> int:
#     if level == "pgd":
#         return 4
#     if level == "pud":
#         return 3
#     if level == "pmd":
#         return 2
#     if level == "pte":
#         return 1
#     return None
#
# def level_idx_lv5(level: str) -> int:
#     if level == "pgd":
#         return 5
#     if level == "p4d":
#         return 4
#     if level == "pud":
#         return 3
#     if level == "pmd":
#         return 2
#     if level == "pte":
#         return 1
#     return None

from __future__ import annotations

# def pagewalk(address, level="pgd"):
#     idx = None
#     if pwndbg.aglib.kernel.uses_5lvl_paging():
#         idx = level_idx_lv5(level)
#     else:
#         idx = level_idx(level)
#     if idx is None:
#         print(M.wanr("invalid page level"))
#         return
#     for _ in range(idx):
#         next = walk

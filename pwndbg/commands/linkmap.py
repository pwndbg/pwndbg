from __future__ import annotations

import argparse

import pwndbg.aglib.dynamic
import pwndbg.aglib.proc
import pwndbg.color as color
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="Show the state of the Link Map",
)


@pwndbg.commands.Command(parser, category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
def linkmap() -> None:
    is_first = True
    rows = [["Node", "Objfile", "Load Bias", "Dynamic Segment"]]
    for obj in pwndbg.aglib.dynamic.link_map():
        name = obj.name().decode("utf-8")
        if name == "":
            name = "<Unknown"
            if is_first:
                is_first = False
                name += f", likely {pwndbg.aglib.proc.exe}"
            name += ">"
        rows.append(
            [f"{obj.link_map_address:#x}", name, f"{obj.load_bias():#x}", f"{obj.dynamic():#x}"]
        )

    col_max = [0, 0, 0, 0]
    for i in range(len(rows)):
        for j in range(len(col_max)):
            if len(rows[i][j]) > col_max[j]:
                col_max[j] = len(rows[i][j])

    colors = [color.light_cyan, color.light_yellow, color.light_red, color.light_purple]
    for i in range(len(rows)):
        for j in range(len(col_max)):
            print(f"{colors[j](rows[i][j].ljust(col_max[j]))} ", end="")
        print()

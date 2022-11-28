# gdb.selected_frame ()
# gdb.newest_frame ()
# Frame.pc ()
# Frame.function ()
# Frame.older ()
# Frame.newer ()
# Frame.select ()
# Frame.read_var (variable [, block])
from typing import List

import gdb

# class Frame:
#     def __init__(self, frame):
#         pass

# def get_frames() -> List[Frame]:
#     pass

# def select_frame(num: int):
#     pass


def get_function_frame(function_name: str):
    f = gdb.selected_frame()
    while f != None:
        if f.function() != None and f.function().name == function_name:
            break
        f = f.older()

    return f

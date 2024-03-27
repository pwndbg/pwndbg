import json
import os
import re
import tempfile
from io import StringIO
from xml.dom import minidom

import pexpect
from rich import text
from rich.console import Console
from rich.terminal_theme import MONOKAI

parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
gdb_common = 'gdb --quiet --ex "source ' + parent_dir + '/gdbinit.py" --ex "set environment HOME /home/pwndbg"'

# rect representing a rectangle with floating point coordinates
class Rect:
    def __init__(self, min_x, min_y, max_x, max_y):
        self.min_x = min_x
        self.min_y = min_y
        self.max_x = max_x
        self.max_y = max_y

    def __str__(self):
        return f"Rect({self.min_x}, {self.min_y}, {self.max_x}, {self.max_y})"

    def extend(self, other):
        if not other.valid():
            return
        if not self.valid():
            self.min_x = other.min_x
            self.min_y = other.min_y
            self.max_x = other.max_x
            self.max_y = other.max_y
            return
        self.min_x = min(self.min_x, other.min_x)
        self.min_y = min(self.min_y, other.min_y)
        self.max_x = max(self.max_x, other.max_x)
        self.max_y = max(self.max_y, other.max_y)

    def width(self):
        return self.max_x - self.min_x

    def height(self):
        return self.max_y - self.min_y

    def valid(self):
        return (
            self.min_x is not None
            and self.min_y is not None
            and self.max_x is not None
            and self.max_y is not None
        )


def annotate_svg(svg_path, annotations=[]):
    annotation_colors = [
        "#1abc9c",
        "#f1c40f",
        "#e74c3c",
        "#9b59b6",
        "#f39c12",
    ]
    doc = minidom.parse(svg_path)
    # clipPath rectandgles by id
    clip_rects = {}
    for clip_path in doc.getElementsByTagName("clipPath"):
        clip_id = clip_path.getAttribute("id")
        for rect in clip_path.getElementsByTagName("rect"):
            clip_rects[clip_id] = Rect(
                float(rect.getAttribute("x")),
                float(rect.getAttribute("y")),
                float(rect.getAttribute("x")) + float(rect.getAttribute("width")),
                float(rect.getAttribute("y")) + float(rect.getAttribute("height")),
            )
    # get all <text> elements
    text_elements = doc.getElementsByTagName("text")
    for annotation in annotations:

        text_parent = None
        # parse annotation["match"] as regexes
        regexes = [re.compile(regex) for regex in annotation["match"]]
        annotation_rect = Rect(None, None, None, None)
        for text_element in text_elements:
            # get the text
            text = text_element.firstChild.nodeValue
            # if any of the regexes match, add the annotation
            if any(regex.search(text) for regex in regexes):
                clipPathId = (
                    text_element.getAttribute("clip-path").replace("url(#", "").replace(")", "")
                )
                rect = clip_rects[clipPathId]
                text_parent = text_element.parentNode.parentNode
                rect.min_x = float(text_element.getAttribute("x"))
                rect.max_x = rect.min_x + float(text_element.getAttribute("textLength"))

                annotation_rect.extend(rect)
        # add the annotation
        if text_parent is not None:
            rect = doc.createElement("rect")
            rect.setAttribute("x", str(annotation_rect.min_x + 2.0))
            rect.setAttribute("y", str(annotation_rect.min_y))
            rect.setAttribute("width", str(annotation_rect.width()))
            rect.setAttribute("height", str(annotation_rect.height() - 2.0))
            rect.setAttribute("fill", "none")
            rect.setAttribute("stroke", annotation_colors[0])
            rect.setAttribute("stroke-width", "3")
            # add rounded corners
            rect.setAttribute("rx", "5")
            rect.setAttribute("ry", "5")
            text_parent.appendChild(rect)
            text = doc.createElement("text")
            text.setAttribute("x", str(annotation_rect.max_x + 15))
            text.setAttribute("y", str((annotation_rect.max_y + annotation_rect.min_y) / 2))
            text.setAttribute("font-size", "40")
            text.setAttribute("font-family", "monospace")
            text.setAttribute("alignment-baseline", "middle")
            text.setAttribute("fill", annotation_colors[0])
            text.appendChild(doc.createTextNode(annotation["text"]))
            text_parent.appendChild(text)

            annotation_colors.append(annotation_colors.pop(0))  # rotate colors

    with open(svg_path, "w") as f:
        f.write(doc.toxml())


# runs the given command in a pty and saves a screenshot of the output
def render_cmd(cmd, stdin_input, outfile, cmd_display_as=None):
    if cmd_display_as is None:
        cmd_display_as = cmd.replace(gdb_common, "gdb")
    sanitized_env = {k: v for k, v in os.environ.items() if k in ["HOME", "LANG", "LC_ALL", "PATH"]}

    child = pexpect.spawn(
        cmd,
        env=sanitized_env,
        cwd="/tmp",
    )
    output = []
    # send the input to the command
    child.sendline(stdin_input)
    while True:
        try:
            data = child.read_nonblocking(size=1, timeout=2)
            output.append(data)
        except pexpect.TIMEOUT:
            # kill the process
            child.kill(9)
        except pexpect.EOF:
            out_str = b"".join(output).decode("utf-8")
            out_str_lines = out_str.splitlines()
            # start from '---START_RENDER---'
            try:
                out_str_lines = out_str_lines[out_str_lines.index("'---START_RENDER---'") + 1 :]
            except ValueError:
                pass
            # end at '---END_RENDER---'
            try:
                out_str_lines = out_str_lines[: out_str_lines.index("'---END_RENDER---'") - 1]
            except ValueError:
                pass

            out_str = "$ " + cmd_display_as + "\n" + "\n".join(out_str_lines)
            console = Console(record=True, file=StringIO())
            richText = text.Text.from_ansi(out_str)
            console.print(richText)
            console.save_svg(outfile, theme=MONOKAI, title="pwndbg")
            annotations = []
            for line in stdin_input.splitlines():
                if line.startswith("#ANNOTATE "):
                    # reove the #ANNOTATE: prefix
                    annotations.append(json.loads(line[10:]))

            annotate_svg(outfile, annotations)
            break


names_used = []


def generate_name(title):
    if title in names_used:
        i = 1
        while title + str(i) in names_used:
            i += 1
        title += str(i)
    names_used.append(title)
    return title


if __name__ == "__main__":
    # open FEATURES.md and find all the code blocks
    with open("FEATURES.src.md", "r") as f:
        lines = f.readlines()
        output = []  # processed markdown lines
        last_title = "untitled"  # hold the last title, so we can name the generated images nicely
        i = 0

        bin_path = None  # path to the last compiled binary

        while i < len(lines):
            if lines[i].startswith("```pwndbg"):
                # the command is everything after the first space
                gdb_cmd = lines[i].split(" ", 1)[1].strip()
                gdb_cmd = gdb_cmd.replace("$GDB", gdb_common).replace("$BIN", bin_path or "$BIN")
                gdb_input = []
                # read until the next code block
                j = i + 1
                while not lines[j].startswith("```"):
                    gdb_input.append(lines[j])
                    j += 1
                j += 1
                svg_name = generate_name(last_title) + ".svg"
                print("Running GDB (for image: {}): {}".format(svg_name, gdb_cmd))

                # render_cmd
                render_cmd(
                    cmd=gdb_cmd,
                    stdin_input="".join(gdb_input).strip(),
                    outfile=parent_dir + "/docs/images/" + svg_name,
                )
                # add the image to the output
                output.append("![](images/" + svg_name + ")\n")
                i = j
            else:
                # compile c programs which specify a command to compile afer ```c
                if lines[i].startswith("```c"):
                    compile_cmd = lines[i].split(" ", 1)[1].strip()
                    c_source = []
                    j = i + 1
                    while not lines[j].startswith("```"):
                        c_source.append(lines[j])
                        j += 1
                    # save the source to a temp file
                    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".c") as f:
                        f.write("".join(c_source))
                    bin_path = f.name + ".out"
                    # compile the source
                    cmd_to_compile = compile_cmd.replace("$BIN", bin_path).replace("$IN", f.name)
                    print("Compiling: " + cmd_to_compile)
                    os.system(cmd_to_compile)
                    bin_path = f.name + ".out"

                if lines[i].startswith("#"):
                    last_title = (
                        lines[i].replace("#", "").strip().replace(" ", "_").replace("`", "").lower()
                    )
                output.append(lines[i])
            i += 1
    # write the output to FEATURES.md
    with open("FEATURES.md", "w") as f:
        f.writelines(output)

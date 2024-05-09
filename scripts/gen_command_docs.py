from pprint import pprint
import pwndbg.commands
from collections import defaultdict
import argparse
import os
import io
import sys
from mdutils.mdutils import MdUtils


def dprint(ob):
    print(dir(ob))


def save_to_file(filename, data):
    with open(filename, 'w') as f:
        f.write(data)

def inline_code(code):
    return f"`{code}`"

def md_help(filename, parser, name):
    mdFile = MdUtils(filename)

    mdFile.new_header(level=1, title=name)
    if parser.description:
        mdFile.new_header(level=2, title="Description")
        mdFile.new_paragraph(parser.description)

    mdFile.new_header(level=2, title="Usage:")
    mdFile.insert_code(parser.format_usage(), language="bash")

    used_actions = {}
    options_positional = ["Positional Argument", "Help"]
    options_optional = ["Short", "Long", "Default", "Help"]

    # Process positional arguments
    if parser._positionals._group_actions:
        for action in parser._positionals._group_actions:
            list_of_str = [inline_code(action.dest), action.help]
            this_id = id(action)
            if this_id in used_actions:
                continue
            used_actions[this_id] = True

            options_positional.extend(list_of_str)

        mdFile.new_header(level=2, title="Positional Arguments")
        options_positional = [
            inline_code(di) if di is None else di.replace("\n", " ") for di in options_positional
        ]
        mdFile.new_table(
            columns=2,
            rows=len(options_positional) // 2,
            text=options_positional,
            text_align="left",
        )

    # Process optional arguments
    if parser._option_string_actions:
        for k in parser._option_string_actions:
            action = parser._option_string_actions[k]
            list_of_str = ["", "", "", action.help]
            this_id = id(action)
            if this_id in used_actions:
                continue
            used_actions[this_id] = True

            for opt in action.option_strings:
                # --, long option
                if len(opt) > 1 and opt[1] in parser.prefix_chars:
                    list_of_str[1] = inline_code(opt)
                # short opt
                elif len(opt) > 0 and opt[0] in parser.prefix_chars:
                    list_of_str[0] = inline_code(opt)

            if not (
                isinstance(action.default, bool)
                or isinstance(action, argparse._VersionAction)
                or isinstance(action, argparse._HelpAction)
            ):
                default = (
                    action.default
                    if isinstance(action.default, str)
                    else repr(action.default)
                )
                list_of_str[2] = inline_code(default)

            options_optional.extend(list_of_str)

        mdFile.new_header(level=2, title="Optional Arguments")
        options_optional = [
            inline_code(di) if di is None else di.replace("\n", " ") for di in options_optional
        ]
        mdFile.new_table(
            columns=4,
            rows=len(options_optional) // 4,
            text=options_optional,
            text_align="left",
        )

    mdFile.create_md_file()

commands_info = {} 

cmd = {}

commands = defaultdict(list)

for i in dir(pwndbg.commands):
    fn = getattr(pwndbg.commands, i)
    # print(dir(fn))
    for j in dir(fn):
        if isinstance(getattr(fn, j), pwndbg.commands.Command):
            fn2 = getattr(fn, j)
            category = fn2.category
            parser = fn2.parser
            if category is None:
                category = 'Other'
            else:
                category = category.value
            commands[category].append(j)

            filename = f'commands/{i}/{j}.md'
            parser = (getattr(fn2, 'parser'))
            cmd[parser.prog] = i

            directory = os.path.dirname(filename)
            os.makedirs(directory, exist_ok=True)

            commands_info[j] = {
                "name": j,
                "command_name": parser.prog,
                "category": category,
                "module": i,
                "desc": parser.description.splitlines()[0] or ''
            }

            data = ""
            
            md_help(filename, parser, parser.prog)

pprint(cmd)



# use d dict to create index
mdFile = MdUtils('commands/index.md')
mdFile.new_header(level=1, title="Commands")
for k, v in commands.items():
    mdFile.new_header(level=2, title=f"{k}")
    items = []
    for i in v:
        info = commands_info[i]
        try:
            items.append(f' [{info["command_name"]}]({info["module"]}/{i}.md) {info["desc"]}')
        except Exception as e:
            print(f"-> {e}")

    mdFile.new_list(items=items)

mdFile.create_md_file()
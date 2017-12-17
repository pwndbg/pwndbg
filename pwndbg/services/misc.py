import pwndbg.commands


def pwndbg_list_and_filter_commands(filter_pattern):
    sorted_commands = list(pwndbg.commands.Command.commands)
    sorted_commands.sort(key=lambda x: x.__name__)

    if filter_pattern:
        filter_pattern = filter_pattern.lower()

    results = []

    for c in sorted_commands:
        name = c.__name__
        docs = c.__doc__

        if docs: docs = docs.strip()
        if docs: docs = docs.splitlines()[0]

        if not filter_pattern or filter_pattern in name.lower() or (docs and filter_pattern in docs.lower()):
            results.append((name, docs))

    return results

"""
Parsing for the XML tables served by the GDB remote protocol's
``qXfer:osdata:read`` packets (the machinery behind ``info os``).

Pure text processing - no debugger or procfs access - so it can be unit
tested anywhere. The packet-transfer side lives one layer up, next to the
rest of the debugger integration.

The document format (see gdb/features/osdata.dtd) is::

    <osdata type="files">
      <item>
        <column name="pid">4242</column>
        <column name="command">cat</column>
        <column name="file descriptor">0</column>
        <column name="name">pipe:[1103727]</column>
      </item>
      ...
    </osdata>
"""

from __future__ import annotations

import xml.etree.ElementTree as ET


def parse_osdata(xml_text: str) -> list[dict[str, str]]:
    """Parse an ``<osdata>`` document into a list of {column-name: value} rows.

    Returns [] for anything that isn't a well-formed osdata document; a stub
    that doesn't know the requested table typically answers with an empty or
    error reply which never reaches this parser.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    if root.tag != "osdata":
        return []

    rows: list[dict[str, str]] = []
    for item in root.findall("item"):
        row: dict[str, str] = {}
        for column in item.findall("column"):
            name = column.get("name")
            if name is not None:
                row[name] = (column.text or "").strip()
        if row:
            rows.append(row)
    return rows


def parse_files_rows(xml_text: str) -> list[tuple[int, int, str, str]]:
    """Parse the ``files`` osdata table into (pid, fd, comm, name) tuples.

    Rows with a non-numeric pid or descriptor column are skipped.
    """
    result: list[tuple[int, int, str, str]] = []
    for row in parse_osdata(xml_text):
        try:
            pid = int(row["pid"])
            fd = int(row["file descriptor"])
        except (KeyError, ValueError):
            continue
        result.append((pid, fd, row.get("command", ""), row.get("name", "")))
    return result

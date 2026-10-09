from __future__ import annotations

from pwndbg.lib.osdata import parse_files_rows
from pwndbg.lib.osdata import parse_osdata

# Shape produced by gdb/nat/linux-osdata.c:linux_xfer_osdata_fds, which backs
# gdbserver's qXfer:osdata:read:files reply.
FILES_XML = """<osdata type="files">
<item>
<column name="pid">4242</column>
<column name="command">cat</column>
<column name="file descriptor">0</column>
<column name="name">pipe:[1103727]</column>
</item>
<item>
<column name="pid">4243</column>
<column name="command">grep</column>
<column name="file descriptor">1</column>
<column name="name">/dev/pts/0</column>
</item>
</osdata>
"""


def test_parse_osdata_files_table() -> None:
    rows = parse_osdata(FILES_XML)
    assert len(rows) == 2
    assert rows[0] == {
        "pid": "4242",
        "command": "cat",
        "file descriptor": "0",
        "name": "pipe:[1103727]",
    }


def test_parse_osdata_rejects_garbage() -> None:
    assert parse_osdata("") == []
    assert parse_osdata("not xml at all") == []
    assert parse_osdata("<notosdata></notosdata>") == []
    # Truncated transfer: broken XML must not raise.
    assert parse_osdata(FILES_XML[: len(FILES_XML) // 2]) == []


def test_parse_osdata_handles_xml_escapes() -> None:
    # readlink targets can contain XML-special characters; linux-osdata.c
    # escapes them with string_xml_appendf.
    xml = (
        '<osdata type="files"><item>'
        '<column name="pid">1</column>'
        '<column name="command">a&amp;b</column>'
        '<column name="file descriptor">3</column>'
        '<column name="name">/tmp/&lt;x&gt;</column>'
        "</item></osdata>"
    )
    rows = parse_osdata(xml)
    assert rows == [{"pid": "1", "command": "a&b", "file descriptor": "3", "name": "/tmp/<x>"}]


def test_parse_files_rows() -> None:
    rows = parse_files_rows(FILES_XML)
    assert rows == [
        (4242, 0, "cat", "pipe:[1103727]"),
        (4243, 1, "grep", "/dev/pts/0"),
    ]


def test_parse_files_rows_skips_non_numeric() -> None:
    xml = (
        '<osdata type="files">'
        '<item><column name="pid">nope</column>'
        '<column name="file descriptor">3</column></item>'
        '<item><column name="pid">5</column>'
        '<column name="file descriptor">7</column></item>'
        "</osdata>"
    )
    assert parse_files_rows(xml) == [(5, 7, "", "")]

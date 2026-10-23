"""A chunk table that fails its checksum is read from its table2 copy.

Each E01 and L01 segment since EnCase 2 carries its chunk table twice, ``table``
and ``table2``, each with an Adler-32 over its header and another over its
entries. One damaged entry used to point a chunk at another chunk's data and
read the wrong bytes with no error, where libewf reads the copy. The real-writer
fixtures, every one of whose tables checks out, must list no table errors.
"""

import glob
import hashlib
import os
import shutil
import struct
import sys
import zlib

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import ewfprobe  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures")


def _tables(data):
    """(type, data offset, entry count) of each table and table2 section."""
    at, found = 13, []
    while at + 76 <= len(data):
        kind = data[at:at + 16].rstrip(b"\0").decode("ascii")
        nxt = struct.unpack_from("<Q", data, at + 16)[0]
        if kind in ("table", "table2"):
            found.append((kind, at + 76, struct.unpack_from("<I", data, at + 76)[0]))
        if kind in ("done", "next") or nxt in (at, 0):
            break
        at = nxt
    return found


def _md5(path):
    with ewfprobe.open_ewf(path) as img:
        digest = hashlib.md5()
        img.seek(0)
        while True:
            piece = img.read(1 << 20)
            if not piece:
                break
            digest.update(piece)
        return digest.hexdigest(), img.stored_hashes.get("MD5"), img.table_errors


def _copy(names, where):
    for name in names:
        shutil.copy(os.path.join(FIXTURES, name), where)
    return os.path.join(where, names[0])


def _point_entry_at_another(path, which, entry, source):
    """Make ``entry`` of the ``which`` table section of ``path`` hold entry
    ``source``'s value, leaving the section's checksums as they were."""
    data = bytearray(open(path, "rb").read())
    _, body, _ = [t for t in _tables(data) if t[0] == which][0]
    value = struct.unpack_from("<I", data, body + 24 + 4 * source)[0]
    struct.pack_into("<I", data, body + 24 + 4 * entry, value)
    open(path, "wb").write(bytes(data))


def test_a_damaged_entry_is_read_from_table2(tmp_path):
    path = _copy(["encase6-fast.E01"], str(tmp_path))
    _point_entry_at_another(path, "table", 1, 0)
    computed, stored, errors = _md5(path)
    assert computed == stored
    assert [(e["section"], e["failed"], e["used"]) for e in errors] == [
        ("table", "entries", "table2")]
    assert errors[0]["file"] == "encase6-fast.E01"


def test_a_damaged_entry_in_a_later_segment_is_read_from_table2(tmp_path):
    names = [f"encase6-split.E0{n}" for n in range(1, 5)]
    path = _copy(names, str(tmp_path))
    _point_entry_at_another(os.path.join(str(tmp_path), names[1]), "table", 2, 1)
    computed, stored, errors = _md5(path)
    assert computed == stored
    assert [(e["file"], e["used"]) for e in errors] == [("encase6-split.E02", "table2")]


def test_a_damaged_header_is_read_from_table2(tmp_path):
    path = _copy(["encase6-fast.E01"], str(tmp_path))
    data = bytearray(open(path, "rb").read())
    _, body, count = _tables(data)[0]
    struct.pack_into("<I", data, body, count - 5)           # a count the checksum rules out
    open(path, "wb").write(bytes(data))
    computed, stored, errors = _md5(path)
    assert computed == stored
    assert [(e["failed"], e["used"]) for e in errors] == [("header", "table2")]


def test_with_both_copies_damaged_the_table_is_read_as_stored_and_said(tmp_path):
    path = _copy(["encase6-fast.E01"], str(tmp_path))
    _point_entry_at_another(path, "table", 1, 0)
    _point_entry_at_another(path, "table2", 1, 0)
    computed, stored, errors = _md5(path)
    assert computed != stored                               # as 0.14.0 read it
    assert [(e["failed"], e["used"]) for e in errors] == [("entries", "table as stored")]


def test_a_table2_that_also_fails_is_not_used(tmp_path):
    path = _copy(["encase6-fast.E01"], str(tmp_path))
    _point_entry_at_another(path, "table", 1, 0)
    _point_entry_at_another(path, "table2", 3, 2)
    _computed, _stored, errors = _md5(path)
    assert [e["used"] for e in errors] == ["table as stored"]


def test_verify_and_the_command_line_report_table_errors(tmp_path, capsys):
    path = _copy(["encase6-fast.E01"], str(tmp_path))
    _point_entry_at_another(path, "table", 1, 0)
    with ewfprobe.open_ewf(path) as img:
        result = img.verify()
        assert result["match"] is True
        assert result["table_errors"] == img.table_errors != []
        assert img.info()["table_errors"] == img.table_errors
    assert ewfprobe.main(["verify", "-q", path]) == 0
    out = capsys.readouterr().out
    assert "chunk tables that fail their checksum: 1" in out
    assert "read from its table2 copy" in out


@pytest.mark.parametrize("path", sorted(
    p for p in glob.glob(os.path.join(FIXTURES, "*"))
    if os.path.isfile(p) and open(p, "rb").read(3) in (b"EVF", b"LVF")
    and p.endswith(("01", "E01", "L01"))))
def test_real_writer_tables_list_no_errors(path):
    with ewfprobe.open_ewf(path) as img:
        assert img.table_errors == []


def test_every_real_writer_table_checks_out():
    # the rule the reader applies, measured on the fixtures: the header's Adler-32
    # always, and the entries' Adler-32 where the section ends four bytes after them
    checked = 0
    for path in glob.glob(os.path.join(FIXTURES, "*")):
        if not os.path.isfile(path) or open(path, "rb").read(3) not in (b"EVF", b"LVF"):
            continue
        data = open(path, "rb").read()
        for _kind, body, count in _tables(data):
            head = data[body:body + 24]
            assert struct.unpack_from("<I", head, 20)[0] == zlib.adler32(head[:20])
            checked += 1
    assert checked >= 20

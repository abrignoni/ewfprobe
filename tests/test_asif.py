"""Tests for the ASIF reader's states and refusals.

asif-manifest.json holds the hash of what macOS read back from the committed images
(tools/make_asif_fixture.py). The small writer here builds what macOS will not write:
damaged images and states with no documented meaning.
"""

import gzip
import hashlib
import json
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ewfprobe  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
CHUNK = 32768
BLOCK = 512
FULL, UNMAPPED, BITMAP = 1 << 62, 2 << 62, 3 << 62
TABLE, BITMAP_CHUNK, DATA = 1, 2, 3


def write_asif(path, entries, *, bitmap=b"", sectors=256, version=1, flags=0,
               versions=(2, 1), second_table=None, cut=None):
    """An image of one table: ``entries`` are its first data entries."""
    out = bytearray(CHUNK * (DATA + 4))
    out[:80] = struct.pack(">4sIIIQQ16sQQIHHQ", b"shdw", version, 512, flags, 512, 1024,
                           bytes(range(16)), sectors, 2048, CHUNK, BLOCK, 0, 0)
    struct.pack_into(">QQ", out, 512, versions[0], TABLE)
    struct.pack_into(">QQ", out, 1024, versions[1],
                     TABLE if second_table is None else second_table)
    for index, entry in enumerate(entries):
        struct.pack_into(">Q", out, TABLE * CHUNK + index * 8, entry)
    if bitmap:
        struct.pack_into(">Q", out, TABLE * CHUNK + 2048 * 8, BITMAP_CHUNK)
        out[BITMAP_CHUNK * CHUNK:BITMAP_CHUNK * CHUNK + len(bitmap)] = bitmap
    for number in range(4):
        start = (DATA + number) * CHUNK
        out[start:start + CHUNK] = bytes([0x41 + number]) * CHUNK
    with open(path, "wb") as fh:
        fh.write(out[:cut] if cut else out)
    return str(path)


def read_all(path):
    image = ewfprobe.open_ewf(path)
    try:
        return image.read(image.size)
    finally:
        image.close()


def fixture(tmp_path, name):
    with open(os.path.join(FIXTURES, "asif-manifest.json"), encoding="utf-8") as fh:
        entry = json.load(fh)["images"][name]
    path = tmp_path / name
    with gzip.open(os.path.join(FIXTURES, entry["file"])) as src:
        path.write_bytes(src.read())
    return str(path), entry


def test_image_macos_wrote_reads_as_macos_read_it(tmp_path):
    path, entry = fixture(tmp_path, "asif-states.asif")
    assert set(entry["data_entry_states"]) == {"0", "1", "2", "3"}
    data = read_all(path)
    assert len(data) == entry["logical_size"]
    assert hashlib.sha256(data).hexdigest() == entry["logical_sha256"]


@pytest.mark.skipif(ewfprobe._AES is None, reason="no AES package")  # pylint: disable=protected-access
def test_encrypted_image_macos_wrote_opens_at_its_size(tmp_path):
    # macOS records the data length of an encrypted ASIF as 0
    path, entry = fixture(tmp_path, "asif-encrypted.asif")
    image = ewfprobe.open_ewf(path, password=entry["password"])
    try:
        assert image.format == ewfprobe.FORMAT_ASIF
        assert image.size == entry["logical_size"]
    finally:
        image.close()


def test_full_absent_and_unmapped_chunks(tmp_path):
    path = write_asif(tmp_path / "a.asif", [FULL | DATA, 0, UNMAPPED, FULL | (DATA + 1)],
                      sectors=256)
    data = read_all(path)
    assert data == b"A" * CHUNK + bytes(2 * CHUNK) + b"B" * CHUNK


def test_bitmap_states_read_low_bits_first(tmp_path):
    # blocks 0..3 are written, unwritten, unmapped, written
    path = write_asif(tmp_path / "a.asif", [BITMAP | DATA], bitmap=bytes([0b01100001]),
                      sectors=4)
    assert read_all(path) == (b"A" * BLOCK + bytes(2 * BLOCK) + b"A" * BLOCK)


def test_size_stops_inside_a_chunk(tmp_path):
    path = write_asif(tmp_path / "a.asif", [FULL | DATA], sectors=3)
    assert read_all(path) == b"A" * (3 * BLOCK)


def test_higher_directory_version_is_current(tmp_path):
    path = write_asif(tmp_path / "a.asif", [FULL | DATA], versions=(1, 2),
                      second_table=0, sectors=64)
    assert read_all(path) == bytes(CHUNK)


@pytest.mark.parametrize("entries, kwargs, message", [
    ([FULL], {}, "names chunk 0"),
    ([DATA], {}, "not a documented state"),
    ([UNMAPPED | DATA], {}, "not a documented state"),
    ([BITMAP | DATA], {}, "bitmap its group"),
    ([BITMAP | DATA], {"bitmap": b"\x03"}, "invalid bitmap state"),
])
def test_undocumented_states_are_refused(tmp_path, entries, kwargs, message):
    path = write_asif(tmp_path / "a.asif", entries, **kwargs)
    with pytest.raises(ewfprobe.EwfFormatError, match=message):
        read_all(path)


def test_shadow_version_is_refused(tmp_path):
    path = write_asif(tmp_path / "a.shadow", [], version=4)
    with pytest.raises(ewfprobe.EwfFormatError, match="shadow"):
        ewfprobe.open_ewf(path)


def test_unknown_flags_are_refused(tmp_path):
    path = write_asif(tmp_path / "a.asif", [], flags=1)
    with pytest.raises(ewfprobe.EwfFormatError, match="unsupported ASIF header"):
        ewfprobe.open_ewf(path)


def test_a_header_asking_for_a_huge_chunk_is_refused_on_opening(tmp_path):
    # 112 bytes that declare a 3 GiB chunk must not reach an allocation of that size
    path = tmp_path / "huge.asif"
    path.write_bytes(struct.pack(">4sIIIQQ16sQQIHHQ", b"shdw", 1, 80, 0, 80, 96,
                                 bytes(16), 8, 8, 3 << 30, 512, 0, 0).ljust(112, b"\0"))
    with pytest.raises(ewfprobe.EwfFormatError, match="chunk size"):
        ewfprobe.open_ewf(str(path))


@pytest.mark.parametrize("extents, md5, collected", [
    ("1 0 1", "a" * 32, False),         # what EnCase Imager 7.10 stores for such a folder
    ("1 0 2", "a" * 32, True),          # more than its one byte: incomplete
    ("2 0 1 1 1", "a" * 32, True),      # two extents: incomplete
    ("1 0 1", "", True),                # no recorded MD5: incomplete
    ("", "a" * 32, True),               # no extent at all: incomplete
])
def test_only_the_encase_placeholder_reads_as_not_collected(extents, md5, collected):
    values = {"p": "1", "ls": "100", "be": extents, "ha": md5}
    assert ewfprobe.LogicalEntry(("folder",), values, None).content_collected is collected


def test_equal_versions_with_different_directories_are_refused(tmp_path):
    path = write_asif(tmp_path / "a.asif", [], versions=(1, 1), second_table=2)
    with pytest.raises(ewfprobe.EwfFormatError, match="same version"):
        ewfprobe.open_ewf(path)


def test_file_cut_inside_a_stored_chunk_is_refused(tmp_path):
    path = write_asif(tmp_path / "a.asif", [FULL | DATA], cut=DATA * CHUNK + 100)
    with pytest.raises(ewfprobe.EwfIncompleteSetError, match="cut short"):
        read_all(path)

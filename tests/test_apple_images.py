"""Tests for the Apple disk image readers: UDIF (.dmg) and sparse images.

The images hdiutil writes are the independent oracle, and they are in
tests/fixtures, checked by test_reference_fixtures.py. The writers here exist for
what hdiutil will not write: damaged and unusual images the reader has to refuse,
and a sparse image long enough to need continuation headers without committing a
gigabyte. They follow the layouts measured on hdiutil's own images, so they are a
second reading of those measurements, not evidence about the format by themselves.
"""

import hashlib
import os
import plistlib
import random
import shutil
import struct
import sys
import zlib

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ewfprobe  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

ZERO, RAW, IGNORE, ZLIB, COMMENT, END = 0, 1, 2, 0x80000005, 0x7FFFFFFE, 0xFFFFFFFF


# ---------------------------------------------------- a minimal UDIF writer

def _checksum(value):
    """A type 2 (CRC32) checksum field: type, bit count, 128 bytes of value."""
    return struct.pack(">II", 2, 32) + struct.pack(">I", value) + bytes(124)


def write_udif(path, data, *, chunks=None, tables=None, segment=(1, 1), xml=True,
               trailer_sectors=None, mutate=None):
    """Write data as a UDIF image. ``tables`` is a list of block tables, each a
    list of (kind, sector count) chunks; the default is one table of zlib chunks of
    8 sectors. ``mutate`` may edit the list of entries before they are packed."""
    sectors = len(data) // 512
    if tables is None:
        per = chunks or 8
        tables = [[(ZLIB, min(per, sectors - s)) for s in range(0, sectors, per)]]
    fork = bytearray()
    blkx, part_crcs = [], []
    at = 0
    for number, table in enumerate(tables):
        start = at
        entries, stored = [], bytearray()
        for kind, count in table:
            piece = data[at * 512:(at + count) * 512]
            if kind == RAW:
                blob = piece
            elif kind == ZLIB:
                blob = zlib.compress(piece)
            else:
                blob = b""
            if blob:
                stored += piece
            entries.append([kind, 0, at - start, count, len(fork), len(blob)])
            fork += blob
            at += count
        entries.append([END, 0, at - start, 0, len(fork), 0])
        if mutate:
            mutate(number, entries)
        crc = zlib.crc32(stored)
        part_crcs.append(crc)
        span = max(e[2] + e[3] for e in entries)
        mish = struct.pack(">4sIQQQII24x", b"mish", 1, start, span, 0, 0, len(entries))
        mish += _checksum(crc) + struct.pack(">I", len(entries))
        mish += b"".join(struct.pack(">IIQQQQ", *e) for e in entries)
        blkx.append({"Name": f"table {number}", "ID": str(number), "Data": mish})
    body = plistlib.dumps({"resource-fork": {"blkx": blkx}}) if xml else b""
    with open(path, "wb") as fh:
        fh.write(fork)
        xml_offset = fh.tell()
        fh.write(body)
        master = zlib.crc32(b"".join(struct.pack(">I", c) for c in part_crcs))
        trailer = struct.pack(">4sIIIQQQQQII", b"koly", 4, 512, 1, 0, 0, len(fork), 0, 0,
                              segment[0], segment[1])
        trailer += bytes(16) + _checksum(zlib.crc32(fork))
        trailer += struct.pack(">QQ", xml_offset, len(body)) + bytes(120)
        trailer += _checksum(master)
        trailer += struct.pack(">IQ", 1, sectors if trailer_sectors is None
                               else trailer_sectors) + bytes(12)
        assert len(trailer) == 512
        fh.write(trailer)
    return str(path)


def _disk(sectors=64, seed=3):
    r = random.Random(seed)
    out = bytearray()
    for s in range(sectors):
        out += bytes(512) if s % 5 == 2 else bytes(r.randrange(256) for _ in range(512))
    return bytes(out)


def _read_all(img):
    img.seek(0)
    return img.read()


# --------------------------------------------------------------- UDIF reads

def test_a_udif_image_reads_back_the_disk_it_holds(tmp_path):
    data = _disk()
    path = write_udif(tmp_path / "a.dmg", data)
    assert ewfprobe.is_image(path)
    assert ewfprobe.apple_image_kind(path) == "UDIF"
    with ewfprobe.open_ewf(path) as img:
        assert img.format == ewfprobe.FORMAT_UDIF
        assert img.media_size == len(data) and img.sector_size == 512
        assert _read_all(img) == data
        assert img.compression_level == "zlib"
        checks = img.verify()["container_checks"]
    assert [c["what"] for c in checks] == ["data", "block table table 0", "master"]
    assert all(c["match"] for c in checks)


def test_raw_unstored_and_compressed_chunks_mix_across_tables(tmp_path):
    data = _disk(80)
    data = data[:20 * 512] + bytes(10 * 512) + data[30 * 512:]
    tables = [[(RAW, 4), (ZLIB, 16)], [(IGNORE, 10)], [(ZERO, 5), (ZLIB, 45)]]
    data = data[:30 * 512] + bytes(5 * 512) + data[35 * 512:]
    path = write_udif(tmp_path / "mix.dmg", data, tables=tables)
    with ewfprobe.open_ewf(path) as img:
        assert _read_all(img) == data
        for start, length in ((0, 1), (2047, 4096), (15 * 512 + 7, 7000), (len(data) - 3, 3)):
            img.seek(start)
            assert img.read(length) == data[start:start + length]
        assert all(c["match"] for c in img.verify()["container_checks"])


def test_comment_entries_are_skipped(tmp_path):
    data = _disk(16)

    def add_comment(_number, entries):
        entries.insert(0, [COMMENT, 0, 0, 0, 0, 0])

    path = write_udif(tmp_path / "c.dmg", data, mutate=add_comment)
    with ewfprobe.open_ewf(path) as img:
        assert _read_all(img) == data


def test_verify_reports_a_damaged_chunk(tmp_path):
    data = _disk(32)
    path = write_udif(tmp_path / "d.dmg", data, tables=[[(RAW, 16), (RAW, 16)]])
    with open(path, "r+b") as fh:
        fh.seek(100)
        byte = fh.read(1)
        fh.seek(100)
        fh.write(bytes([byte[0] ^ 0xFF]))
    with ewfprobe.open_ewf(path) as img:
        checks = {c["what"]: c["match"] for c in img.verify()["container_checks"]}
    assert checks == {"data": False, "block table table 0": False, "master": True}
    assert ewfprobe.main(["verify", "-q", path]) == 1


def test_a_corrupt_compressed_chunk_is_an_error_not_zeros(tmp_path):
    data = _disk(16)
    path = write_udif(tmp_path / "z.dmg", data)
    with open(path, "r+b") as fh:
        fh.seek(10)
        fh.write(b"\x00" * 20)
    with ewfprobe.open_ewf(path) as img:
        with pytest.raises(ewfprobe.EwfFormatError, match="could not be decompressed"):
            _read_all(img)


def test_a_chunk_that_decompresses_to_the_wrong_size_is_refused(tmp_path):
    data = _disk(16)

    def grow(_number, entries):
        entries[0][3] += 1              # claims one sector more than it holds
        for e in entries[1:]:
            e[2] += 1

    path = write_udif(tmp_path / "w.dmg", data, mutate=grow, trailer_sectors=17)
    with ewfprobe.open_ewf(path) as img:
        with pytest.raises(ewfprobe.EwfFormatError, match="decompressed to"):
            _read_all(img)


@pytest.mark.parametrize("case,match", [
    ("segmented", "segmented Apple disk image"),
    ("no_xml", "carries no XML property list"),
    ("gap", "where the previous entry ended"),
    ("table_gap", "block table 1 starts at sector 9 where the one before it ended at 8"),
    ("unknown_type", "chunk type 0x80000009"),
    ("too_big", "more than 2048"),
    ("outside", "points outside"),
    ("short_disk", "the trailer says the disk is"),
    ("empty_entry", "covers no sectors"),
])
def test_malformed_udif_images_are_refused(tmp_path, case, match):
    data = _disk(16)
    kwargs = {}
    if case == "segmented":
        kwargs["segment"] = (1, 2)
    elif case == "no_xml":
        kwargs["xml"] = False
    elif case == "gap":
        kwargs["mutate"] = lambda n, e: e[1].__setitem__(2, e[1][2] + 1)
    elif case == "table_gap":
        kwargs["tables"] = [[(ZLIB, 8)], [(ZLIB, 8)]]
    elif case == "unknown_type":
        kwargs["mutate"] = lambda n, e: e[0].__setitem__(0, 0x80000009)
    elif case == "too_big":
        data = _disk(2056)
        kwargs["tables"] = [[(ZLIB, 2049), (ZLIB, 7)]]
    elif case == "outside":
        kwargs["mutate"] = lambda n, e: e[0].__setitem__(4, 10 ** 6)
    elif case == "short_disk":
        kwargs["trailer_sectors"] = 17
    elif case == "empty_entry":
        kwargs["mutate"] = lambda n, e: e.insert(0, [ZLIB, 0, 0, 0, 0, 0])
    path = write_udif(tmp_path / f"{case}.dmg", data, **kwargs)
    if case == "table_gap":
        # rewrite the second table to start one sector late
        with open(path, "rb") as fh:
            raw = fh.read()
        trailer = raw[-512:]
        xml_offset, xml_size = struct.unpack_from(">QQ", trailer, 216)
        plist = plistlib.loads(bytes(raw[xml_offset:xml_offset + xml_size]))
        mish = bytearray(plist["resource-fork"]["blkx"][1]["Data"])
        struct.pack_into(">Q", mish, 8, 9)
        plist["resource-fork"]["blkx"][1]["Data"] = bytes(mish)
        body = plistlib.dumps(plist)
        trailer = bytearray(trailer)
        struct.pack_into(">QQ", trailer, 216, xml_offset, len(body))
        with open(path, "wb") as fh:
            fh.write(bytes(raw[:xml_offset]) + body + bytes(trailer))
    with pytest.raises(ewfprobe.EwfError, match=match):
        ewfprobe.open_ewf(path)


def test_a_udif_image_cut_short_is_refused(tmp_path):
    data = _disk(16)
    path = write_udif(tmp_path / "cut.dmg", data)
    blob = open(path, "rb").read()
    with open(path, "wb") as fh:                # drop part of the data, keep the trailer
        fh.write(blob[:5] + blob[-512:])
    with pytest.raises(ewfprobe.EwfError):
        ewfprobe.open_ewf(path)


def test_an_encrypted_image_is_recognised_and_refused(tmp_path):
    path = tmp_path / "enc.dmg"
    path.write_bytes(b"encrcdsa" + bytes(8192))
    assert ewfprobe.apple_image_kind(str(path)) == "ENCRYPTED"
    assert not ewfprobe.is_image(str(path))
    with pytest.raises(ewfprobe.EwfFormatError, match="encrypted Apple disk image"):
        ewfprobe.open_ewf(str(path))


def test_an_image_with_no_trailer_is_not_udif(tmp_path):
    path = tmp_path / "plain.dmg"                # an uncompressed read-write image
    path.write_bytes(_disk(8))
    assert ewfprobe.apple_image_kind(str(path)) is None
    assert not ewfprobe.is_image(str(path))


def test_lzfse_without_its_package_is_refused_by_name(monkeypatch):
    path = os.path.join(FIXTURES, "dmg-ulfo.dmg")
    if not os.path.exists(path):
        pytest.skip("reference fixtures absent")
    monkeypatch.setattr(ewfprobe, "liblzfse", None)
    with pytest.raises(ewfprobe.EwfFormatError, match="pyliblzfse"):
        ewfprobe.open_ewf(path)


def test_the_cli_describes_a_udif_image(tmp_path, capsys):
    path = write_udif(tmp_path / "cli.dmg", _disk(16))
    assert ewfprobe.main(["info", path]) == 0
    out = capsys.readouterr().out
    assert "format          UDIF" in out and "block tables    1" in out
    assert "data checksum   CRC32" in out
    assert ewfprobe.main(["verify", "-q", path]) == 0
    out = capsys.readouterr().out
    assert "all match" in out


# ---------------------------------------------------------------------- ADC

@pytest.mark.parametrize("stream,size,expected", [
    (b"\x82ABC", 3, b"ABC"),                                  # literal of 3
    (b"\x81AB\x00\x01", 5, b"ABABA"),                         # 3 bytes from distance 1
    (b"\x80A\x00\x00", 4, b"AAAA"),                           # overlapping copy of one byte
    (b"\x80A" + b"\x40\x00\x00", 5, b"AAAAA"),                # three-byte form, 4 bytes
    (b"\x83ABCD" + bytes([0x04 | 0, 3]), 8, b"ABCDABCD"),     # 4 bytes from distance 3
])
def test_adc_decodes(stream, size, expected):
    assert ewfprobe._adc_decompress(stream, size) == expected  # pylint: disable=protected-access


@pytest.mark.parametrize("stream", [b"\x85AB", b"\x00\x05", b"\x40\x00", b"\x00"])
def test_adc_refuses_damage(stream):
    with pytest.raises(ewfprobe.EwfFormatError):
        ewfprobe._adc_decompress(stream, 16)  # pylint: disable=protected-access


# -------------------------------------------------------- sparse image writer

def write_sparse(path, data, band_sectors=1, order=None, *, version=3, low=None,
                 sectors=None, damage=None):
    """Write data as a sparse image whose non-zero bands are stored in ``order``,
    with continuation headers once a header's slots are used, as hdiutil lays them
    out: 1,008 slots in the first header from offset 64, 1,010 in each continuation
    from offset 56, and each header naming the next."""
    band = band_sectors * 512
    total = sectors if sectors is not None else len(data) // 512
    count = -(-total // band_sectors)
    stored = order if order is not None else [
        b for b in range(count) if any(data[b * band:(b + 1) * band])]
    groups = [stored[:1008]]
    rest = stored[1008:]
    while rest:
        groups.append(rest[:1010])
        rest = rest[1010:]
    headers = []
    offset = 0
    for g in groups:
        headers.append(offset)
        offset += 4096 + len(g) * band
    out = bytearray()
    for n, g in enumerate(groups):
        following = headers[n + 1] if n + 1 < len(groups) else 0
        head = bytearray(4096)
        if n == 0:
            struct.pack_into(">4sIIII", head, 0, b"sprs", version, band_sectors, 1,
                             (total & 0xFFFFFFFF) if low is None else low)
            struct.pack_into(">QQ", head, 20, following, total)
            struct.pack_into(f">{len(g)}I", head, 64, *[b + 1 for b in g])
        else:
            struct.pack_into(">4sIIQ", head, 0, b"sprs", n - 1, 1, following)
            struct.pack_into(f">{len(g)}I", head, 56, *[b + 1 for b in g])
        out += head
        for b in g:
            out += data[b * band:(b + 1) * band].ljust(band, b"\x00")
    if damage:
        out = damage(out)
    with open(path, "wb") as fh:
        fh.write(out)
    return str(path)


def _bands_disk(bands, seed=9):
    r = random.Random(seed)
    out = bytearray()
    for b in range(bands):
        out += bytes(512) if b % 7 == 3 else bytes([r.randrange(1, 256)]) * 512
    return bytes(out)


def test_a_sparse_image_reads_back_its_disk(tmp_path):
    data = _bands_disk(40)
    order = [b for b in range(40) if b % 7 != 3]
    random.Random(1).shuffle(order)
    path = write_sparse(tmp_path / "s.sparseimage", data, order=order)
    assert ewfprobe.apple_image_kind(path) == "SPARSEIMAGE" and ewfprobe.is_image(path)
    with ewfprobe.open_ewf(path) as img:
        assert img.format == ewfprobe.FORMAT_SPARSEIMAGE
        assert _read_all(img) == data
        assert img.info()["stored_bands"] == len(order)


def test_a_sparse_image_follows_its_continuation_headers(tmp_path):
    data = _bands_disk(2500)
    order = [b for b in range(2500) if b % 7 != 3]
    random.Random(2).shuffle(order)
    path = write_sparse(tmp_path / "chain.sparseimage", data, order=order)
    with open(path, "rb") as fh:                # the fixture really has three headers
        blob = fh.read()
    assert blob.count(b"sprs") >= 3
    with ewfprobe.open_ewf(path) as img:
        assert len(img._bands) == len(order)    # pylint: disable=protected-access
        assert hashlib.sha256(_read_all(img)).digest() == hashlib.sha256(data).digest()


def test_a_sparse_image_larger_than_2_tib_keeps_its_size(tmp_path):
    sectors = (1 << 32) + 2048                  # does not fit the 32-bit field
    path = write_sparse(tmp_path / "big.sparseimage", b"", band_sectors=2048, order=[],
                        sectors=sectors)
    with ewfprobe.open_ewf(path) as img:
        assert img.media_size == sectors * 512
        img.seek(img.media_size - 4096)
        assert img.read(8192) == bytes(4096)


@pytest.mark.parametrize("case,match", [
    ("version", "version 2 sparse image"),
    ("disagree", "in one field and"),
    ("duplicate", "stored twice"),
    ("beyond", "numbered 41 of a disk of 40"),
    ("sequence", "continuation header 1 found where 0"),
    ("loop", "cannot be a header"),
])
def test_malformed_sparse_images_are_refused(tmp_path, case, match):
    data = _bands_disk(40)
    kwargs = {}
    order = [b for b in range(40) if b % 7 != 3]
    if case == "version":
        kwargs["version"] = 2
    elif case == "disagree":
        kwargs["low"] = 39
    elif case == "duplicate":
        order = order + [order[0]]
    elif case == "beyond":
        kwargs["damage"] = lambda out: out[:64] + struct.pack(">I", 41) + out[68:]
    elif case in ("sequence", "loop"):
        data = _bands_disk(1200)
        order = list(range(1200))

        def chain(out, case=case):
            out = bytearray(out)
            second = 4096 + 1008 * 512
            if case == "sequence":
                struct.pack_into(">I", out, second + 4, 1)
            else:
                struct.pack_into(">Q", out, second + 12, second)
            return bytes(out)

        kwargs["damage"] = chain
    path = write_sparse(tmp_path / f"{case}.sparseimage", data, order=order, **kwargs)
    with pytest.raises(ewfprobe.EwfError, match=match):
        ewfprobe.open_ewf(path)


def test_a_sparse_image_cut_short_is_refused(tmp_path):
    data = _bands_disk(20)
    path = write_sparse(tmp_path / "cut.sparseimage", data,
                        damage=lambda out: out[:-100])
    with pytest.raises(ewfprobe.EwfIncompleteSetError, match="cut short"):
        ewfprobe.open_ewf(path)


def test_copying_keeps_a_fixture_readable(tmp_path):
    """The reader opens an image wherever it sits: no sibling files are looked for."""
    src = os.path.join(FIXTURES, "dmg-udzo.dmg")
    if not os.path.exists(src):
        pytest.skip("reference fixtures absent")
    dst = tmp_path / "renamed.bin"
    shutil.copyfile(src, dst)
    with ewfprobe.open_ewf(str(dst)) as img:
        assert img.format == ewfprobe.FORMAT_UDIF

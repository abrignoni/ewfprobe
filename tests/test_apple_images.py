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
               trailer_sectors=None, mutate=None, relative=False, part_size=None,
               ident=b"\x11" * 16, part_mutate=None):
    """Write data as a UDIF image. ``tables`` is a list of block tables, each a
    list of (kind, sector count) chunks; the default is one table of zlib chunks of
    8 sectors. ``mutate`` may edit the list of entries before they are packed.

    ``relative`` writes each table's own base at the table's data offset and entry
    offsets relative to it, as hdiutil segment does. ``part_size`` splits the data
    fork into segments of that many bytes, the first in ``path`` and the rest in
    .dmgpart files beside it named as hdiutil names them; ``part_mutate(number,
    trailer)`` may edit a segment's trailer (a bytearray) before it is written."""
    sectors = len(data) // 512
    if tables is None:
        per = chunks or 8
        tables = [[(ZLIB, min(per, sectors - s)) for s in range(0, sectors, per)]]
    fork = bytearray()
    blkx, part_crcs = [], []
    at = 0
    for number, table in enumerate(tables):
        start = at
        base = len(fork) if relative else 0
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
            entries.append([kind, 0, at - start, count, len(fork) - base, len(blob)])
            fork += blob
            at += count
        entries.append([END, 0, at - start, 0, len(fork) - base, 0])
        if mutate:
            mutate(number, entries)
        crc = zlib.crc32(stored)
        part_crcs.append(crc)
        span = max(e[2] + e[3] for e in entries)
        mish = struct.pack(">4sIQQQII24x", b"mish", 1, start, span, base, 0, len(entries))
        mish += _checksum(crc) + struct.pack(">I", len(entries))
        mish += b"".join(struct.pack(">IIQQQQ", *e) for e in entries)
        blkx.append({"Name": f"table {number}", "ID": str(number), "Data": mish})
    body = plistlib.dumps({"resource-fork": {"blkx": blkx}}) if xml else b""
    master = zlib.crc32(b"".join(struct.pack(">I", c) for c in part_crcs))
    pieces = ([bytes(fork)] if part_size is None else
              [bytes(fork[i:i + part_size]) for i in range(0, len(fork), part_size)])
    count = len(pieces) if part_size is not None else segment[1]
    stem = str(path)[:-4] if str(path).lower().endswith(".dmg") else str(path)
    running = 0
    for n, piece in enumerate(pieces, 1):
        target = str(path) if n == 1 else f"{stem}.{n:03d}.dmgpart"
        own = body if n == 1 else plistlib.dumps({"resource-fork": {}})
        number = n if part_size is not None else segment[0]
        with open(target, "wb") as fh:
            fh.write(piece)
            xml_offset = fh.tell()
            fh.write(own)
            trailer = bytearray(struct.pack(">4sIIIQQQQQII", b"koly", 4, 512, 1, running,
                                            0, len(piece), 0, 0, number, count))
            trailer += ident + _checksum(zlib.crc32(piece))
            trailer += struct.pack(">QQ", xml_offset, len(own)) + bytes(120)
            trailer += _checksum(master)
            trailer += struct.pack(">IQ", 1, sectors if trailer_sectors is None
                                   else trailer_sectors) + bytes(12)
            assert len(trailer) == 512
            if part_mutate:
                part_mutate(n, trailer)
            fh.write(bytes(trailer))
        running += len(piece)
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
    ("segmented", "is segment 2 of 2 of a segmented Apple disk image; open its first"),
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
        kwargs["segment"] = (2, 2)
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


def test_an_encrypted_image_is_recognised_and_a_bad_header_refused(tmp_path):
    # reading encrypted images is tested in test_encrypted_images.py
    path = tmp_path / "enc.dmg"
    path.write_bytes(b"encrcdsa" + bytes(8192))
    assert ewfprobe.apple_image_kind(str(path)) == "ENCRYPTED"
    assert not ewfprobe.is_image(str(path))
    with pytest.raises(ewfprobe.EwfFormatError, match="encrcdsa version 0"):
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


# ------------------------------------------- table data offsets and segments

def _distinct_disk(sectors, seed=5):
    """Random sectors with no zero ones, so every chunk of equal length decodes to
    something different: a chunk read from the wrong place cannot pass for it."""
    r = random.Random(seed)
    return bytes(r.randrange(256) for _ in range(sectors * 512))


@pytest.mark.parametrize("tables", [
    # every chunk is 4 incompressible sectors, so each one compresses to the same
    # length and a chunk read from the wrong table decodes without an error: a reader
    # that ignores the table's data offset returns wrong bytes silently
    [[(ZLIB, 4), (ZLIB, 4)]] * 4,
    [[(ZLIB, 4), (ZLIB, 4)], [(ZLIB, 4), (ZLIB, 4)], [(RAW, 4), (ZLIB, 4)],
     [(ZLIB, 4), (RAW, 4)]],
], ids=["same-length", "mixed"])
def test_block_tables_with_their_own_base_offset_read_correctly(tmp_path, tables):
    # Every table's first chunk sits at relative offset 0, where a reader that ignores
    # the table's data offset finds the first table's chunk.
    data = _distinct_disk(32)
    path = write_udif(tmp_path / "based.dmg", data, tables=tables, relative=True)
    with ewfprobe.open_ewf(path) as img:
        assert len(img.paths) == 1
        assert _read_all(img) == data
        assert all(c["match"] for c in img.verify()["container_checks"])


def _segmented(tmp_path, name="a.dmg", sectors=96, part_size=3000, **kwargs):
    data = _distinct_disk(sectors, seed=kwargs.pop("seed", 5))
    kwargs.setdefault("relative", True)
    path = write_udif(tmp_path / name, data, part_size=part_size, **kwargs)
    return path, data


def test_a_segmented_image_reads_across_its_segments(tmp_path):
    path, data = _segmented(tmp_path)
    parts = sorted(os.listdir(tmp_path))
    assert parts[0] == "a.002.dmgpart" and parts[-1] == "a.dmg" and len(parts) > 4
    with ewfprobe.open_ewf(path) as img:
        assert img.format == ewfprobe.FORMAT_UDIF
        assert [os.path.basename(p) for p in img.paths] == \
            ["a.dmg"] + [f"a.{n:03d}.dmgpart" for n in range(2, len(parts) + 1)]
        assert _read_all(img) == data
        for start, length in ((0, 1), (2999, 2), (8191, 9000), (len(data) - 700, 700)):
            img.seek(start)
            assert img.read(length) == data[start:start + length]
        info = img.info()
        assert [s["file"] for s in info["udif"]["segments"]] == \
            [os.path.basename(p) for p in img.paths]
        checks = img.verify()["container_checks"]
    names = [c["what"] for c in checks]
    assert names[:len(parts)] == [f"data of {os.path.basename(p)}" for p in img.paths]
    assert names[-1] == "master" and all(c["match"] for c in checks)


def test_udif_segments_lists_a_set_without_reading_it(tmp_path):
    path, _data = _segmented(tmp_path)
    count = len(os.listdir(tmp_path))
    files = ewfprobe.udif_segments(path)
    assert [os.path.basename(f) for f in files] == \
        ["a.dmg"] + [f"a.{n:03d}.dmgpart" for n in range(2, count + 1)]
    single = write_udif(tmp_path / "one.dmg", _disk(16))
    assert ewfprobe.udif_segments(single) == [os.path.abspath(single)]
    with pytest.raises(ewfprobe.EwfFormatError, match="open its first segment"):
        ewfprobe.udif_segments(str(tmp_path / "a.003.dmgpart"))
    os.remove(tmp_path / "a.002.dmgpart")
    with pytest.raises(ewfprobe.EwfIncompleteSetError, match="segment 2 is not beside it"):
        ewfprobe.udif_segments(path)


def test_a_chunk_can_run_from_one_segment_into_the_next(tmp_path):
    path, data = _segmented(tmp_path, tables=[[(RAW, 16)], [(ZLIB, 8)] * 2],
                            sectors=32, part_size=5000)
    with ewfprobe.open_ewf(path) as img:
        assert len(img.paths) >= 3
        assert _read_all(img) == data


def test_a_later_segment_points_at_the_first(tmp_path):
    _segmented(tmp_path)
    with pytest.raises(ewfprobe.EwfFormatError,
                       match="a.002.dmgpart is segment 2 of .* open its first segment"):
        ewfprobe.open_ewf(str(tmp_path / "a.002.dmgpart"))


def test_a_missing_segment_is_reported_not_read_as_empty(tmp_path):
    path, _data = _segmented(tmp_path)
    os.remove(tmp_path / "a.003.dmgpart")
    with pytest.raises(ewfprobe.EwfIncompleteSetError,
                       match=r"segment 3 is not beside it \(hdiutil names them like "
                             r"a\.002\.dmgpart\)"):
        ewfprobe.open_ewf(path)


def test_segments_are_found_by_what_they_record_not_by_name(tmp_path):
    path, data = _segmented(tmp_path)
    os.rename(tmp_path / "a.002.dmgpart", tmp_path / "renamed.dmgpart")
    # another segmented image in the same folder is not taken for this one's
    _segmented(tmp_path, name="b.dmg", ident=b"\x22" * 16, seed=6)
    with ewfprobe.open_ewf(path) as img:
        assert os.path.basename(img.paths[1]) == "renamed.dmgpart"
        assert _read_all(img) == data


def test_two_files_claiming_one_segment_are_refused(tmp_path):
    path, _data = _segmented(tmp_path)
    shutil.copyfile(tmp_path / "a.002.dmgpart", tmp_path / "a copy.002.dmgpart")
    with pytest.raises(ewfprobe.EwfFormatError, match="both say they are segment 2"):
        ewfprobe.open_ewf(path)


def _poke(fmt, at, value, only=2):
    def mutate(number, trailer):
        if number == only:
            struct.pack_into(fmt, trailer, at, value)
    return mutate


@pytest.mark.parametrize("mutate,match", [
    (_poke(">Q", 16, 1), "a.002.dmgpart says its data starts at 1 in the image's data, "
                         "where the segments before it end at 3000"),
    (_poke(">Q", 492, 7), "a.002.dmgpart gives a different disk size"),
    (_poke(">I", 60, 9), "a.002.dmgpart says it is segment 2 of 9"),
    (_poke(">I", 56, 1), "both say they are segment 1"),
    (_poke(">Q", 16, 5, only=1), "the first segment says its data starts at 5"),
])
def test_malformed_segments_are_refused(tmp_path, mutate, match):
    path, _data = _segmented(tmp_path, part_mutate=mutate)
    with pytest.raises(ewfprobe.EwfFormatError, match=match):
        ewfprobe.open_ewf(path)


def test_a_segment_cut_short_is_refused(tmp_path):
    path, _data = _segmented(tmp_path)
    part = tmp_path / "a.002.dmgpart"
    blob = part.read_bytes()
    part.write_bytes(blob[:100] + blob[-512:])
    with pytest.raises(ewfprobe.EwfIncompleteSetError, match="a.002.dmgpart: the data"):
        ewfprobe.open_ewf(path)


def test_verify_names_the_damaged_segment(tmp_path):
    path, _data = _segmented(tmp_path, tables=[[(RAW, 8)] * 12])
    part = tmp_path / "a.002.dmgpart"
    blob = bytearray(part.read_bytes())
    blob[100] ^= 0xFF
    part.write_bytes(bytes(blob))
    with ewfprobe.open_ewf(path) as img:
        checks = img.verify()["container_checks"]
    failed = [c["what"] for c in checks if not c["match"]]
    assert failed == ["data of a.002.dmgpart", "block table table 0"]


def test_the_cli_describes_a_segmented_image(tmp_path, capsys):
    path, _data = _segmented(tmp_path)
    count = len(os.listdir(tmp_path))
    assert ewfprobe.main(["info", path]) == 0
    out = capsys.readouterr().out
    assert f"segments        {count} (a.dmg .. a.{count:03d}.dmgpart)" in out
    assert out.count("data checksum   CRC32") == count
    assert "(a.002.dmgpart)" in out


# ------------------------------------------------------------- sparse bundles

def write_bundle(folder, data, band, *, version=1, size=None, token=b"", backup=None,
                 bands=None, extra=None):
    """Write data as a sparse bundle with bands of ``band`` bytes, as hdiutil lays
    one out: a band that is all zeros has no file, and a band's file stops after its
    last nonzero byte rounded up to a sector. ``bands`` may give some band files'
    contents outright (name to bytes); ``extra`` adds other entries to bands/."""
    folder = str(folder)
    os.makedirs(os.path.join(folder, "bands"))
    info = {"CFBundleInfoDictionaryVersion": "6.0", "band-size": band,
            "bundle-backingstore-version": version,
            "diskimage-bundle-type": "com.apple.diskimage.sparsebundle",
            "size": len(data) if size is None else size}
    body = plistlib.dumps(info)
    for name, content in (("Info.plist", body), ("Info.bckup", backup or body),
                          ("token", token), ("lock", b"")):
        with open(os.path.join(folder, name), "wb") as fh:
            fh.write(content)
    for n in range(0, -(-len(data) // band)):
        piece = data[n * band:(n + 1) * band].rstrip(b"\0")
        if piece:
            piece += bytes(-len(piece) % 512)
            with open(os.path.join(folder, "bands", format(n, "x")), "wb") as fh:
                fh.write(piece)
    for name, content in (bands or {}).items():
        with open(os.path.join(folder, "bands", name), "wb") as fh:
            fh.write(content)
    for name, content in (extra or {}).items():
        with open(os.path.join(folder, "bands", name), "wb") as fh:
            fh.write(content)
    return folder


def _zeroed_disk(sectors=64, seed=4):
    """A disk with whole bands of zeros and zeros at band ends, the shapes that
    leave a band without a file or with a short one."""
    r = random.Random(seed)
    out = bytearray()
    for s in range(sectors):
        zero = s % 7 in (3, 4) or 20 <= s < 32
        out += bytes(512) if zero else bytes(r.randrange(1, 256) for _ in range(512))
    return bytes(out)


@pytest.mark.parametrize("band", [1536, 2048, 4096, 1 << 20])
def test_a_sparse_bundle_reads_back_its_disk(tmp_path, band):
    data = _zeroed_disk()
    path = write_bundle(tmp_path / "a.sparsebundle", data, band)
    assert ewfprobe.is_image(path)
    assert ewfprobe.apple_image_kind(path) == "SPARSEBUNDLE"
    with ewfprobe.open_ewf(path) as img:
        assert img.format == ewfprobe.FORMAT_SPARSEBUNDLE
        assert img.media_size == len(data)
        assert _read_all(img) == data
        for start, length in ((0, 1), (band - 1, 2), (1500, 9000), (len(data) - 5, 5)):
            img.seek(start)
            assert img.read(length) == data[start:start + length]
        info = img.info()["sparsebundle"]
    stored = len(os.listdir(os.path.join(path, "bands")))
    assert info["band_size"] == band and info["bands_stored"] == stored
    if band == 1536:
        assert stored < info["band_count"]      # the all-zero bands have no file


def test_a_large_sparse_bundle_names_its_bands_in_hexadecimal(tmp_path):
    band, size = 8 << 20, 6 << 30               # 768 bands, the last is 2ff
    folder = tmp_path / "big.sparsebundle"
    marks = {"0": b"\x01" * 512, "1a0": b"\x02" * 4096, "2ff": b"\x03" * 1024}
    write_bundle(folder, b"", band, size=size, bands=marks)
    with ewfprobe.open_ewf(str(folder)) as img:
        assert img.media_size == size
        img.seek(0x1A0 * band)
        assert img.read(4097) == b"\x02" * 4096 + b"\0"
        img.seek(size - band)
        assert img.read(1025) == b"\x03" * 1024 + b"\0"
        img.seek(size - 1)
        assert img.read(10) == b"\0"
        img.seek(0x1A0 * band - 1)
        assert img.read(2) == b"\0\x02"


def test_band_files_hdiutil_would_ignore_are_ignored_and_listed(tmp_path, capsys):
    data = _zeroed_disk(16, seed=8)
    band = 2048
    path = write_bundle(tmp_path / "odd.sparsebundle", data, band,
                        bands={"1": data[band:2 * band] + b"\xAA" * 512},
                        extra={"40": b"\xBB" * 512, "0A": b"\xCC" * 512,
                               "01": b"\xDD" * 512, ".DS_Store": b"x"})
    with ewfprobe.open_ewf(path) as img:
        assert _read_all(img) == data
        info = img.info()["sparsebundle"]
    assert info["bands_past_end"] == ["40"]
    assert info["bands_longer_than_a_band"] == ["1"]
    assert sorted(info["other_entries"]) == [".DS_Store", "01", "0A"]
    assert ewfprobe.main(["info", path]) == 0
    out = capsys.readouterr().out
    assert "1 band file numbered past the disk's end, not read: 40" in out
    assert "1 band file longer than a band, read to the band's end only: 1" in out
    assert "3 other entries in bands, not read" in out


def test_an_encrypted_sparse_bundle_is_recognised(tmp_path):
    # reading encrypted bundles is tested in test_encrypted_images.py
    path = write_bundle(tmp_path / "enc.sparsebundle", _zeroed_disk(8), 2048,
                        token=b"encrcdsa" + bytes(1000))
    assert ewfprobe.apple_image_kind(path) == "ENCRYPTED"
    assert not ewfprobe.is_image(path)


def test_a_folder_is_a_sparse_bundle_only_by_its_info_plist(tmp_path):
    plain = tmp_path / "plain.sparsebundle"
    plain.mkdir()
    assert ewfprobe.apple_image_kind(str(plain)) is None
    other = tmp_path / "other"
    other.mkdir()
    (other / "Info.plist").write_bytes(plistlib.dumps({"diskimage-bundle-type": "x"}))
    assert ewfprobe.apple_image_kind(str(other)) is None and not ewfprobe.is_image(str(other))
    named = write_bundle(tmp_path / "no-suffix", _zeroed_disk(8), 2048)
    assert ewfprobe.apple_image_kind(named) == "SPARSEBUNDLE"


@pytest.mark.parametrize("kwargs,match", [
    ({"version": 2}, "version 2 sparse bundle; only version 1"),
    ({"size": 4097}, "not a whole number of 512-byte sectors"),
    ({"band": 0}, "band size of 0"),
    ({"band": "8388608"}, "gives band-size as '8388608'"),
])
def test_malformed_sparse_bundles_are_refused(tmp_path, kwargs, match):
    band = kwargs.pop("band", 2048)
    folder = tmp_path / "bad.sparsebundle"
    write_bundle(folder, _zeroed_disk(8), band if isinstance(band, int) and band else 2048,
                 **kwargs)
    if not isinstance(band, int) or not band:
        info = plistlib.loads((folder / "Info.plist").read_bytes())
        info["band-size"] = band
        (folder / "Info.plist").write_bytes(plistlib.dumps(info))
    with pytest.raises(ewfprobe.EwfFormatError, match=match):
        ewfprobe.open_ewf(str(folder))


def test_a_sparse_bundle_without_its_bands_folder_is_refused(tmp_path):
    path = write_bundle(tmp_path / "gone.sparsebundle", _zeroed_disk(8), 2048)
    shutil.rmtree(os.path.join(path, "bands"))
    with pytest.raises(ewfprobe.EwfIncompleteSetError, match="has no bands folder"):
        ewfprobe.open_ewf(path)


def test_a_sparse_bundle_reports_a_backup_that_differs(tmp_path, capsys):
    path = write_bundle(tmp_path / "b.sparsebundle", _zeroed_disk(8), 2048,
                        backup=b"<plist/>")
    with ewfprobe.open_ewf(path) as img:
        assert img.info()["sparsebundle"]["backup_matches"] is False
        result = img.verify()
    assert result["match"] is None and result["container_checks"] == []
    assert ewfprobe.main(["info", path]) == 0
    assert "Info.bckup      differs from Info.plist" in capsys.readouterr().out
    assert ewfprobe.main(["verify", "-q", path]) == 0
    assert "recorded no hash" in capsys.readouterr().out


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

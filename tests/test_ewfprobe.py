"""Tests for the EWF-E01 reader.

Nothing on PyPI writes EWF, and the reference implementation is LGPL, so the
fixtures here are built by a small EWF writer that lives only in this file. The
writer is deliberately a separate program from the reader: it packs sections
and chunk tables from the format documentation, and the reader is required to
hand back the exact bytes that went in, together with the MD5 the writer stored.

That proves the reader against a second reading of the specification, which is
worth having and is not the same as proving it against evidence. A set written
by EnCase or FTK Imager is the independent oracle, and it is still outstanding.
"""

import hashlib
import os
import random
import struct
import sys
import zlib

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ewfprobe  # noqa: E402


# ----------------------------------------------------- a minimal EWF writer

def _section(out, name, payload, last=False):
    start = out.tell()
    size = ewfprobe.SECTION_SIZE + len(payload)
    nxt = start if last else start + size
    head = struct.pack("<16sQQ40s", name.encode("ascii").ljust(16, b"\x00"), nxt, size,
                       b"\x00" * 40)
    out.write(head + struct.pack("<I", zlib.adler32(head) & 0xFFFFFFFF) + payload)


def _volume(chunk_count, sectors_per_chunk, sector_size, sector_count):
    data = bytearray(1052)
    data[0] = 0x01                                        # fixed media
    struct.pack_into("<III", data, 4, chunk_count, sectors_per_chunk, sector_size)
    struct.pack_into("<Q", data, 16, sector_count)
    data[52] = 0x01                                       # compression: good
    return bytes(data)


def _header2():
    text = ("1\nmain\n"
            "c\tn\ta\te\tt\tav\tov\tm\tu\tp\n"
            "CASE-1\tEV-1\ttest image\tExaminer\tnotes here\t1.0\tTest OS\t"
            "2026 1 1 0 0 0\t2026 1 1 0 0 0\t\n")
    return zlib.compress(("﻿" + text).encode("utf-16-le"))


def _pack_chunks(chunks, compress):
    """The chunk data blob plus one table entry per chunk, offsets relative."""
    blob = bytearray()
    entries = []
    for chunk in chunks:
        rel = len(blob)
        if compress:
            packed = zlib.compress(chunk, 6)
            if len(packed) < len(chunk):
                entries.append(rel | ewfprobe._COMPRESSED_BIT)
                blob += packed
                continue
        entries.append(rel)
        blob += chunk + struct.pack("<I", zlib.adler32(chunk) & 0xFFFFFFFF)
    return bytes(blob), entries


def _table_payload(entries, base):
    head = struct.pack("<IIQI", len(entries), 0, base, 0)
    payload = head + struct.pack("<I", zlib.adler32(head) & 0xFFFFFFFF)
    body = b"".join(struct.pack("<I", e) for e in entries)
    return payload + body + struct.pack("<I", zlib.adler32(body) & 0xFFFFFFFF)


def sector_padded(data, sector_size=512):
    """A disk is a whole number of sectors, so the media is padded up to one."""
    return data + b"\x00" * (-len(data) % sector_size)


def write_ewf(folder, stem, data, *, chunk_size=1024, sector_size=512,
              compress=True, chunks_per_segment=None, stored_md5=True,
              md5_override=None, tables_per_segment=1):
    """Write ``data`` as an EWF-E01 set and return the segment paths in order.

    The content is padded to a sector boundary first, because that is what an
    acquisition of a real disk contains, and the stored hash covers the padded
    media rather than the caller's bytes.
    """
    data = sector_padded(data, sector_size)
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)] or [b""]
    per_segment = chunks_per_segment or len(chunks)
    groups = [chunks[i:i + per_segment] for i in range(0, len(chunks), per_segment)]
    sectors_per_chunk = chunk_size // sector_size
    sector_count = (len(data) + sector_size - 1) // sector_size

    paths = []
    for index, group in enumerate(groups):
        ext = f"E{index + 1:02d}"
        path = os.path.join(folder, f"{stem}.{ext}")
        paths.append(path)
        last_segment = index == len(groups) - 1
        with open(path, "wb") as out:
            out.write(struct.pack("<8sBHH", ewfprobe.SIGNATURE, 1, index + 1, 0))
            if index == 0:
                _section(out, "header2", _header2())
                _section(out, "header", zlib.compress(b"1\nmain\nc\n\n"))
                _section(out, "volume",
                         _volume(len(chunks), sectors_per_chunk, sector_size,
                                 sector_count))
            # A real acquisition writes many sectors/table pairs per segment, so
            # most tables are followed by a great deal more of the file.
            per_table = -(-len(group) // tables_per_segment)
            for j in range(0, len(group), per_table):
                blob, entries = _pack_chunks(group[j:j + per_table], compress)
                base = out.tell() + ewfprobe.SECTION_SIZE
                _section(out, "sectors", blob)
                _section(out, "table", _table_payload(entries, base))
            if last_segment:
                if stored_md5:
                    digest = md5_override or hashlib.md5(data).digest()
                    _section(out, "hash", digest + b"\x00" * 16)
                _section(out, "done", b"", last=True)
            else:
                _section(out, "next", b"", last=True)
    return paths


def sample_bytes(n_chunks=6, chunk_size=1024, tail=300, seed=7):
    """Content with compressible and incompressible chunks and a short tail."""
    rnd = random.Random(seed)
    out = bytearray()
    for i in range(n_chunks):
        if i % 2 == 0:
            out += bytes([65 + i]) * chunk_size          # compresses well
        else:
            out += bytes(rnd.randrange(256) for _ in range(chunk_size))
    out += bytes([90]) * tail
    return bytes(out)


# ------------------------------------------------------------------- tests

def test_round_trip_single_segment(tmp_path):
    data = sample_bytes()
    write_ewf(str(tmp_path), "img", data)
    with ewfprobe.open_ewf(str(tmp_path / "img.E01")) as img:
        assert img.media_size >= len(data)
        img.seek(0)
        assert img.read(len(data)) == data


def test_both_compressed_and_uncompressed_chunks_are_present(tmp_path):
    """The fixture must exercise both chunk forms, or the test proves half of it."""
    data = sample_bytes()
    write_ewf(str(tmp_path), "img", data)
    with ewfprobe.open_ewf(str(tmp_path / "img.E01")) as img:
        flags = {img._chunk_location(n)[3] for n in range(img._needed_chunks())}
    assert flags == {True, False}, f"only saw compressed={flags}"


def test_short_final_chunk(tmp_path):
    data = sample_bytes(n_chunks=2, tail=17)
    write_ewf(str(tmp_path), "img", data)
    with ewfprobe.open_ewf(str(tmp_path / "img.E01")) as img:
        img.seek(0)
        got = img.read(img.media_size)
    assert got[:len(data)] == data


def test_multi_segment_round_trip(tmp_path):
    data = sample_bytes(n_chunks=9)
    paths = write_ewf(str(tmp_path), "img", data, chunks_per_segment=2)
    assert len(paths) > 3
    with ewfprobe.open_ewf(str(tmp_path / "img.E01")) as img:
        assert len(img.paths) == len(paths)
        img.seek(0)
        assert img.read(len(data)) == data


def test_reads_across_a_segment_boundary(tmp_path):
    data = sample_bytes(n_chunks=6)
    write_ewf(str(tmp_path), "img", data, chunks_per_segment=2)
    with ewfprobe.open_ewf(str(tmp_path / "img.E01")) as img:
        img.seek(2048 - 10)                              # spans segments 1 and 2
        assert img.read(20) == data[2038:2058]


def test_random_access_matches_the_source(tmp_path):
    media = sector_padded(sample_bytes(n_chunks=8))
    write_ewf(str(tmp_path), "img", media, chunks_per_segment=3)
    rnd = random.Random(11)
    with ewfprobe.open_ewf(str(tmp_path / "img.E01")) as img:
        assert img.media_size == len(media)
        for _ in range(60):
            off = rnd.randrange(0, len(media))
            length = rnd.randrange(1, 4096)
            img.seek(off)
            assert img.read(length) == media[off:off + length], f"at {off}+{length}"


def test_an_incomplete_segment_set_is_refused(tmp_path):
    """The forensic case: a partial set must not read as a small clean image."""
    data = sample_bytes(n_chunks=9)
    paths = write_ewf(str(tmp_path), "img", data, chunks_per_segment=2)
    os.remove(paths[-1])
    with pytest.raises(ewfprobe.EwfIncompleteSetError):
        ewfprobe.open_ewf(str(tmp_path / "img.E01"))


def test_verify_matches_the_stored_hash(tmp_path):
    data = sample_bytes()
    write_ewf(str(tmp_path), "img", data)
    with ewfprobe.open_ewf(str(tmp_path / "img.E01")) as img:
        result = img.verify()
    assert result["stored"]["MD5"] == hashlib.md5(sector_padded(data)).hexdigest()
    assert result["computed"]["MD5"] == result["stored"]["MD5"]
    assert result["match"] is True


def test_verify_reports_a_mismatch(tmp_path):
    data = sample_bytes()
    write_ewf(str(tmp_path), "img", data, md5_override=b"\x01" * 16)
    with ewfprobe.open_ewf(str(tmp_path / "img.E01")) as img:
        result = img.verify()
    assert result["match"] is False


def test_uncompressed_chunk_checksum_mismatch_is_recorded(tmp_path):
    """A flipped byte in a stored chunk is reported, and the read still returns."""
    data = sample_bytes(n_chunks=2)
    write_ewf(str(tmp_path), "img", data, compress=False)
    path = tmp_path / "img.E01"
    raw = bytearray(path.read_bytes())
    # The first chunk's data sits right after the sectors section descriptor.
    marker = raw.find(b"sectors")
    body = marker + ewfprobe.SECTION_SIZE
    raw[body + 5] ^= 0xFF
    path.write_bytes(bytes(raw))
    with ewfprobe.open_ewf(str(path)) as img:
        img.seek(0)
        got = img.read(64)
        assert img.checksum_errors == [0]
    assert got != data[:64]


def test_metadata_is_parsed(tmp_path):
    write_ewf(str(tmp_path), "img", sample_bytes(n_chunks=2))
    with ewfprobe.open_ewf(str(tmp_path / "img.E01")) as img:
        meta = img.metadata
    assert meta.get("case_number") == "CASE-1"
    assert meta.get("evidence_number") == "EV-1"
    assert meta.get("examiner") == "Examiner"


def test_geometry(tmp_path):
    data = sample_bytes(n_chunks=4, tail=0)
    write_ewf(str(tmp_path), "img", data, chunk_size=1024, sector_size=512)
    with ewfprobe.open_ewf(str(tmp_path / "img.E01")) as img:
        assert img.sector_size == 512
        assert img.sectors_per_chunk == 2
        assert img.chunk_size == 1024
        assert img.media_size == len(sector_padded(data))


def test_reading_past_the_end_returns_empty(tmp_path):
    write_ewf(str(tmp_path), "img", sample_bytes(n_chunks=2))
    with ewfprobe.open_ewf(str(tmp_path / "img.E01")) as img:
        img.seek(img.media_size)
        assert img.read(100) == b""
        assert img.seek(0, os.SEEK_END) == img.media_size


def test_is_ewf_rejects_other_files(tmp_path):
    other = tmp_path / "not.E01"
    other.write_bytes(b"PK\x03\x04 this is a zip, not an acquisition")
    assert ewfprobe.is_ewf(str(other)) is False
    with pytest.raises(ewfprobe.EwfFormatError):
        ewfprobe.open_ewf(str(other))
    write_ewf(str(tmp_path), "real", sample_bytes(n_chunks=1))
    assert ewfprobe.is_ewf(str(tmp_path / "real.E01")) is True


def test_the_file_like_surface_matches_what_a_walker_expects(tmp_path):
    """qnxprobe and friends only ever use these, so they are the contract."""
    write_ewf(str(tmp_path), "img", sample_bytes(n_chunks=2))
    with ewfprobe.open_ewf(str(tmp_path / "img.E01")) as img:
        assert img.seek(10) == 10
        assert img.tell() == 10
        assert len(img.read(4)) == 4
        assert img.seekable() and img.readable() and not img.writable()
    assert img._closed


def test_cli_info_and_verify(tmp_path, capsys):
    data = sample_bytes()
    write_ewf(str(tmp_path), "img", data)
    path = str(tmp_path / "img.E01")
    assert ewfprobe.main(["info", path]) == 0
    out = capsys.readouterr().out
    assert "media size" in out and "CASE-1" in out
    assert ewfprobe.main(["verify", path, "-q"]) == 0
    assert "matches the stored hash" in capsys.readouterr().out


def test_cli_export_round_trips(tmp_path):
    data = sample_bytes()
    write_ewf(str(tmp_path), "img", data)
    out = tmp_path / "out.raw"
    assert ewfprobe.main(
        ["export", str(tmp_path / "img.E01"), "-o", str(out), "-q"]) == 0
    assert out.read_bytes()[:len(data)] == data


def test_a_chunk_read_is_bounded_by_what_a_chunk_can_hold(tmp_path):
    """The last entry of a table has no next entry to bound it, and the section
    boundary that stands in for one is the end of the segment file. Measured on a
    232.9 GiB FTK Imager set, that made 471 reads averaging 773 MB, the worst 1.47 GB,
    each to produce one 32 KiB chunk."""
    data = sample_bytes(n_chunks=64, chunk_size=1024, tail=0)
    path = write_ewf(tmp_path, "many", data, chunk_size=1024,
                     tables_per_segment=8)[0]
    with ewfprobe.open_ewf(path) as img:
        assert len(img._tables) == 8, "the fixture is not multi-table"
        bound = ewfprobe._compressed_bound(img.chunk_size)
        spans = []
        for table in img._tables:
            last = table.first_chunk + len(table.entries) // 4 - 1
            _seg, start, end, _c = img._chunk_location(last)
            spans.append(end - start)
        assert max(spans) <= bound, spans

    # and the data still comes back whole, which is what the bound must not cost
    with ewfprobe.open_ewf(path) as img:
        assert img.read(img.media_size) == sector_padded(data)


def test_the_bound_covers_a_chunk_that_does_not_compress(tmp_path):
    """Incompressible content is stored rather than deflated, which is the case the
    bound has to be generous enough for; a few bytes short would truncate a chunk."""
    rnd = random.Random(11)
    data = bytes(rnd.randrange(256) for _ in range(8192))
    packed = zlib.compress(data, 9)
    assert len(packed) >= len(data), "the fixture is meant to be incompressible"
    assert len(packed) <= ewfprobe._compressed_bound(len(data))
    path = write_ewf(tmp_path, "rand", data, chunk_size=8192, tables_per_segment=1)[0]
    with ewfprobe.open_ewf(path) as img:
        assert img.read(img.media_size) == sector_padded(data)


# ------------------------------------------------ SMART (EWF-S01), spec-written

def _smart_volume(chunk_count, sectors_per_chunk, sector_size, sector_count):
    """The original 94-byte volume section, with SMART at offset 85."""
    data = bytearray(94)
    data[0] = 0x01                                        # reserved, not a media type
    struct.pack_into("<IIII", data, 4, chunk_count, sectors_per_chunk, sector_size,
                     sector_count)
    data[85:90] = b"SMART"
    struct.pack_into("<I", data, 90, zlib.adler32(bytes(data[:90])) & 0xFFFFFFFF)
    return bytes(data)


def write_smart(folder, stem, data, *, chunk_size=1024, sector_size=512,
                chunks_per_segment=None, table_padding=b"\x00" * 16, level="f"):
    """Write ``data`` as an EWF-S01 set: lowercase names, a table header with no base
    offset, and the chunks inside the table section at offsets from the file start.

    ``table_padding`` fills the 16 bytes the E01 layout reads a base offset from, so a
    reader that took a base offset out of a SMART table would read the wrong place.
    """
    data = sector_padded(data, sector_size)
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
    per_segment = chunks_per_segment or len(chunks)
    groups = [chunks[i:i + per_segment] for i in range(0, len(chunks), per_segment)]
    paths = []
    for index, group in enumerate(groups):
        path = os.path.join(folder, f"{stem}.s{index + 1:02d}")
        paths.append(path)
        with open(path, "wb") as out:
            out.write(struct.pack("<8sBHH", ewfprobe.SIGNATURE, 1, index + 1, 0))
            if index == 0:
                header = ("1\nmain\nc\tn\ta\te\tt\tav\tov\tm\tu\tp\tr\n"
                          f"S-1\tE-1\tsmart test\tExaminer\t\t1.0\tTest OS\t"
                          f"2026 1 1 0 0 0\t2026 1 1 0 0 0\t0\t{level}\n\n")
                _section(out, "header", zlib.compress(header.encode("ascii")))
                _section(out, "volume", _smart_volume(
                    len(chunks), chunk_size // sector_size, sector_size,
                    len(data) // sector_size))
            start = out.tell()
            head = struct.pack("<I", len(group)) + table_padding
            head += struct.pack("<I", zlib.adler32(head) & 0xFFFFFFFF)
            first_chunk = start + ewfprobe.SECTION_SIZE + len(head) + 4 * len(group)
            packed = [zlib.compress(c, 6) for c in group]
            entries, pos = [], first_chunk
            for p in packed:
                entries.append(pos | ewfprobe._COMPRESSED_BIT)
                pos += len(p)
            body = b"".join(struct.pack("<I", e) for e in entries)
            _section(out, "table", head + body + b"".join(packed))
            if index == len(groups) - 1:
                _section(out, "hash", hashlib.md5(data).digest() + b"\x00" * 16)
                _section(out, "done", b"", last=True)
            else:
                _section(out, "next", b"", last=True)
    return paths


def test_smart_round_trip_across_segments(tmp_path):
    data = sample_bytes(n_chunks=9)
    paths = write_smart(str(tmp_path), "img", data, chunks_per_segment=2)
    assert [os.path.basename(p) for p in paths][:2] == ["img.s01", "img.s02"]
    with ewfprobe.open_ewf(paths[2]) as img:           # any member opens the set
        assert img.format == ewfprobe.FORMAT_S01
        assert len(img.paths) == len(paths)
        assert img.read(len(data)) == data
        assert img.verify()["match"] is True


def test_smart_table_padding_is_not_read_as_a_base_offset(tmp_path):
    """The E01 layout reads a 64-bit base offset from bytes 8 to 16 of the table
    header; in SMART those bytes are padding. Junk there must change nothing."""
    data = sample_bytes(n_chunks=4)
    path = write_smart(str(tmp_path), "img", data,
                       table_padding=b"\xa5" * 16)[0]
    with ewfprobe.open_ewf(path) as img:
        assert {t.base for t in img._tables} == {0}
        assert img.read(len(data)) == data


def test_smart_reports_what_its_volume_section_does_not_record(tmp_path):
    """Byte 0 of a SMART volume is a reserved 1, which the E01 layout would print
    as fixed media; the compression level comes from the header's r value."""
    path = write_smart(str(tmp_path), "img", sample_bytes(n_chunks=2), level="b")[0]
    with ewfprobe.open_ewf(path) as img:
        assert img.media_type is None
        assert img.compression_level == "best"
        assert img.info()["format"] == "EWF-S01"


def test_an_incomplete_smart_set_is_refused(tmp_path):
    paths = write_smart(str(tmp_path), "img", sample_bytes(n_chunks=9),
                        chunks_per_segment=2)
    os.remove(paths[-1])
    with pytest.raises(ewfprobe.EwfIncompleteSetError):
        ewfprobe.open_ewf(paths[0])


def test_e01_images_still_report_their_own_format(tmp_path):
    path = write_ewf(str(tmp_path), "img", sample_bytes(n_chunks=2))[0]
    with ewfprobe.open_ewf(path) as img:
        assert img.format == ewfprobe.FORMAT_E01
        assert img.media_type == "fixed"


def test_segment_extension_sequences():
    e = list(ewfprobe._extension_sequence("E"))
    s = list(ewfprobe._extension_sequence("s"))
    assert e[0] == "E01" and e[98] == "E99" and e[99] == "EAA" and e[-1] == "ZZZ"
    assert s[0] == "s01" and s[98] == "s99" and s[99] == "saa"
    # after szz the first letter advances, as the E sequence does after EZZ
    assert s[99 + 675] == "szz" and s[99 + 676] == "taa" and s[-1] == "zzz"


# ------------------------------------------------- EWF2-Ex01, spec-written

def _serialized(tags, values):
    text = "1\nmain\n" + "\t".join(tags) + "\n" + "\t".join(values) + "\n\n"
    return zlib.compress(("﻿" + text).encode("utf-16-le"))


def _v2_section(out, stype, payload, previous, flags=0):
    """Write a section's data, then its 64-byte descriptor, which follows it."""
    pad = -len(payload) % 16
    out.write(payload + b"\x00" * pad)
    here = out.tell()
    head = struct.pack("<IIQQII", stype, flags, previous, len(payload) + pad, 64, pad)
    head += b"\x00" * 16 + b"\x00" * 12
    out.write(head + struct.pack("<I", zlib.adler32(head) & 0xFFFFFFFF))
    return here


def write_ex01(folder, stem, data, *, chunk_size=1024, sector_size=512,
               chunks_per_segment=None, kinds=None, method=1, set_ids=None,
               encrypted_section=None, keys_section=False, case_values=None):
    """Write ``data`` as an EWF2-Ex01 set from the EWF2 documentation.

    ``kinds`` chooses each chunk's form: "z" deflate, "c" stored with an Adler-32,
    "p" pattern fill, "r" stored raw. By default a chunk of one repeated eight-byte
    pattern is pattern-filled, others alternate between deflate and stored.
    """
    data = sector_padded(data, sector_size)
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
    per = chunks_per_segment or len(chunks)
    groups = [chunks[i:i + per] for i in range(0, len(chunks), per)]
    paths, number = [], 0
    for index, group in enumerate(groups):
        path = os.path.join(folder, f"{stem}.Ex{index + 1:02d}")
        paths.append(path)
        set_id = (set_ids[index] if set_ids else b"\x11" * 16)
        with open(path, "wb") as out:
            out.write(struct.pack("<8sBBHI16s", ewfprobe.SIGNATURE_V2, 2, 1, method,
                                  index + 1, set_id))
            prev = 0
            prev = _v2_section(out, 1, _serialized(
                ["sn", "md", "lb", "ts", "dt", "bp", "ph"],
                ["", "Test drive", "", str(len(data) // sector_size), "f",
                 str(sector_size), "1"]), prev)
            tags = ["nm", "cn", "en", "ex", "nt", "av", "os", "tt", "at", "tb", "cp",
                    "sb", "gr"]
            values = case_values or ["ex01 test", "CASE-2", "EV-2", "Examiner", "",
                                     "1.0", "Test OS", "1767225600", "1767225600",
                                     str(len(chunks)), "1",
                                     str(chunk_size // sector_size), "64"]
            prev = _v2_section(out, 2, _serialized(tags, values), prev,
                               flags=2 if encrypted_section == 2 else 0)
            blob_start = out.tell()
            blob, entries = bytearray(), []
            for chunk in group:
                kind = kinds[number] if kinds else None
                if kind is None:
                    if chunk[:8] * (len(chunk) // 8) == chunk:
                        kind = "p"
                    else:
                        kind = "z" if number % 2 == 0 else "c"
                if kind == "p":
                    entries.append((struct.unpack("<Q", chunk[:8])[0], 0, 0x05))
                elif kind == "z":
                    packed = zlib.compress(chunk, 6)
                    entries.append((blob_start + len(blob), len(packed), 0x01))
                    blob += packed + b"\x00" * (-len(packed) % 16)
                elif kind == "c":
                    stored = chunk + struct.pack("<I", zlib.adler32(chunk) & 0xFFFFFFFF)
                    entries.append((blob_start + len(blob), len(stored), 0x02))
                    blob += stored + b"\x00" * (-len(stored) % 16)
                else:
                    entries.append((blob_start + len(blob), len(chunk), 0x00))
                    blob += chunk + b"\x00" * (-len(chunk) % 16)
                number += 1
            prev = _v2_section(out, 3, bytes(blob), prev)
            head = struct.pack("<QII", number - len(group), len(group), 0)
            head += struct.pack("<I", zlib.adler32(head) & 0xFFFFFFFF) + b"\x00" * 12
            body = b"".join(struct.pack("<QII", *e) for e in entries)
            table = head + body + struct.pack("<I", zlib.adler32(body) & 0xFFFFFFFF)
            prev = _v2_section(out, 4, table, prev)
            if index == len(groups) - 1:
                md5 = hashlib.md5(data).digest()
                sha1 = hashlib.sha1(data).digest()
                prev = _v2_section(out, 8, md5 + struct.pack(
                    "<I", zlib.adler32(md5) & 0xFFFFFFFF), prev)
                prev = _v2_section(out, 9, sha1 + struct.pack(
                    "<I", zlib.adler32(sha1) & 0xFFFFFFFF), prev)
                if keys_section:
                    prev = _v2_section(out, 0x0B, b"\x00" * 32, prev)
                _v2_section(out, 0x0F, b"", prev)
            else:
                _v2_section(out, 0x0D, b"", prev)
    return paths


def ex01_sample(n_chunks=8, chunk_size=1024):
    """Deflatable, random and single-pattern chunks, so every chunk form occurs."""
    rnd = random.Random(21)
    out = bytearray()
    for i in range(n_chunks):
        if i % 4 == 3:
            out += b"ABCDEFGH" * (chunk_size // 8)            # pattern fill
        elif i % 2 == 0:
            out += bytes([48 + i]) * (chunk_size // 2) + bytes(rnd.randrange(256)
                                                             for _ in range(chunk_size // 2))
        else:
            out += bytes(rnd.randrange(256) for _ in range(chunk_size))
    return bytes(out)


def test_ex01_round_trip_across_segments(tmp_path):
    data = ex01_sample(n_chunks=12)
    paths = write_ex01(str(tmp_path), "img", data, chunks_per_segment=3)
    assert [os.path.basename(p) for p in paths][:2] == ["img.Ex01", "img.Ex02"]
    with ewfprobe.open_ewf(paths[1]) as img:            # any member opens the set
        assert img.format == ewfprobe.FORMAT_EX01
        assert len(img.paths) == len(paths)
        assert img.read(len(data)) == data
        result = img.verify()
    assert result["stored"] == {"MD5": hashlib.md5(data).hexdigest(),
                                "SHA1": hashlib.sha1(data).hexdigest()}
    assert result["match"] is True and result["checksum_errors"] == []


def test_ex01_every_chunk_form_reads(tmp_path):
    data = ex01_sample(n_chunks=4)
    path = write_ex01(str(tmp_path), "img", data, kinds=["z", "c", "r", "p"])[0]
    with ewfprobe.open_ewf(path) as img:
        flags = [ewfprobe._TABLE_V2_ENTRY.unpack_from(img._tables[0].entries, 16 * k)[2]
                 for k in range(4)]
        assert flags == [0x01, 0x02, 0x00, 0x05]
        assert img.read(len(data)) == data


def test_ex01_pattern_fill_comes_from_the_offset_field(tmp_path):
    """A pattern-filled chunk has no data: the offset field is the pattern. A reader
    that seeked to it would read the file header or nothing at all."""
    data = b"12345678" * 128
    path = write_ex01(str(tmp_path), "img", data, kinds=["p"])[0]
    with ewfprobe.open_ewf(path) as img:
        assert img.read() == data


def test_ex01_metadata_and_geometry(tmp_path):
    values = ["line one\x01line two", "CASE-2", "EV-2", "Examiner", "tab\x03here",
              "1.0", "Test OS", "1767225600", "1767225601", "4", "1", "2", "64"]
    path = write_ex01(str(tmp_path), "img", ex01_sample(n_chunks=4),
                      case_values=values)[0]
    with ewfprobe.open_ewf(path) as img:
        assert (img.sector_size, img.sectors_per_chunk, img.chunk_size) == (512, 2, 1024)
        assert img.media_type == "fixed"
        assert img.compression_level == "deflate"
        meta = img.metadata
    assert meta["description"] == "line one\nline two"
    assert meta["notes"] == "tab\there"
    assert meta["case_number"] == "CASE-2"
    assert meta["target_time"] == "1767225600" and meta["actual_time"] == "1767225601"
    assert meta["drive_model"] == "Test drive"


def test_ex01_checksum_mismatch_is_recorded(tmp_path):
    data = ex01_sample(n_chunks=2)
    path = write_ex01(str(tmp_path), "img", data, kinds=["c", "c"])[0]
    raw = bytearray(open(path, "rb").read())
    with ewfprobe.open_ewf(path) as img:
        offset = ewfprobe._TABLE_V2_ENTRY.unpack_from(img._tables[0].entries, 0)[0]
    raw[offset + 3] ^= 0xFF
    open(path, "wb").write(bytes(raw))
    with ewfprobe.open_ewf(path) as img:
        img.read()
        assert img.checksum_errors == [0]


def test_an_incomplete_ex01_set_is_refused(tmp_path):
    paths = write_ex01(str(tmp_path), "img", ex01_sample(n_chunks=9),
                       chunks_per_segment=2)
    os.remove(paths[-1])
    with pytest.raises(ewfprobe.EwfIncompleteSetError, match="'next' section"):
        ewfprobe.open_ewf(paths[0])


def test_an_ex01_chunk_claiming_more_than_a_chunk_can_hold_is_refused(tmp_path):
    """A table whose checksum is intact can still name an absurd size, and reading
    it would pull that many bytes. The claim is refused instead."""
    path = write_ex01(str(tmp_path), "img", ex01_sample(n_chunks=2), kinds=["z", "z"])[0]
    with ewfprobe.open_ewf(path) as img:
        entries = img._tables[0].entries
    raw = bytearray(open(path, "rb").read())
    at = bytes(raw).find(entries)
    offset, _size, flags = ewfprobe._TABLE_V2_ENTRY.unpack_from(entries, 0)
    forged = ewfprobe._TABLE_V2_ENTRY.pack(offset, 1 << 30, flags) + entries[16:]
    raw[at:at + len(entries)] = forged
    struct.pack_into("<I", raw, at + len(entries), zlib.adler32(forged) & 0xFFFFFFFF)
    open(path, "wb").write(bytes(raw))
    with ewfprobe.open_ewf(path) as img:
        with pytest.raises(ewfprobe.EwfFormatError, match="more than a chunk"):
            img.read(16)


def test_ex01_segments_from_another_acquisition_are_refused(tmp_path):
    paths = write_ex01(str(tmp_path), "img", ex01_sample(n_chunks=4),
                       chunks_per_segment=2, set_ids=[b"\x11" * 16, b"\x22" * 16])
    with pytest.raises(ewfprobe.EwfFormatError, match="different acquisition"):
        ewfprobe.open_ewf(paths[0])


@pytest.mark.parametrize("kwargs", [{"encrypted_section": 2}, {"keys_section": True}])
def test_encrypted_ex01_is_refused(tmp_path, kwargs):
    path = write_ex01(str(tmp_path), "img", ex01_sample(n_chunks=2), **kwargs)[0]
    with pytest.raises(ewfprobe.EwfFormatError, match="encrypted"):
        ewfprobe.open_ewf(path)


def test_bzip2_ex01_is_refused(tmp_path):
    path = write_ex01(str(tmp_path), "img", ex01_sample(n_chunks=2), method=2)[0]
    with pytest.raises(ewfprobe.EwfFormatError, match="bzip2"):
        ewfprobe.open_ewf(path)


def test_a_corrupt_ex01_chunk_table_is_refused(tmp_path):
    path = write_ex01(str(tmp_path), "img", ex01_sample(n_chunks=4))[0]
    with ewfprobe.open_ewf(path) as img:
        entries = img._tables[0].entries
    raw = bytearray(open(path, "rb").read())
    at = bytes(raw).find(entries)
    raw[at + 9] ^= 0x40                                  # a chunk size byte
    open(path, "wb").write(bytes(raw))
    with pytest.raises(ewfprobe.EwfFormatError, match="checksum"):
        ewfprobe.open_ewf(path)


def test_logical_evidence_is_named_not_misread(tmp_path):
    for name, magic in (("x.L01", b"LVF\x09\x0d\x0a\xff\x00"),
                        ("y.Lx01", b"LEF2\r\n\x81\x00")):
        (tmp_path / name).write_bytes(magic + b"\x00" * 120)
        with pytest.raises(ewfprobe.EwfFormatError, match="logical evidence"):
            ewfprobe.open_ewf(str(tmp_path / name), segments=[str(tmp_path / name)])


def test_ex01_extension_sequence_and_detection(tmp_path):
    seq = list(ewfprobe._extension_sequence_v2())
    assert seq[0] == "Ex01" and seq[98] == "Ex99" and seq[99] == "ExAA"
    assert seq[99 + 676] == "EyAA" and seq[-1] == "EzZZ"
    assert ewfprobe._family("Ex01") == "Ex" and ewfprobe._family("EXA") == "E"
    path = write_ex01(str(tmp_path), "img", ex01_sample(n_chunks=2))[0]
    assert ewfprobe.is_ewf(path) is True

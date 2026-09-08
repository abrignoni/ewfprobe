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
              md5_override=None):
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
            blob, entries = _pack_chunks(group, compress)
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

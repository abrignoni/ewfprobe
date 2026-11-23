"""An L01's last chunk stored raw and filled to a sector is valid, and a chunk table with
no copy that passes makes ``verify()`` raise unless a stored hash of the whole matches.

Everything here is built from the committed fixtures or the synthetic L01 writer.
"""

import os
import shutil
import struct
import sys
import zlib

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import ewfprobe  # noqa: E402
import test_ewfprobe as ewf  # noqa: E402
import test_logical_verify_review as review  # noqa: E402

L01_FIXTURE = os.path.join(HERE, "fixtures", "tracy-phone-2012-07-05-1640.L01")
E01_FIXTURE = os.path.join(HERE, "fixtures", "encase6-fast.E01")


def _media(path):
    with ewfprobe.open_ewf(path) as img:
        img.seek(0)
        return img.read()


def _restore_last_chunk_raw(path):
    """Store the last chunk of the L01 at ``path`` the way a writer that does not
    compress it does: filled to a whole sector, then its Adler-32. It goes at the end
    of the file and both table copies are repointed, with their checksums made right.
    Returns (file offset of the stored chunk, bytes of it that are data, filled size)."""
    with ewfprobe.open_ewf(path) as img:
        assert len(img.paths) == 1
        last = img._needed_chunks() - 1
        want = img.media_size % img.chunk_size
        table = img._tables[-1]
        k = last - table.first_chunk
        assert (k + 1) * 4 == len(table.entries)            # the table's last entry
        entries = bytes(table.entries)
        base = table.base
        _seg, start, end, compressed = img._chunk_location(last)
        assert compressed
        with open(path, "rb") as fh:
            fh.seek(start)
            filled = zlib.decompressobj().decompress(fh.read(end - start))
        assert want < len(filled) and len(filled) % img.sector_size == 0
    with open(path, "r+b") as fh:
        at = fh.seek(0, os.SEEK_END)
        fh.write(filled + struct.pack("<I", zlib.adler32(filled) & 0xFFFFFFFF))
        patched = entries[:k * 4] + struct.pack("<I", at - base)
        patched_sum = struct.pack("<I", zlib.adler32(patched) & 0xFFFFFFFF)
        done = 0
        for _s, name, offset, size, _n in list(ewfprobe._sections(fh, path)):
            if name not in ("table", "table2"):
                continue
            fh.seek(offset + ewfprobe.TABLE_HEADER_SIZE)
            if fh.read(len(entries)) != entries:
                continue
            fh.seek(offset + ewfprobe.TABLE_HEADER_SIZE)
            fh.write(patched)
            assert size == ewfprobe.TABLE_HEADER_SIZE + len(entries) + 4
            fh.write(patched_sum)
            done += 1
    assert done == 2
    return at, want, len(filled)


@pytest.fixture
def raw_tail(tmp_path):
    path = str(tmp_path / "raw-tail.L01")
    shutil.copy(L01_FIXTURE, path)
    before = _media(path)
    at, want, filled = _restore_last_chunk_raw(path)
    assert _media(path) == before
    return path, at, want, filled, before


def _flip(path, at):
    with open(path, "r+b") as fh:
        fh.seek(at)
        value = fh.read(1)[0]
        fh.seek(at)
        fh.write(bytes([value ^ 0xFF]))


# ---------------------------------------------------------------- the last chunk

def test_a_raw_last_chunk_filled_to_a_sector_passes_verify(raw_tail, capsys):
    path, _at, _want, _filled, before = raw_tail
    with ewfprobe.open_ewf(path) as img:
        result = img.verify()
        assert result["checksum_errors"] == [] and result["padded_chunks"] == []
        assert result["entry_md5_checked"] and result["entry_md5_mismatched"] == []
    assert ewfprobe.main(["verify", "-q", path]) == 0
    assert "checksum" not in capsys.readouterr().out
    assert _media(path) == before


def test_an_entry_in_a_raw_filled_last_chunk_exports_clean(raw_tail, tmp_path, capsys):
    path = raw_tail[0]
    with ewfprobe.open_ewf(path) as img:
        last = img._needed_chunks() - 1
        entry = next(e for e in img.logical_entries if e.size and any(
            o is not None and (o + n - 1) // img.chunk_size == last
            for o, n, _fill in img._entry_runs(e)))
        wanted = img.read_entry(entry)
        name = entry.path
    out = tmp_path / "entry.bin"
    assert ewfprobe.main(["export", "-q", path, "--entry", name, "-o", str(out)]) == 0
    assert "WARNING" not in capsys.readouterr().err
    assert out.read_bytes() == wanted


@pytest.mark.parametrize("where", ["first data byte", "last data byte", "fill", "checksum"])
def test_a_flipped_byte_in_a_raw_filled_last_chunk_is_caught(raw_tail, where):
    path, at, want, filled, _before = raw_tail
    _flip(path, at + {"first data byte": 0, "last data byte": want - 1,
                      "fill": want, "checksum": filled}[where])
    with ewfprobe.open_ewf(path) as img:
        last = img._needed_chunks() - 1
        assert img.verify()["checksum_errors"] == [last]
    assert ewfprobe.main(["verify", "-q", path]) == 1


def _unfilled(tmp_path):
    """A synthetic L01 whose last chunk is shorter than a sector and stored raw with its
    Adler-32 straight after it, as the reader has always accepted."""
    data = review.NOISE[:2500]
    paths, media = ewf.write_l01(str(tmp_path), "ev", [ewf.l01_node("a", data, md5=True)])
    tail = media[2048:]
    assert 0 < len(tail) < 512
    with ewfprobe.open_ewf(paths[0]) as img:
        assert img.sector_size == 512 and img.media_size == len(media)
        _seg, start, _end, compressed = img._chunk_location(2)
        assert not compressed
    stored = open(paths[0], "rb").read()[start:start + len(tail) + 4]
    assert stored == tail + struct.pack("<I", zlib.adler32(tail) & 0xFFFFFFFF)
    return paths[0], start, media


def test_a_raw_last_chunk_with_no_fill_still_reads_and_passes(tmp_path):
    path, _start, media = _unfilled(tmp_path)
    with ewfprobe.open_ewf(path) as img:
        img.seek(0)
        assert img.read() == media
        assert img.verify()["checksum_errors"] == []
    assert ewfprobe.main(["verify", "-q", path]) == 0


def test_a_flipped_byte_in_a_raw_last_chunk_with_no_fill_is_caught(tmp_path):
    path, start, media = _unfilled(tmp_path)
    _flip(path, start + len(media) - 2048 - 1)
    with ewfprobe.open_ewf(path) as img:
        assert img.verify()["checksum_errors"] == [2]
    assert ewfprobe.main(["verify", "-q", path]) == 1


# ---------------------------------------------------------------- unproven tables

def _repoint_chunk_1(path, sections=("table", "table2")):
    """Point chunk 1 at chunk 0 in the named table sections, checksums left as stored."""
    with open(path, "r+b") as fh:
        for _s, name, offset, _size, _n in list(ewfprobe._sections(fh, path)):
            if name in sections:
                body = offset + ewfprobe.TABLE_HEADER_SIZE
                fh.seek(body)
                value = fh.read(4)
                fh.seek(body + 4)
                fh.write(value)


@pytest.fixture
def e01(tmp_path):
    path = str(tmp_path / "encase6-fast.E01")
    shutil.copy(E01_FIXTURE, path)
    return path


def test_an_unproven_table_with_no_stored_hash_raises(e01, monkeypatch):
    _repoint_chunk_1(e01)
    monkeypatch.setattr(ewfprobe.EwfImage, "_parse_hashes", lambda self, name, data: None)
    with ewfprobe.open_ewf(e01) as img:
        with pytest.raises(ewfprobe.EwfFormatError, match="no copy that passes") as caught:
            img.verify()
        result = caught.value.result
    assert result["match"] is None
    assert [e["used"] for e in result["table_errors"]] == ["table as stored"]


def test_keep_going_returns_the_result_for_an_unproven_table(e01, monkeypatch):
    _repoint_chunk_1(e01)
    monkeypatch.setattr(ewfprobe.EwfImage, "_parse_hashes", lambda self, name, data: None)
    with ewfprobe.open_ewf(e01) as img:
        result = img.verify(keep_going=True)
    assert result["match"] is None and result["table_errors"]


def test_an_unproven_table_under_a_hash_that_differs_raises(e01):
    _repoint_chunk_1(e01)
    with ewfprobe.open_ewf(e01) as img:
        with pytest.raises(ewfprobe.EwfFormatError) as caught:
            img.verify()
    assert caught.value.result["match"] is False


def test_a_matching_stored_hash_outweighs_a_bad_table_checksum(e01):
    with open(e01, "r+b") as fh:
        for _s, name, offset, size, _n in list(ewfprobe._sections(fh, e01)):
            if name in ("table", "table2"):
                fh.seek(offset + size - 4)
                value = fh.read(4)
                fh.seek(offset + size - 4)
                fh.write(bytes(b ^ 0xFF for b in value))
    with ewfprobe.open_ewf(e01) as img:
        result = img.verify()
    assert result["match"] is True
    assert {e["used"] for e in result["table_errors"]} == {"table as stored"}


def test_a_table_read_from_its_passing_copy_does_not_raise(e01, monkeypatch):
    _repoint_chunk_1(e01, sections=("table",))
    monkeypatch.setattr(ewfprobe.EwfImage, "_parse_hashes", lambda self, name, data: None)
    with ewfprobe.open_ewf(e01) as img:
        result = img.verify()
    assert result["match"] is None
    assert [e["used"] for e in result["table_errors"]] == ["table2"]

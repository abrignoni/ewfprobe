"""Damage in logical evidence must not read as success, and values no read can honour
are refused for their own entry.

Everything here is built from the committed fixtures or the synthetic writers in the
other test files. Each test names the failure it guards against.
"""

import hashlib
import os
import random
import shutil
import struct
import sys
import tracemalloc
import zlib

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import ewfprobe  # noqa: E402
import test_asif as asif  # noqa: E402
import test_ewfprobe as ewf  # noqa: E402
import test_lx01 as lx  # noqa: E402

MULTI_AD1 = os.path.join(HERE, "fixtures", "ad1", "lean-multi-ntfs-c9.ad1")
# no two chunks alike, so replacing one chunk's stream replaces only that chunk
_RANDOM = random.Random(7)
NOISE = bytes(_RANDOM.randrange(256) for _ in range(3072))


def _l01_with_stored_chunk(tmp_path, tree, media, n, stored):
    """``tree`` as an L01 of 1,024-byte chunks whose chunk ``n`` is stored as ``stored``
    in place of its zlib stream. ``media`` is the media data the tree gives."""
    chunk = media[n * 1024:(n + 1) * 1024]
    real = zlib.compress
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(zlib, "compress", lambda d, *a, **k: stored if d == chunk
                      else real(d, *a, **k))
        paths, written = ewf.write_l01(str(tmp_path), "ev", tree)
    assert written == media
    return paths[0]


def _lx01_flipped(tmp_path, at_in_chunk):
    """An Lx01 with one byte flipped in its first stored chunk, ``at_in_chunk`` bytes
    from the chunk's start (the 1,024 data bytes are followed by their Adler-32)."""
    files = lx.sample_files()
    paths = lx.write_lx01(str(tmp_path), "set", files)
    with ewfprobe.open_ewf(paths[0]) as img:
        offset = ewfprobe._TABLE_V2_ENTRY.unpack_from(img._tables[0].entries, 0)[0]
    raw = bytearray(open(paths[0], "rb").read())
    raw[offset + at_in_chunk] ^= 0xFF
    open(paths[0], "wb").write(bytes(raw))
    return paths[0], files


# ---------------------------------------------------------------- fix 1

def test_verify_fails_on_a_chunk_checksum_even_when_every_entry_hash_matches(tmp_path, capsys):
    path, _files = _lx01_flipped(tmp_path, 1024)      # the chunk's Adler-32, not its data
    with ewfprobe.open_ewf(path) as img:
        result = img.verify()
    assert result["checksum_errors"] == [0] and result["entry_md5_mismatched"] == []
    assert ewfprobe.main(["verify", "-q", path]) == 1
    assert "chunk checksum mismatches: 1" in capsys.readouterr().out


def test_verify_fails_on_a_padded_chunk_of_an_l01_with_no_hashes(tmp_path, capsys):
    data = NOISE
    path = _l01_with_stored_chunk(tmp_path, [ewf.l01_node("a", data)], b"\x00" + data, 1,
                                  zlib.compress(b"B" * 300))
    assert ewfprobe.main(["verify", "-q", path]) == 1
    assert "read with zeros in its place: 1" in capsys.readouterr().out


def test_export_writes_a_damaged_entry_warns_and_exits_nonzero(tmp_path, capsys):
    path, files = _lx01_flipped(tmp_path, 5)
    out = tmp_path / "first.bin"
    assert ewfprobe.main(["export", path, "--entry", "first.bin", "-o", str(out)]) == 1
    expected = bytearray(files[0][2])
    expected[5] ^= 0xFF
    assert out.read_bytes() == bytes(expected)
    err = capsys.readouterr().err
    assert "WARNING" in err and "chunk 0 at byte 0 fails its checksum" in err


def test_export_of_an_entry_in_clean_chunks_is_not_blamed_for_another(tmp_path, capsys):
    path, files = _lx01_flipped(tmp_path, 5)
    with ewfprobe.open_ewf(path) as img:
        img.seek(0)
        img.read()                                    # the damage is already recorded
        assert img.checksum_errors == [0]
    out = tmp_path / "second.bin"
    assert ewfprobe.main(["export", path, "--entry", "second.bin", "-o", str(out)]) == 0
    assert out.read_bytes() == files[1][2]
    assert "WARNING" not in capsys.readouterr().err


def test_export_of_the_whole_media_warns_about_a_damaged_chunk(tmp_path, capsys):
    path, _files = _lx01_flipped(tmp_path, 5)
    out = tmp_path / "media.bin"
    assert ewfprobe.main(["export", path, "-q", "-o", str(out)]) == 1
    assert "WARNING" in capsys.readouterr().err
    clean = tmp_path / "clean.bin"
    assert ewfprobe.main(["export", path, "-q", "--offset", "2048", "-o", str(clean)]) == 0


def test_export_keeps_what_precedes_a_chunk_that_cannot_be_read(tmp_path, capsys):
    data = NOISE
    path = _l01_with_stored_chunk(tmp_path, [ewf.l01_node("a", data)], b"\x00" + data, 1,
                                  b"\xff" * 20)
    out = tmp_path / "a.bin"
    assert ewfprobe.main(["export", path, "--entry", "a", "-o", str(out)]) == 2
    assert out.read_bytes() == data[:1023]            # all of chunk 0 after the root's byte
    assert "stops after 1,023" in capsys.readouterr().err


# ---------------------------------------------------------------- fix 2

def test_an_ad1_entry_with_no_hash_that_does_not_inflate_fails_verify(tmp_path, capsys):
    path = str(tmp_path / "copy.ad1")                 # without FTK Imager's log beside it
    shutil.copyfile(MULTI_AD1, path)
    with ewfprobe.open_ewf(path) as img:
        entry = next(e for e in img.logical_entries
                     if e.size and e.md5 is None and e.sha1 is None)
        target = entry.path
        start, end = img._ad1_chunks(entry)[:2]
    raw = bytearray(open(path, "rb").read())
    raw[start + 512:end + 512] = b"\xff" * (end - start)   # the file's margin is 512 bytes
    open(path, "wb").write(bytes(raw))
    assert ewfprobe.main(["verify", "-q", path]) == 1
    assert "entries that could not be read: 1" in capsys.readouterr().out
    with ewfprobe.open_ewf(path) as img:
        result = img.verify(keep_going=True)
    assert [e["path"] for e in result["entry_unreadable"]] == [target]


# ---------------------------------------------------------------- fix 3

def test_verify_tries_every_l01_entry_and_reports_each_failure(tmp_path, capsys):
    good = b"good content"
    tree = [ewf.l01_node("no hash", b"abcd", be="1 ffffff 4"),
            ewf.l01_node("with hash", b"efgh", be="1 ffffff 4", md5=True),
            ewf.l01_node("good", good, md5=True),
            ewf.l01_node("plain", b"no hash, readable")]
    paths, _media = ewf.write_l01(str(tmp_path), "ev", tree)
    with ewfprobe.open_ewf(paths[0]) as img:
        result = img.verify(keep_going=True)
    assert [e["path"] for e in result["entry_unreadable"]] == ["no hash", "with hash"]
    assert result["entry_md5_checked"] == 2           # the good one, and the failed one
    assert result["entry_md5_mismatched"] == ["with hash"]   # what an API caller reads
    assert result["entry_no_stored_hash"] >= 2
    assert ewfprobe.main(["verify", "-q", paths[0]]) == 1
    out = capsys.readouterr().out
    assert "entries that could not be read: 2" in out and "no stored hash" in out


def test_verify_reads_past_an_l01_chunk_that_does_not_inflate(tmp_path, capsys):
    first, second = NOISE, b"second entry " * 200
    tree = [ewf.l01_node("first", first), ewf.l01_node("second", second, md5=True)]
    path = _l01_with_stored_chunk(tmp_path, tree, b"\x00" + first + second, 1, b"\xff" * 20)
    with ewfprobe.open_ewf(path) as img:
        result = img.verify(keep_going=True)
    assert [c["chunk"] for c in result["unreadable_chunks"]] == [1]
    assert result["computed"] == {}                   # no hash of a whole it could not read
    assert [e["path"] for e in result["entry_unreadable"]] == ["first"]
    assert result["entry_md5_checked"] == 1 and result["entry_md5_mismatched"] == []
    assert ewfprobe.main(["verify", "-q", path]) == 1
    assert "COULD NOT BE READ" in capsys.readouterr().out


def test_a_caller_reading_only_the_older_keys_cannot_take_damage_for_a_pass(tmp_path):
    # Crush reads checksum_errors, padded_chunks and the mismatch lists. An unreadable
    # chunk or an unreadable entry with no hash is in none of them, so verify() raises,
    # after trying everything, unless the caller says it reads the new keys.
    tree = [ewf.l01_node("no hash", b"abcd", be="1 ffffff 4"),
            ewf.l01_node("good", b"good content", md5=True)]
    paths, _media = ewf.write_l01(str(tmp_path), "ev", tree)
    with ewfprobe.open_ewf(paths[0]) as img:
        with pytest.raises(ewfprobe.EwfFormatError, match="could not be read") as caught:
            img.verify()
    assert [e["path"] for e in caught.value.result["entry_unreadable"]] == ["no hash"]
    assert caught.value.result["entry_md5_checked"] == 1


def test_an_unreadable_entry_with_a_hash_shows_in_the_mismatch_list(tmp_path):
    tree = [ewf.l01_node("with hash", b"efgh", be="1 ffffff 4", md5=True)]
    paths, _media = ewf.write_l01(str(tmp_path), "ev", tree)
    with ewfprobe.open_ewf(paths[0]) as img:
        assert img.verify()["entry_md5_mismatched"] == ["with hash"]


# ---------------------------------------------------------------- fix 4

def test_verify_checks_a_recorded_sha1_beside_a_matching_md5(tmp_path, capsys):
    data = b"content with both digests"
    tree = [ewf.l01_node("both", data, md5=True, sha=hashlib.sha1(b"other").hexdigest()),
            ewf.l01_node("right", data + b"!", md5=True,
                         sha=hashlib.sha1(data + b"!").hexdigest())]
    paths, _media = ewf.write_l01(str(tmp_path), "ev", tree)
    with ewfprobe.open_ewf(paths[0]) as img:
        result = img.verify()
    assert result["entry_md5_checked"] == 2 and result["entry_md5_mismatched"] == []
    assert result["entry_sha1_checked"] == 2 and result["entry_sha1_mismatched"] == ["both"]
    assert ewfprobe.main(["verify", "-q", paths[0]]) == 1
    assert "entry SHA-1s    2 checked, 1 DO NOT MATCH" in capsys.readouterr().out


def test_verify_checks_an_entry_that_records_only_a_sha1(tmp_path):
    data = b"only a sha1"
    tree = [ewf.l01_node("sha only", data, sha=hashlib.sha1(b"not it").hexdigest())]
    paths, _media = ewf.write_l01(str(tmp_path), "ev", tree)
    with ewfprobe.open_ewf(paths[0]) as img:
        result = img.verify()
    assert result["entry_md5_checked"] == 0
    assert result["entry_sha1_checked"] == 1 and result["entry_sha1_mismatched"] == ["sha only"]
    assert ewfprobe.main(["verify", "-q", paths[0]]) == 1


# ---------------------------------------------------------------- fix 5

@pytest.mark.parametrize("values,words", [
    ({"be": "2 1 -5 1 d"}, "negative"),               # 8 bytes, reached through -5
    ({"ls": "-5"}, "negative"),
    ({"ls": ""}, "no size"),
    ({"ls": "-5", "opr": str(ewfprobe.L01_FLAG_SPARSE)}, "negative"),
    ({"ls": "", "opr": str(ewfprobe.L01_FLAG_SPARSE), "du": "1"}, "no size"),
])
def test_an_impossible_size_is_refused_for_that_entry_only(tmp_path, capsys, values, words):
    tree = [ewf.l01_node("bad", b"12345678", **values), ewf.l01_node("fine", b"readable")]
    paths, _media = ewf.write_l01(str(tmp_path), "ev", tree)
    with ewfprobe.open_ewf(paths[0]) as img:
        with pytest.raises(ewfprobe.EwfFormatError, match=words):
            img.read_entry(img.find_entry("bad"))
        assert img.read_entry(img.find_entry("fine")) == b"readable"
    assert ewfprobe.main(["verify", "-q", paths[0]]) == 1
    assert "bad" in capsys.readouterr().out


@pytest.mark.parametrize("values,expected", [
    ({"be": "2 1 0 1 8"}, b"12345678"),               # a zero-length extent first
    ({"be": "1 1 9"}, b"12345678"),                   # an extent longer than the size
    ({"ls": "", "be": "1 1 1"}, b""),                 # EnCase's empty file: one byte, no size
])
def test_valid_extent_shapes_read_as_they_did(tmp_path, values, expected):
    tree = [ewf.l01_node("f", b"12345678", **values), ewf.l01_node("after", b"xx")]
    paths, _media = ewf.write_l01(str(tmp_path), "ev", tree)
    with ewfprobe.open_ewf(paths[0]) as img:
        assert img.read_entry(img.find_entry("f")) == expected
        assert not img.verify().get("entry_unreadable")


# ---------------------------------------------------------------- fix 6

DEPTH = 4000                    # a tuple per entry would take about 64 MiB of pointers
PEAK_LIMIT = 16 << 20


def _peak(make):
    tracemalloc.start()
    try:
        kept = make()
        return kept, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_a_deep_l01_tree_costs_memory_in_its_depth_not_its_square():
    rows = []
    for level in range(DEPTH + 1):
        rows += [f"0\t{0 if level == DEPTH else 1}", f"n{level}\t\t"]
    text = "\n".join(["5", "rec", "tb", "0", "", "entry", "1\t1", "n\tls\tbe", *rows, "", ""])
    (_size, root), peak = _peak(lambda: ewfprobe._parse_ltree_text(text))
    assert peak < PEAK_LIMIT
    node = root
    while node.children:
        node = node.children[0]
    assert isinstance(node.names, tuple) and len(node.names) == DEPTH
    assert node.names[:2] == ("n1", "n2") and node.name == f"n{DEPTH}"
    assert node.path == "/".join(f"n{i}" for i in range(1, DEPTH + 1))


def test_a_deep_ad1_tree_costs_memory_in_its_depth_not_its_square():
    buffer = bytearray(16)
    addresses = []
    parent_address = 0
    for level in range(DEPTH):
        name = f"n{level}".encode()
        address = len(buffer)
        addresses.append(address)
        size = ewfprobe._AD1_ITEM.size + len(name) + 8
        child = address + size if level < DEPTH - 1 else 0
        buffer += ewfprobe._AD1_ITEM.pack(0, child, 0, 0, 0, 5, len(name))
        buffer += name + struct.pack("<Q", parent_address)
        parent_address = address
    data = bytes(buffer)
    image = ewfprobe.EwfImage.__new__(ewfprobe.EwfImage)
    image._ad1_read = lambda addr, n: data[addr:addr + n]
    image._ad1_total = len(data)

    def walk():
        root = ewfprobe.Ad1Entry((), None)
        node = root
        for address in addresses:
            entry, _next, _child = image._ad1_item(address, node, len(data))
            node.children.append(entry)
            node = entry
        return node

    deepest, peak = _peak(walk)
    assert peak < PEAK_LIMIT
    assert isinstance(deepest.names, tuple) and len(deepest.names) == DEPTH
    assert deepest.names[0] == "n0" and deepest.name == f"n{DEPTH - 1}"


def test_an_entry_built_with_its_full_names_keeps_them():
    entry = ewfprobe.LogicalEntry(("a", "b"), {"n": "b"}, None)
    assert entry.names == ("a", "b") and entry.path == "a/b" and entry.name == "b"
    assert ewfprobe.Ad1Entry(("c", "d"), None).names == ("c", "d")


# ---------------------------------------------------------------- fix 7

@pytest.mark.parametrize("bad", ["--1", "²", "٣", "1-", "+1"])
def test_a_bad_l01_time_is_kept_as_stored_with_no_parsed_time(tmp_path, bad):
    tree = [ewf.l01_node("f", b"data", cr=bad, wr="1500000000", ac="-3600")]
    paths, _media = ewf.write_l01(str(tmp_path), "ev", tree)
    with ewfprobe.open_ewf(paths[0]) as img:
        entry = img.find_entry("f")
        assert entry.values["cr"] == bad
        assert "cr" not in entry.times
        assert entry.times["wr"] == 1500000000 and entry.times["ac"] == -3600
    assert ewfprobe.main(["files", paths[0]]) == 0


# ---------------------------------------------------------------- fix 8

def _huge_asif(path, entries):
    """An ASIF of a few chunks whose header declares about 4 GiB."""
    asif.write_asif(path, entries)
    raw = bytearray(open(path, "rb").read())
    per_table = 2048 * asif.CHUNK
    maximum = 63 * per_table // asif.BLOCK
    struct.pack_into(">QQ", raw, 48, maximum, maximum)
    open(path, "wb").write(bytes(raw))
    return str(path)


@pytest.fixture
def no_full_read(monkeypatch):
    """Fails at once, where the old code would hash the whole declared disk."""
    real = ewfprobe.EwfImage.read
    spent = [0]

    def budget(self, n=-1):
        data = real(self, n)
        spent[0] += len(data)
        assert spent[0] < 16 << 20, "verify read the unallocated space"
        return data

    monkeypatch.setattr(ewfprobe.EwfImage, "read", budget)


def test_asif_verify_reads_only_what_is_allocated(tmp_path, capsys, no_full_read):
    path = _huge_asif(tmp_path / "huge.asif", [asif.FULL | asif.DATA, 0, asif.FULL | (asif.DATA + 1)])
    with ewfprobe.open_ewf(path) as img:
        assert img.media_size > 1 << 31
        result = img.verify()
    assert result["computed"] == {} and result["match"] is None
    assert result["bytes"] == 2 * asif.CHUNK and result["unreadable_chunks"] == []
    assert ewfprobe.main(["verify", "-q", path]) == 0
    out = capsys.readouterr().out
    assert "stores no hash" in out and "(none stored)" not in out


def test_asif_verify_reports_an_allocated_chunk_it_cannot_read(tmp_path, capsys, no_full_read):
    path = _huge_asif(tmp_path / "bad.asif", [asif.FULL | asif.DATA, asif.FULL | 100000])
    with ewfprobe.open_ewf(path) as img:
        result = img.verify(keep_going=True)
    assert [c["chunk"] for c in result["unreadable_chunks"]] == [1]
    assert ewfprobe.main(["verify", "-q", path]) == 1
    assert "COULD NOT BE READ" in capsys.readouterr().out


def test_asif_verify_reads_a_chunk_named_many_times_once(tmp_path, no_full_read):
    path = _huge_asif(tmp_path / "same.asif", [asif.FULL | asif.DATA] * 200)
    with ewfprobe.open_ewf(path) as img:
        assert img.verify()["bytes"] == asif.CHUNK

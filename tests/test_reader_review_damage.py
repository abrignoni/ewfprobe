"""Damage that used to read as success: an AD1 subtree the walk never reached, an L01
segment from another acquisition, an ASIF block past the end of the file behind a
shared chunk, and a chunk table with no copy that passes. Also a stored chunk too
short for its checksum, and offsets given with ``export --entry``.

Everything here is built from the committed fixtures or the synthetic writers in the
other test files.
"""

import hashlib
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
import test_asif as asif  # noqa: E402
import test_ewfprobe as ewf  # noqa: E402
import test_logical_verify_review as review  # noqa: E402
import test_lx01 as lx  # noqa: E402

AD1_DIR = os.path.join(HERE, "fixtures", "ad1")
MULTI_AD1 = os.path.join(AD1_DIR, "lean-multi-ntfs-c9.ad1")
SPLIT_AD1 = os.path.join(AD1_DIR, "lean-src-c0-1mb.ad1")
_AD1_FIRST_ITEM_FIELD = 36      # in the logical header: 16s, three I, then meta, first item


def _ad1_without_log(tmp_path):
    path = str(tmp_path / "copy.ad1")
    shutil.copy(MULTI_AD1, path)
    return path


def _patch_u64(path, at, value):
    with open(path, "r+b") as fh:
        fh.seek(at)
        fh.write(struct.pack("<Q", value))


def _ad1_with_a_sibling_cut(tmp_path):
    """A log-less AD1 with the next-sibling address of one item zeroed, and how many
    entries it had."""
    path = _ad1_without_log(tmp_path)
    with ewfprobe.open_ewf(path) as img:
        count = len(img.logical_entries)
        target = None
        for entry in img.logical_entries:
            if struct.unpack("<Q", img._ad1_read(entry.address, 8))[0]:
                target = entry.address
                break
    assert target is not None
    _patch_u64(path, ewfprobe._AD1_MARGIN + target, 0)
    return path, count


# ---------------------------------------------------------------- M1: AD1 space

def test_an_ad1_subtree_cut_off_from_the_walk_fails_verify(tmp_path, capsys):
    path, count = _ad1_with_a_sibling_cut(tmp_path)
    assert ewfprobe.main(["verify", "-q", path]) == 1
    out = capsys.readouterr().out
    with ewfprobe.open_ewf(path) as img:                    # it still opens
        assert len(img.logical_entries) < count
        result = img.verify(keep_going=True)
    assert result["logical_unreached_bytes"] > 0
    assert f"not reached from its item tree, so entries may be missing: " \
           f"{result['logical_unreached_bytes']:,}" in out


def test_verify_raises_for_an_unreached_subtree_unless_told_to_go_on(tmp_path):
    path, _count = _ad1_with_a_sibling_cut(tmp_path)
    with ewfprobe.open_ewf(path) as img, pytest.raises(ewfprobe.EwfFormatError) as caught:
        img.verify()
    assert caught.value.result["logical_unreached_bytes"] > 0
    assert "were not reached" in str(caught.value)


def test_a_first_item_address_moved_forward_does_not_hide_what_it_skips(tmp_path):
    path = _ad1_without_log(tmp_path)
    with ewfprobe.open_ewf(path) as img:
        tops = img.logical_root.children
        assert len(tops) > 1
        second = tops[1].address
    _patch_u64(path, ewfprobe._AD1_MARGIN + _AD1_FIRST_ITEM_FIELD, second)
    assert ewfprobe.main(["verify", "-q", path]) == 1
    with ewfprobe.open_ewf(path) as img:
        assert img.verify(keep_going=True)["logical_unreached_bytes"] > 0


@pytest.mark.parametrize("path", [MULTI_AD1, SPLIT_AD1], ids=["single", "four-files"])
def test_a_clean_ad1_accounts_for_every_byte(path, capsys):
    with ewfprobe.open_ewf(path) as img:
        result = img.verify()
    assert result["logical_unreached_bytes"] == 0
    assert result["logical_unreached_spans"] == []
    assert ewfprobe.main(["verify", "-q", path]) == 0
    assert "not reached" not in capsys.readouterr().out


def test_a_clean_ad1_with_no_log_beside_it_passes(tmp_path):
    path = _ad1_without_log(tmp_path)
    assert ewfprobe.main(["verify", "-q", path]) == 0


# ---------------------------------------------------------------- M2: L01 set GUID

def _plant_guid(path, section, guid):
    with open(path, "r+b") as fh:
        for _seg, name, offset, _size, _next in list(ewfprobe._sections(fh, path)):
            if name == section:
                fh.seek(offset + 64)
                fh.write(guid)
                return
    raise AssertionError(f"no {section} section")


def _two_segment_l01(tmp_path, first, second):
    paths, _media = ewf.write_l01(str(tmp_path), "ev", [ewf.l01_node("a", review.NOISE)],
                                  chunks_per_segment=2)
    assert len(paths) == 2
    _plant_guid(paths[0], "volume", first)
    _plant_guid(paths[1], "data", second)
    return paths


def test_an_l01_segment_from_another_acquisition_fails_verify(tmp_path, capsys):
    paths = _two_segment_l01(tmp_path, b"\x11" * 16, b"\x22" * 16)
    assert ewfprobe.main(["verify", "-q", paths[0]]) == 1
    assert "ev.L02 records a different acquisition than ev.L01" in capsys.readouterr().out
    with ewfprobe.open_ewf(paths[0]) as img:                # recorded, not refused
        assert img.segment_set_errors == [{"file": "ev.L02", "expected_file": "ev.L01"}]
        with pytest.raises(ewfprobe.EwfFormatError) as caught:
            img.verify()
        assert caught.value.result["segment_set_errors"] == img.segment_set_errors


def test_a_matching_stored_hash_outweighs_a_differing_set_guid(tmp_path, monkeypatch, capsys):
    # no real multi-segment L01 shows that every writer repeats this value, so an image
    # whose stored hash proves its content is reported and not failed
    paths = _two_segment_l01(tmp_path, b"\x11" * 16, b"\x22" * 16)
    with ewfprobe.open_ewf(paths[0]) as img:
        digest = hashlib.md5(img.read()).hexdigest()
    real = ewfprobe.EwfImage._index

    def with_hash(self):
        real(self)
        self.stored_hashes["MD5"] = digest

    monkeypatch.setattr(ewfprobe.EwfImage, "_index", with_hash)
    assert ewfprobe.main(["verify", "-q", paths[0]]) == 0
    assert "records a different acquisition" in capsys.readouterr().out


@pytest.mark.parametrize("extra", [[], ["--entry", "a"]], ids=["whole", "entry"])
def test_export_from_a_mismatched_set_warns_and_exits_nonzero(tmp_path, capsys, extra):
    paths = _two_segment_l01(tmp_path, b"\x11" * 16, b"\x22" * 16)
    out = tmp_path / "out.bin"
    assert ewfprobe.main(["export", "-q", paths[0], *extra, "-o", str(out)]) == 1
    assert out.stat().st_size > 0
    err = capsys.readouterr().err
    assert "WARNING" in err and "records a different acquisition" in err


@pytest.mark.parametrize("first, second", [
    (b"\x11" * 16, b"\x11" * 16),
    (bytes(16), b"\x22" * 16),
    (b"\x11" * 16, bytes(16)),
    (bytes(16), bytes(16)),
], ids=["same", "first-zero", "second-zero", "both-zero"])
def test_matching_or_zero_set_guids_pass(tmp_path, first, second):
    paths = _two_segment_l01(tmp_path, first, second)
    with ewfprobe.open_ewf(paths[0]) as img:
        assert img.segment_set_errors == []
    assert ewfprobe.main(["verify", "-q", paths[0]]) == 0
    assert ewfprobe.main(["export", "-q", paths[0], "--entry", "a",
                          "-o", str(tmp_path / "out.bin")]) == 0


def test_a_physical_e01_is_not_checked_for_a_set_guid(tmp_path):
    names = [f"encase6-split.E0{n}" for n in range(1, 5)]
    for name in names:
        shutil.copy(os.path.join(HERE, "fixtures", name), tmp_path)
    first, second = str(tmp_path / names[0]), str(tmp_path / names[1])
    _plant_guid(first, "volume", b"\x11" * 16)
    _plant_guid(second, "data", b"\x22" * 16)
    with ewfprobe.open_ewf(first) as img:
        assert img.segment_set_errors == []


# ---------------------------------------------------------------- R1: ASIF

def test_asif_verify_checks_the_blocks_of_a_shared_chunk(tmp_path, capsys):
    # both entries name the last physical chunk, of which the file holds one block:
    # the first writes block 0 and the second block 63, past the end of the file
    last = asif.DATA + 3
    bitmap = bytearray(32)
    bitmap[0] = 0b01
    bitmap[31] = 0b01 << 6
    path = asif.write_asif(tmp_path / "a.asif", [asif.BITMAP | last, asif.BITMAP | last],
                           bitmap=bytes(bitmap), sectors=128,
                           cut=last * asif.CHUNK + asif.BLOCK)
    with ewfprobe.open_ewf(path) as img:
        result = img.verify(keep_going=True)
    assert [c["chunk"] for c in result["unreadable_chunks"]] == [1]
    assert ewfprobe.main(["verify", "-q", path]) == 1
    assert "COULD NOT BE READ" in capsys.readouterr().out


def test_asif_verify_passes_a_shared_chunk_the_file_holds(tmp_path):
    bitmap = bytearray(32)
    bitmap[0] = 0b01
    bitmap[31] = 0b01 << 6
    path = asif.write_asif(tmp_path / "a.asif",
                           [asif.BITMAP | asif.DATA, asif.BITMAP | asif.DATA],
                           bitmap=bytes(bitmap), sectors=128)
    assert ewfprobe.main(["verify", "-q", path]) == 0


# ---------------------------------------------------------------- L3: both table copies

def _swap_table_entries(path, section):
    with open(path, "r+b") as fh:
        for _seg, name, offset, _size, _next in list(ewfprobe._sections(fh, path)):
            if name == section:
                fh.seek(offset + ewfprobe.TABLE_HEADER_SIZE)
                one, two = struct.unpack("<II", fh.read(8))
                fh.seek(offset + ewfprobe.TABLE_HEADER_SIZE)
                fh.write(struct.pack("<II", two, one))
                return
    raise AssertionError(f"no {section} section")


def test_a_table_with_no_passing_copy_fails_verify_and_export(tmp_path, capsys):
    paths, _media = ewf.write_l01(str(tmp_path), "ev", [ewf.l01_node("a", review.NOISE)])
    for section in ("table", "table2"):
        _swap_table_entries(paths[0], section)
    with ewfprobe.open_ewf(paths[0]) as img:
        assert img.read_entry(img.find_entry("a")) != review.NOISE     # the wrong bytes
    assert ewfprobe.main(["verify", "-q", paths[0]]) == 1
    assert "no table2 copy passes" in capsys.readouterr().out
    out = tmp_path / "a.bin"
    assert ewfprobe.main(["export", "-q", paths[0], "--entry", "a", "-o", str(out)]) == 1
    err = capsys.readouterr().err
    assert "WARNING" in err and "has no copy that passes" in err


def test_a_stored_hash_that_matches_outweighs_a_bad_table_checksum(tmp_path, capsys):
    # the entries are right and only the checksum after them is wrong in both copies
    path = str(tmp_path / "encase6-fast.E01")
    shutil.copy(os.path.join(HERE, "fixtures", "encase6-fast.E01"), path)
    with open(path, "r+b") as fh:
        for _seg, name, offset, size, _next in list(ewfprobe._sections(fh, path)):
            if name in ("table", "table2"):
                fh.seek(offset + size - 4)
                value = fh.read(4)
                fh.seek(offset + size - 4)
                fh.write(bytes(b ^ 0xFF for b in value))
    assert ewfprobe.main(["verify", "-q", path]) == 0
    out = capsys.readouterr().out
    assert "no table2 copy passes" in out and "matches the stored hash" in out


def test_a_table_read_from_its_passing_copy_is_not_damage(tmp_path):
    paths, _media = ewf.write_l01(str(tmp_path), "ev", [ewf.l01_node("a", review.NOISE)])
    _swap_table_entries(paths[0], "table")
    assert ewfprobe.main(["verify", "-q", paths[0]]) == 0
    assert ewfprobe.main(["export", "-q", paths[0], "--entry", "a",
                          "-o", str(tmp_path / "a.bin")]) == 0
    assert (tmp_path / "a.bin").read_bytes() == review.NOISE


def test_an_entry_outside_the_damaged_table_is_not_blamed(tmp_path):
    tree = [ewf.l01_node("a", review.NOISE[:2100]), ewf.l01_node("b", review.NOISE[2100:])]
    paths, _media = ewf.write_l01(str(tmp_path), "ev", tree, chunks_per_segment=2)
    with ewfprobe.open_ewf(paths[0]) as img:
        runs = img._entry_runs(img.find_entry("b"))
        assert min(o for o, _n, _f in runs) >= 2 * img.chunk_size   # all in the second table
    for section in ("table", "table2"):
        _swap_table_entries(paths[0], section)
    assert ewfprobe.main(["export", "-q", paths[0], "--entry", "b",
                          "-o", str(tmp_path / "b.bin")]) == 0
    assert (tmp_path / "b.bin").read_bytes() == review.NOISE[2100:]


# ---------------------------------------------------------------- L5: short v2 chunk

def _shorten_first_v2_chunk(path, stored):
    """Give entry 0 of the first chunk table a stored size of ``stored`` bytes, with
    the table's checksum made right again."""
    with ewfprobe.open_ewf(path) as img:
        body = bytes(img._tables[0].entries)
    _offset, _size, flags = ewfprobe._TABLE_V2_ENTRY.unpack_from(body, 0)
    assert flags == ewfprobe.V2_CHUNK_CHECKSUMED
    raw = bytearray(open(path, "rb").read())
    at = raw.find(body)
    assert at > 0
    struct.pack_into("<I", raw, at + 8, stored)         # entry 0: offset, size, flags
    struct.pack_into("<I", raw, at + len(body),
                     zlib.adler32(bytes(raw[at:at + len(body)])) & 0xFFFFFFFF)
    open(path, "wb").write(bytes(raw))


@pytest.mark.parametrize("stored", [0, 1, 3])
def test_an_lx01_chunk_too_short_for_its_checksum_is_a_format_error(tmp_path, capsys, stored):
    paths = lx.write_lx01(str(tmp_path), "set", lx.sample_files())
    _shorten_first_v2_chunk(paths[0], stored)
    out = tmp_path / "out.bin"
    assert ewfprobe.main(["export", "-q", paths[0], "-o", str(out)]) == 2
    assert "too few to hold its 4-byte checksum" in capsys.readouterr().err
    assert ewfprobe.main(["verify", "-q", paths[0]]) == 1      # goes on past the chunk
    assert "too few to hold its 4-byte checksum" in capsys.readouterr().out


@pytest.mark.parametrize("stored", [0, 1, 3])
def test_an_ex01_chunk_too_short_for_its_checksum_is_a_format_error(tmp_path, capsys, stored):
    path = str(tmp_path / "ex01-none.Ex01")
    shutil.copy(os.path.join(HERE, "fixtures", "ex01-none.Ex01"), path)
    _shorten_first_v2_chunk(path, stored)
    assert ewfprobe.main(["verify", "-q", path]) == 2
    assert "too few to hold its 4-byte checksum" in capsys.readouterr().err


# ---------------------------------------------------------------- L6: export --entry

@pytest.mark.parametrize("extra", [["--length", "50"], ["--offset", "5"],
                                   ["--offset", "5", "--length", "50"]],
                         ids=["length", "offset", "both"])
def test_export_entry_refuses_a_range(tmp_path, capsys, extra):
    paths, _media = ewf.write_l01(str(tmp_path), "ev", [ewf.l01_node("a", review.NOISE)])
    out = tmp_path / "a.bin"
    assert ewfprobe.main(["export", "-q", paths[0], "--entry", "a", *extra,
                          "-o", str(out)]) == 2
    assert not out.exists()
    assert "--offset and --length" in capsys.readouterr().err


def test_export_entry_with_no_range_writes_the_entry(tmp_path):
    paths, _media = ewf.write_l01(str(tmp_path), "ev", [ewf.l01_node("a", review.NOISE)])
    out = tmp_path / "a.bin"
    assert ewfprobe.main(["export", "-q", paths[0], "--entry", "a", "-o", str(out)]) == 0
    assert out.read_bytes() == review.NOISE

"""Lx01, EnCase's EWF2 logical evidence.

The two fixtures are real: EnCase Forensic Imager 7.10 wrote them from synthetic files,
with compression on and off. lx01-encase-imager-710.json holds the source files' sizes
and hashes, taken before the acquisition. The sets written here cover what those two
cannot: more than one segment and damaged structures.
"""
import hashlib
import json
import os
import struct
import subprocess
import sys
import zlib

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import ewfprobe  # noqa: E402

FIXTURES = os.path.join(ROOT, "tests", "fixtures")
PLAIN = os.path.join(FIXTURES, "lx01-encase-imager-710.Lx01")
STORED = os.path.join(FIXTURES, "lx01-encase-imager-710-nocomp.Lx01")
with open(os.path.join(FIXTURES, "lx01-encase-imager-710.json"), encoding="utf-8") as fh:
    KNOWN = json.load(fh)
FILES = [e for e in KNOWN["entries"] if not e["is_dir"]]
FOLDERS = [e for e in KNOWN["entries"] if e["is_dir"]]


def adler(data):
    return zlib.adler32(data) & 0xFFFFFFFF


def descriptors(data):
    """[(descriptor offset, type)] from the first section to the last."""
    out, offset = [], len(data) - 64
    while True:
        stype, _flags, previous = struct.unpack_from("<IIQ", data, offset)
        out.append((offset, stype))
        if not previous:
            return out[::-1]
        offset = previous


def edited(tmp_path, change):
    """A copy of the compressed fixture after ``change(bytearray, tree descriptor)``."""
    raw = bytearray(open(PLAIN, "rb").read())
    tree = next(o for o, t in descriptors(bytes(raw)) if t == ewfprobe.V2_SINGLE_FILES)
    change(raw, tree)
    path = tmp_path / "edited.Lx01"
    path.write_bytes(bytes(raw))
    return str(path)


def seal(raw, offset):
    raw[offset + 60:offset + 64] = struct.pack("<I", adler(bytes(raw[offset:offset + 60])))


def section(out, stype, payload, previous, flags=0, digest=None):
    pad = -len(payload) % 16
    body = payload + b"\x00" * pad
    out.write(body)
    here = out.tell()
    md5 = hashlib.md5(body).digest() if flags & 1 else b"\x00" * 16
    head = struct.pack("<IIQQII", stype, flags, previous, len(body), 64, pad)
    head += (digest or md5) + b"\x00" * 12
    out.write(head + struct.pack("<I", adler(head)))
    return here


def serialized(tags, values):
    text = "﻿1\nmain\n" + "\t".join(tags) + "\n" + "\t".join(values) + "\n\n"
    return zlib.compress(text.encode("utf-16-le"))


def tree_text(files):
    """The tree text as the Imager lays it out, for ``files``: [(name, offset, bytes)]."""
    total = sum(len(b) for _n, _o, b in files)
    columns = "p\tls\tbe\tha\tn\topr"
    lines = ["﻿5", "rec", "tb", str(total), "", "entry", "1\t1", columns,
             f"0\t{len(files)}", "1\t\t\t\tLogicalEntries\t"]
    for name, offset, content in files:
        lines += ["0\t0", f"\t{len(content)}\t1 {offset:x} {len(content):x}\t"
                  f"{hashlib.md5(content).hexdigest()}\t{name}\t4194312"]
    return "\n".join(lines) + "\n"


def write_lx01(folder, stem, files, chunks_per_segment=2, chunk=1024, method=1):
    """An Lx01 set in the Imager's section order: case data, sectors and table in each
    segment, then the tree and device information in the last."""
    media = b"".join(b for _n, _o, b in files)
    pieces = [media[i:i + chunk] for i in range(0, len(media), chunk)]
    pieces[-1] = pieces[-1].ljust(chunk, b"\x00")
    groups = [pieces[i:i + chunks_per_segment]
              for i in range(0, len(pieces), chunks_per_segment)]
    paths, first = [], 0
    for index, group in enumerate(groups):
        path = os.path.join(folder, f"{stem}.Lx{index + 1:02d}")
        paths.append(path)
        with open(path, "wb") as out:
            out.write(struct.pack("<8sBBHI16s", ewfprobe.LEF2_SIGNATURE, 2, 1, method,
                                  index + 1, b"\x22" * 16))
            prev = section(out, 2, serialized(
                ["nm", "cn", "tb", "sb"], ["x", "c", "", str(chunk // 512)]), 0)
            start = out.tell()
            blob, entries = bytearray(), []
            for piece in group:
                packed = piece + struct.pack("<I", adler(piece))
                entries.append((start + len(blob), len(packed), 2))
                blob += packed + b"\x00" * (-len(packed) % 16)
            prev = section(out, 3, bytes(blob), prev)
            head = struct.pack("<QII", first, len(group), 0)
            head += struct.pack("<I", adler(head)) + b"\x00" * 12
            body = b"".join(struct.pack("<QII", *e) for e in entries)
            prev = section(out, 4, head + body + struct.pack("<I", adler(body)), prev)
            first += len(group)
            if index == len(groups) - 1:
                text = tree_text(files).encode("utf-16-le")
                prev = section(out, 0x20, text + struct.pack("<I", adler(text)), prev, flags=1)
                prev = section(out, 1, serialized(["ts", "dt", "bp"], ["", "l", "512"]), prev)
                section(out, 0x0F, b"", prev)
            else:
                section(out, 0x0D, b"", prev)
    return paths


def sample_files():
    first = bytes(range(256)) * 10
    second = b"second file spans a segment boundary " * 120
    return [("first.bin", 0, first), ("second.bin", len(first), second)]


@pytest.mark.parametrize("path", [PLAIN, STORED], ids=["compressed", "stored"])
def test_real_lx01_reads_every_known_file(path):
    assert ewfprobe.is_logical_evidence(path) is True
    assert ewfprobe.is_image(path) is False
    assert ewfprobe.is_ewf(path) is False
    with ewfprobe.open_ewf(path) as img:
        assert img.format == ewfprobe.FORMAT_LX01
        assert img.media_type == "logical"
        assert img.chunk_size == 262144
        assert img.media_size == 69103        # the tree's tb, not whole sectors
        assert len(img.logical_entries) == len(KNOWN["entries"])
        assert {e.path for e in img.logical_entries} == {e["path"] for e in KNOWN["entries"]}
        for known in FILES:
            entry = img.find_entry(known["path"])
            content = img.read_entry(entry)
            assert entry.size == known["size"] == len(content), known["path"]
            assert hashlib.md5(content).hexdigest() == known["md5"], known["path"]
            assert hashlib.sha1(content).hexdigest() == known["sha1"], known["path"]
            assert entry.md5 == known["md5"], known["path"]
        for known in FOLDERS:
            assert img.find_entry(known["path"]).is_folder, known["path"]


def test_real_lx01_records_the_source_times():
    with ewfprobe.open_ewf(PLAIN) as img:
        times = img.find_entry("notes.txt").times
    for tag, value in KNOWN["times"]["notes.txt"].items():
        assert times[tag] == value


def test_real_lx01_duplicate_reads_the_first_copy():
    with ewfprobe.open_ewf(PLAIN) as img:
        kept, copy = img.find_entry("sub/deep/copy_b.bin"), img.find_entry("sub/copy_a.bin")
        assert copy.flags & ewfprobe.L01_FLAG_SPARSE and copy.duplicate_offset is not None
        assert copy.duplicate_offset == kept.extents[0][0]
        assert img.read_entry(copy) == img.read_entry(kept)


@pytest.mark.parametrize("path", [PLAIN, STORED], ids=["compressed", "stored"])
def test_real_lx01_verify_names_folders_it_cannot_check(path):
    with ewfprobe.open_ewf(path) as img:
        result = img.verify()
    assert result["entry_md5_checked"] == len(FILES)
    assert result["entry_md5_mismatched"] == []
    assert sorted(result["entry_content_not_collected"]) == sorted(e["path"] for e in FOLDERS)
    assert result["checksum_errors"] == [] and result["padded_chunks"] == []


def test_a_folder_whose_content_was_not_collected_is_not_read_as_empty():
    with ewfprobe.open_ewf(PLAIN) as img:
        folder = img.find_entry("sub")
        assert folder.size > 0 and folder.content_collected is False
        assert img.find_entry("notes.txt").content_collected is True
        with pytest.raises(ewfprobe.EwfFormatError, match="did not collect"):
            img.read_entry(folder)


def test_real_lx01_cli(tmp_path):
    def run(*args):
        return subprocess.run([sys.executable, os.path.join(ROOT, "ewfprobe.py"), *args],
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              encoding="utf-8", check=False)

    info = run("info", PLAIN)
    assert info.returncode == 0 and "EWF2-Lx01" in info.stdout
    listed = run("files", PLAIN)
    assert listed.returncode == 0 and "sub/deep/counter.bin" in listed.stdout
    verified = run("verify", PLAIN)
    assert verified.returncode == 0
    assert f"{len(FILES)} checked, all match" in verified.stdout
    assert f"not be checked: {len(FOLDERS)}" in verified.stdout
    out = tmp_path / "counter.bin"
    assert run("export", PLAIN, "--entry", "sub/deep/counter.bin", "-o", str(out)).returncode == 0
    known = next(e for e in FILES if e["path"] == "sub/deep/counter.bin")
    assert hashlib.sha1(out.read_bytes()).hexdigest() == known["sha1"]


def test_lx01_segments_read_from_any_of_them(tmp_path):
    files = sample_files()
    paths = write_lx01(str(tmp_path), "set", files)
    assert len(paths) > 2
    for opened in (paths[0], paths[1]):
        with ewfprobe.open_ewf(opened) as img:
            assert len(img.paths) == len(paths)
            for name, _offset, content in files:
                assert img.read_entry(img.find_entry(name)) == content


def test_lx01_extension_sequence():
    seq = list(ewfprobe._extension_sequence_v2("L"))
    assert seq[0] == "Lx01" and seq[98] == "Lx99" and seq[99] == "LxAA"
    assert seq[99 + 676] == "LyAA" and seq[-1] == "LzZZ"
    assert ewfprobe._family("Lx01") == "Lx"


def test_lx01_missing_last_segment_is_refused(tmp_path):
    paths = write_lx01(str(tmp_path), "set", sample_files())
    os.remove(paths[-1])
    with pytest.raises(ewfprobe.EwfIncompleteSetError, match="further segment"):
        ewfprobe.open_ewf(paths[0])


def test_lx01_segment_of_another_format_is_refused(tmp_path):
    paths = write_lx01(str(tmp_path), "set", sample_files())
    raw = bytearray(open(paths[1], "rb").read())
    raw[:8] = ewfprobe.SIGNATURE_V2
    open(paths[1], "wb").write(bytes(raw))
    with pytest.raises(ewfprobe.EwfFormatError, match="not an Lx01 file"):
        ewfprobe.open_ewf(paths[0])


def test_lx01_tree_failing_its_descriptor_md5_is_refused(tmp_path):
    def change(raw, tree):
        size = struct.unpack_from("<Q", raw, tree + 16)[0]
        raw[tree - size + 40] ^= 1
    with pytest.raises(ewfprobe.EwfFormatError, match="MD5"):
        ewfprobe.open_ewf(edited(tmp_path, change))


def test_lx01_tree_failing_its_adler32_is_refused(tmp_path):
    def change(raw, tree):
        size = struct.unpack_from("<Q", raw, tree + 16)[0]
        raw[tree - size + 40] ^= 1
        raw[tree + 32:tree + 48] = hashlib.md5(bytes(raw[tree - size:tree])).digest()
        seal(raw, tree)
    with pytest.raises(ewfprobe.EwfFormatError, match="Adler-32"):
        ewfprobe.open_ewf(edited(tmp_path, change))


def test_lx01_without_a_tree_is_refused(tmp_path):
    def change(raw, tree):
        raw[tree:tree + 4] = struct.pack("<I", 0x7F)
        seal(raw, tree)
    with pytest.raises(ewfprobe.EwfFormatError, match="no single files section"):
        ewfprobe.open_ewf(edited(tmp_path, change))


def test_encrypted_lx01_is_refused_by_name(tmp_path):
    def change(raw, tree):
        flags = struct.unpack_from("<I", raw, tree + 4)[0]
        raw[tree + 4:tree + 8] = struct.pack("<I", flags | ewfprobe.V2_SECTION_ENCRYPTED)
        seal(raw, tree)
    with pytest.raises(ewfprobe.EwfFormatError, match="is encrypted. Lx01 encryption"):
        ewfprobe.open_ewf(edited(tmp_path, change))


def test_bzip2_lx01_is_refused_by_name(tmp_path):
    def change(raw, _tree):
        raw[10:12] = struct.pack("<H", 2)
    with pytest.raises(ewfprobe.EwfFormatError, match="bzip2 Lx01"):
        ewfprobe.open_ewf(edited(tmp_path, change))


def test_lx01_name_on_other_bytes_is_refused(tmp_path):
    path = tmp_path / "z.Lx01"
    path.write_bytes(b"\x00" * 128)
    with pytest.raises(ewfprobe.EwfFormatError):
        ewfprobe.open_ewf(str(path))

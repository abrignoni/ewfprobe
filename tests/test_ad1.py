"""Tests for the AD1 reader, on logical images FTK Imager 4.7.3.61 wrote.

The fixtures in fixtures/ad1 were made in a Windows 11 VM (time zone UTC-4, no
daylight saving) from folders a script filled with known content;
lean_manifest.txt records every file's size, MD5, SHA-1, times in UTC and
attributes as Windows reported them before imaging. Each image sits beside FTK
Imager's log (.ad1.txt, holding the image MD5 and SHA-1) and its directory listing
(.ad1.csv, UTF-16), which names each entry's times and whether it is deleted in
FTK's own words.

  lean-src-c0-1mb           C:\\AD1Lean\\src, compression 0, 1 MB files (.ad1-.ad4)
  lean-src-c6-1mb-adcrypt   the same, compression 6, AD encryption, password
                            Ad1Test-2026! (two files)
  lean-multi-ntfs-c9        two sources in one image: the known folder on an NTFS
                            volume (U:) with an alternate data stream and a deleted
                            file, and C:\\AD1Lean\\second; compression 9

EWFPROBE_AD1_REFERENCE names a folder holding pcbje/pyad1's test_data (four files
FTK Imager 3.4.3.3 wrote, with its log); EWFPROBE_REQUIRE_AD1_REFERENCE makes its
absence a failure.
"""

import csv
import datetime
import hashlib
import io
import os
import shutil
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ewfprobe  # noqa: E402

AD1 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "ad1")
PASSWORD = "Ad1Test-2026!"
PLAIN = os.path.join(AD1, "lean-src-c0-1mb.ad1")
CRYPT = os.path.join(AD1, "lean-src-c6-1mb-adcrypt.ad1")
MULTI = os.path.join(AD1, "lean-multi-ntfs-c9.ad1")
_CRYPTO = ewfprobe._AES is not None
_CRYPTO_REQUIRED = bool(os.environ.get("EWFPROBE_REQUIRE_CRYPTO"))
needs_crypto = pytest.mark.skipif(
    not _CRYPTO and not _CRYPTO_REQUIRED,
    reason="AD-encrypted images need the optional pycryptodome package")


def _manifest():
    rows = {}
    with open(os.path.join(AD1, "lean_manifest.txt"), encoding="utf-8") as fh:
        for line in fh.read().splitlines()[2:]:
            path, size, md5, sha1, created, modified, accessed, attrs, _streams = \
                line.split("\t")
            rows[path] = {"size": int(size) if size else None, "md5": md5, "sha1": sha1,
                          "created": created, "modified": modified,
                          "accessed": accessed, "attributes": attrs}
    return rows


def _posix(text):
    """A manifest time (seven decimals, Z) as POSIX seconds cut to microseconds, the
    precision an AD1 records."""
    whole, frac = text.rstrip("Z").split(".")
    t = datetime.datetime.strptime(whole, "%Y-%m-%dT%H:%M:%S").replace(
        tzinfo=datetime.timezone.utc).timestamp()
    return t + int(frac[:6]) / 1e6


def _listing(image):
    """FTK Imager's directory listing beside ``image``: one dict per row."""
    with open(image + ".csv", "rb") as fh:
        text = fh.read().decode("utf-16")
    rows = list(csv.reader(io.StringIO(text), delimiter="\t"))
    head = [h.strip() for h in rows[0]]
    return [dict(zip(head, (c.strip() for c in r))) for r in rows[1:] if len(r) >= len(head)]


def _listed_time(text):
    if not text:
        return None
    t = datetime.datetime.strptime(text, "%Y-%b-%d %H:%M:%S.%f")
    return t.replace(tzinfo=datetime.timezone.utc).timestamp()


def _content_md5(img, entry):
    h = hashlib.md5()
    with img.open_entry(entry) as fh:
        while True:
            piece = fh.read(100_000)
            if not piece:
                return h.hexdigest()
            h.update(piece)


def _open(path, password=None):
    return ewfprobe.open_ewf(path, password=password)


def _fixtures():
    out = [(PLAIN, None, 8, 11), (MULTI, None, 9, 15)]
    out.append(pytest.param(CRYPT, PASSWORD, 8, 11, marks=needs_crypto))
    return out


@pytest.mark.parametrize("image,password,hashed,entries", _fixtures())
def test_every_fixture_verifies_against_ftk_imagers_log(image, password, hashed, entries):
    with _open(image, password) as img:
        assert img.format == ewfprobe.FORMAT_AD1
        assert len(img.logical_entries) == entries
        assert img.ad1["log"] == os.path.basename(image) + ".txt"
        result = img.verify()
    assert result["match"] is True
    assert set(result["computed"]) == {"MD5", "SHA1"}
    assert result["computed"] == result["stored"]
    assert result["entry_md5_checked"] == result["entry_sha1_checked"] == hashed
    assert result["entry_md5_mismatched"] == result["entry_sha1_mismatched"] == []


def _known(image, path):
    """The manifest path of the file an entry holds, or None for an entry the script
    did not write: the sources' own items, the stream and the deleted file."""
    if image != MULTI:
        return "C:\\AD1Lean\\src\\" + path.replace("/", "\\")
    for prefix, root in (("U:\\:AD1LEAN [NTFS]/[root]/known/", "U:\\known\\"),
                         ("second:C:\\AD1Lean\\second/", "C:\\AD1Lean\\second\\")):
        if path.startswith(prefix):
            return root + path[len(prefix):].replace("/", "\\")
    return None


@pytest.mark.parametrize("image,password,files", [
    (PLAIN, None, 8), (MULTI, None, 7),
    pytest.param(CRYPT, PASSWORD, 8, marks=needs_crypto)])
def test_every_file_holds_the_known_content_and_times(image, password, files):
    known = _manifest()
    compared = 0
    with _open(image, password) as img:
        for entry in img.logical_entries:
            row = known.get(_known(image, entry.path) or "")
            if entry.is_folder or row is None:
                continue
            assert entry.size == row["size"]
            assert (entry.md5, entry.sha1) == (row["md5"], row["sha1"])
            # read, not only what the image stores about it
            assert _content_md5(img, entry) == row["md5"]
            assert entry.times["created"] == pytest.approx(_posix(row["created"]), abs=1e-6)
            assert entry.times["modified"] == pytest.approx(_posix(row["modified"]),
                                                            abs=1e-6)
            compared += 1
    assert compared == files


def test_the_folder_image_holds_every_file_and_folder_of_the_source():
    known = _manifest()
    with _open(PLAIN) as img:
        assert len(img.paths) == 4
        assert img.ad1["data_source"] == "C:\\AD1Lean\\src"
        seen = {e.path for e in img.logical_entries}
        for entry in img.logical_entries:
            assert entry.is_folder == (known[_known(PLAIN, entry.path)]["size"] is None)
    expected = {p[len("C:\\AD1Lean\\src\\"):].replace("\\", "/") for p in known
                if p.startswith("C:\\AD1Lean\\src\\")}
    assert seen == expected
    assert "docs/pattern-2300k.bin" in seen     # spans three of the four files


@pytest.mark.parametrize("image,password", [(PLAIN, None), (MULTI, None),
                                            pytest.param(CRYPT, PASSWORD,
                                                         marks=needs_crypto)])
def test_times_and_deletion_agree_with_ftk_imagers_own_listing(image, password):
    listed = _listing(image)
    with _open(image, password) as img:
        by_name = {}
        for entry in img.logical_entries:
            by_name.setdefault((entry.name, entry.md5 or ""), []).append(entry)
        matched = 0
        for row in listed:
            found = by_name.get((row["Filename"], row["Stored MD5 Hash"]), [])
            # FTK lists a deleted index entry with no size
            found = [e for e in found if str(e.size) == (row["Size (bytes)"] or "0")]
            if len(found) != 1:
                continue
            entry = found[0]
            for column, key in (("Created", "created"), ("Modified", "modified"),
                                ("Accessed", "accessed")):
                want = _listed_time(row[column])
                if want is None:
                    assert key not in entry.times
                else:
                    assert entry.times[key] == pytest.approx(want, abs=1e-6), (row, key)
            assert entry.is_deleted == (row["Is Deleted"] == "yes")
            matched += 1
        # logical_entries keeps the order the items lie in the image: each folder's
        # children before its next sibling (FTK Imager's listing goes breadth first)
        addresses = [e.address for e in img.logical_entries]
        assert addresses == sorted(addresses)
    assert matched == len(listed)


def test_two_sources_a_stream_and_a_deleted_file():
    with _open(MULTI) as img:
        assert img.ad1["data_source"] == "Custom Content Image([Multi])"
        tops = [e.name for e in img.logical_root.children]
        assert tops == ["U:\\:AD1LEAN [NTFS]", "second:C:\\AD1Lean\\second"]
        known = "U:\\:AD1LEAN [NTFS]/[root]/known"
        readme = img.find_entry(known + "/readme.txt")
        assert readme.item_type == 1 and readme.type_code == "1"
        stream = img.find_entry(known + "/readme.txt/extra")
        assert stream.parent is readme and stream.type_code == "D"
        assert img.read_entry(stream) == b"alternate data stream\r\n"
        assert readme.metadata[(4, 0x1005)] == "true"        # archive, read on request
        assert len(readme.metadata) > 20                     # NTFS times, owner, flags
        gone = img.find_entry(known + "/to-delete.txt")
        assert gone.is_deleted and gone.item_type == 2
        assert img.read_entry(gone) == b"this file is deleted before imaging\r\n"
        assert img.find_entry("second:C:\\AD1Lean\\second/more/second.txt").size == 15
        assert sum(e.is_deleted for e in img.logical_entries) == 1
    with pytest.raises(ValueError, match="closed"):
        _ = readme.metadata


def test_a_set_opens_from_any_of_its_files():
    with _open(PLAIN) as whole:
        want = [(e.path, e.size, e.md5) for e in whole.logical_entries]
    for n in (2, 4):
        with _open(PLAIN[:-1] + str(n)) as img:
            assert img.paths[0].endswith(".ad1") and len(img.paths) == 4
            assert [(e.path, e.size, e.md5) for e in img.logical_entries] == want


def _copy_set(tmp_path, image=PLAIN, keep=None, log=True):
    """Copies of an image's files (the first ``keep`` of them) and, unless ``log`` is
    False, of FTK Imager's log beside it."""
    names = sorted(n for n in os.listdir(AD1)
                   if n.startswith(os.path.basename(image)[:-4] + ".ad")
                   and n[-1].isdigit())
    out = []
    for name in names[:keep]:
        shutil.copy(os.path.join(AD1, name), tmp_path / name)
        out.append(tmp_path / name)
    if log:
        shutil.copy(image + ".txt", tmp_path / (os.path.basename(image) + ".txt"))
    return out


def test_a_missing_file_is_refused(tmp_path):
    files = _copy_set(tmp_path, keep=3)
    with pytest.raises(ewfprobe.EwfIncompleteSetError, match="records 4 files"):
        _open(str(files[0]))


def test_a_file_cut_short_is_refused(tmp_path):
    files = _copy_set(tmp_path)
    data = files[1].read_bytes()
    files[1].write_bytes(data[:len(data) // 2])
    with pytest.raises(ewfprobe.EwfIncompleteSetError, match="cut short"):
        _open(str(files[0]))


@pytest.mark.parametrize("image,cut", [(PLAIN, 1), (MULTI, 1), (MULTI, 400)])
def test_a_last_file_cut_short_is_refused(tmp_path, image, cut):
    # The last file may be shorter than the recorded segment size, so only the end its
    # footer computes shows that bytes are missing.
    last = _copy_set(tmp_path, image)[-1]
    data = last.read_bytes()
    last.write_bytes(data[:-cut])
    with pytest.raises(ewfprobe.EwfIncompleteSetError, match="cut short"):
        _open(str(last))


def test_bytes_after_the_footer_are_refused(tmp_path):
    last = _copy_set(tmp_path, MULTI)[-1]
    last.write_bytes(last.read_bytes() + b"\x00" * 3)
    with pytest.raises(ewfprobe.EwfFormatError, match="3 bytes after its AD1 footer"):
        _open(str(last))


def test_a_footer_block_out_of_place_is_refused(tmp_path):
    last = _copy_set(tmp_path, MULTI)[-1]
    data = bytearray(last.read_bytes())
    at = data.rindex(b"LOCSGUID")
    data[at:at + 8] = b"LOCSGUIX"
    last.write_bytes(bytes(data))
    with pytest.raises(ewfprobe.EwfFormatError, match="no LOCSGUID block"):
        _open(str(last))


def test_a_file_out_of_place_is_refused(tmp_path):
    files = _copy_set(tmp_path)
    a, b = files[1].read_bytes(), files[2].read_bytes()
    files[1].write_bytes(b)
    files[2].write_bytes(a)
    with pytest.raises(ewfprobe.EwfFormatError, match="says it is file 3"):
        _open(str(files[0]))


def _logical_poke(path, logical, data):
    """Write ``data`` at a logical offset of a one-file AD1."""
    with open(path, "r+b") as fh:
        fh.seek(512 + logical)
        fh.write(data)


def test_a_damaged_chunk_fails_its_entry_and_the_image_hash(tmp_path):
    files = _copy_set(tmp_path)
    with _open(str(files[0])) as img:
        entry = img.find_entry("docs/exact-64k.bin")
        first_chunk = img._ad1_chunks(entry)[0]
    # compression 0 stores the bytes inside the zlib stream, so one flipped byte
    # fails the stream's own checksum
    with open(files[0], "r+b") as fh:
        fh.seek(512 + first_chunk + 100)
        byte = fh.read(1)
        fh.seek(-1, os.SEEK_CUR)
        fh.write(bytes([byte[0] ^ 0xFF]))
    with _open(str(files[0])) as img:
        entry = img.find_entry("docs/exact-64k.bin")
        with pytest.raises(ewfprobe.EwfFormatError, match="does not inflate"):
            img.read_entry(entry)
        result = img.verify()
    assert result["match"] is False
    assert result["entry_md5_mismatched"] == ["docs/exact-64k.bin"]


def test_version_3_is_refused(tmp_path):
    copy = tmp_path / "lean-multi-ntfs-c9.ad1"
    shutil.copy(MULTI, copy)
    _logical_poke(copy, 16, struct.pack("<I", 3))
    with pytest.raises(ewfprobe.EwfFormatError, match="AD1 version 3"):
        _open(str(copy))


def test_a_tree_that_loops_is_refused(tmp_path):
    copy = tmp_path / "lean-multi-ntfs-c9.ad1"
    shutil.copy(MULTI, copy)
    with _open(str(copy)) as img:
        first = img.ad1["first_item"]
    _logical_poke(copy, first, struct.pack("<Q", first))     # its own next sibling
    with pytest.raises(ewfprobe.EwfFormatError, match="loops"):
        _open(str(copy))


def test_an_item_under_the_wrong_parent_is_refused(tmp_path):
    copy = tmp_path / "lean-multi-ntfs-c9.ad1"
    shutil.copy(MULTI, copy)
    with _open(str(copy)) as img:
        entry = img.find_entry("U:\\:AD1LEAN [NTFS]/[root]/known/hidden.txt")
        at = entry.address + entry.header_length - 8
    _logical_poke(copy, at, struct.pack("<Q", 12345))
    with pytest.raises(ewfprobe.EwfFormatError, match="names its parent"):
        _open(str(copy))


@needs_crypto
def test_the_encrypted_set_needs_its_password_and_reads_as_the_plain_one():
    with pytest.raises(ewfprobe.EwfPasswordRequiredError):
        _open(CRYPT)
    with pytest.raises(ewfprobe.EwfWrongPasswordError):
        _open(CRYPT, "not the password")
    with _open(PLAIN) as plain, _open(CRYPT[:-1] + "2", PASSWORD) as crypt:
        assert crypt.encryption["cipher"] == "AES-256-CTR"
        assert len(crypt.paths) == 2
        assert [(e.path, e.md5) for e in crypt.logical_entries] == \
               [(e.path, e.md5) for e in plain.logical_entries]
        big = "docs/pattern-2300k.bin"
        assert _content_md5(crypt, crypt.find_entry(big)) == \
               _content_md5(plain, plain.find_entry(big))


def test_logical_evidence_is_recognised():
    assert ewfprobe.is_logical_evidence(PLAIN)
    assert ewfprobe.is_logical_evidence(PLAIN[:-1] + "3")
    assert ewfprobe.is_ad1(MULTI)
    assert not ewfprobe.is_image(PLAIN)
    assert not ewfprobe.is_logical_evidence(CRYPT)          # opens only with a password
    assert ewfprobe.is_adcrypt(CRYPT)


def test_the_command_line(capsys, tmp_path):
    assert ewfprobe.main(["info", MULTI]) == 0
    out = capsys.readouterr().out
    assert "AD1 version     4" in out and "Custom Content Image([Multi])" in out
    assert ewfprobe.main(["files", MULTI]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "kind\tsize\tmd5\titem_type\ttype_code\tpath"
    assert len(lines) == 16
    assert "file\t37\tdcd9d485e0b077c0c79537d63c34af3d\t2\t1\t" \
           "U:\\:AD1LEAN [NTFS]/[root]/known/to-delete.txt" in lines
    out = tmp_path / "extra.bin"
    assert ewfprobe.main(["export", MULTI, "--entry",
                          "U:\\:AD1LEAN [NTFS]/[root]/known/readme.txt/extra",
                          "-o", str(out)]) == 0
    assert out.read_bytes() == b"alternate data stream\r\n"
    assert ewfprobe.main(["verify", "-q", PLAIN]) == 0
    out = capsys.readouterr().out
    assert "matches the stored hash" in out and "entry SHA-1s    8 checked, all match" in out


def test_without_the_log_nothing_is_stored_and_verify_still_checks_entries(tmp_path):
    files = _copy_set(tmp_path, image=MULTI, log=False)
    with _open(str(files[0])) as img:
        assert img.ad1["log"] is None and img.stored_hashes == {}
        result = img.verify()
    assert result["match"] is None
    assert set(result["computed"]) == {"MD5", "SHA1"}
    assert result["entry_md5_checked"] == 9 and not result["entry_md5_mismatched"]


_REFERENCE = os.environ.get("EWFPROBE_AD1_REFERENCE")


@pytest.mark.skipif(not _REFERENCE and not os.environ.get("EWFPROBE_REQUIRE_AD1_REFERENCE"),
                    reason="EWFPROBE_AD1_REFERENCE names no folder of pyad1's test data")
def test_pyad1s_sample_from_ftk_imager_3_4():
    path = os.path.join(_REFERENCE or "", "text-and-pictures.ad1")
    with _open(path) as img:
        assert len(img.paths) == 4
        assert img.ad1["data_source"] == "C:\\Users\\pcbje\\Desktop\\Data"
        result = img.verify()
    # the log's hashes, as pyad1's own test reads them
    assert result["stored"] == {"MD5": "24b6c553392e92dec7b6fa9c92c0216d",
                                "SHA1": "0608982ed40664ec922f1991ac7ccf07d239ada1"}
    assert result["match"] is True
    assert result["entry_sha1_checked"] == 8 and not result["entry_sha1_mismatched"]

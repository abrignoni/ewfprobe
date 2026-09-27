"""Tests against EWF files written by the reference implementation.

The fixtures under ``tests/fixtures`` were produced by ``ewfacquire`` from
libewf, driven by ``tools/make_fixtures.py``. They are bytes neither this
reader nor the test writer in ``test_ewfprobe.py`` produced, which is what makes
them worth having: they check the reader against the format as a different
program actually writes it, not against a second reading of the specification.

``manifest.json`` records the source image's own SHA-256 and the offset, length
and SHA-256 of every synthetic media file placed in it. Those are the known
answers, and they are also the known answers a carver will be measured against.

The content is generated, not evidence.
"""

import hashlib
import json
import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ewfprobe  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
MANIFEST_PATH = os.path.join(FIXTURES, "manifest.json")

pytestmark = pytest.mark.skipif(
    not os.path.exists(MANIFEST_PATH),
    reason="reference fixtures absent; run tools/make_fixtures.py tests/fixtures --small")


def _manifest():
    with open(MANIFEST_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _variants():
    man = _manifest()
    return [(name, v) for name, v in sorted(man["variants"].items())]


def _first(variant):
    """The path to open: an AFD's directory, else the first file."""
    return os.path.join(FIXTURES, variant.get("image", variant["files"][0]))


def _media_sha(img):
    h = hashlib.sha256()
    img.seek(0)
    while True:
        block = img.read(1 << 20)
        if not block:
            break
        h.update(block)
    return h.hexdigest()


@pytest.mark.parametrize("name,variant", _variants())
def test_every_variant_reproduces_the_source_exactly(name, variant):
    man = _manifest()
    with ewfprobe.open_ewf(_first(variant)) as img:
        assert img.media_size == man["size"], name
        assert img.sector_size == man["sector_size"], name
        assert _media_sha(img) == man["sha256"], name


@pytest.mark.parametrize("name,variant", _variants())
def test_every_variant_matches_its_own_stored_hash(name, variant):
    with ewfprobe.open_ewf(_first(variant)) as img:
        result = img.verify()
    assert result["checksum_errors"] == [], name
    if variant.get("stores_no_hash"):
        # FTK Imager's AFF keeps its hashes in its text log, not in the image.
        assert result["stored"] == {} and result["match"] is None, name
        return
    assert result["stored"], f"{name} recorded no hash"
    assert result["match"] is True, name


@pytest.mark.parametrize("name,variant", _variants())
def test_the_known_media_is_where_the_manifest_says(name, variant):
    """Also the known-answer set a carver will be measured against."""
    man = _manifest()
    with ewfprobe.open_ewf(_first(variant)) as img:
        for item in man["media"]:
            img.seek(item["offset"])
            data = img.read(item["length"])
            assert hashlib.sha256(data).hexdigest() == item["sha256"], \
                f"{name}: {item['kind']} at {item['offset']}"


def test_the_older_encase5_table_layout_reads():
    """encase5 predates the 64-bit table base offset, so it exercises base 0."""
    variants = dict(_variants())
    assert "encase5-fast" in variants, "the encase5 fixture is missing"
    with ewfprobe.open_ewf(_first(variants["encase5-fast"])) as img:
        assert _media_sha(img) == _manifest()["sha256"]
        assert {t.base for t in img._tables} == {0}, \
            "encase5 should carry no table base offset"


def test_the_split_fixture_is_genuinely_multi_segment():
    variants = dict(_variants())
    split = variants["encase6-split"]
    assert len(split["files"]) >= 3, "the split fixture did not actually split"
    with ewfprobe.open_ewf(_first(split)) as img:
        assert len(img.paths) == len(split["files"])
        # a read that crosses from one segment file into the next
        boundary = next(t.first_chunk * img.chunk_size
                        for t in img._tables if t.segment == 1)
        img.seek(boundary - 4096)
        spanning = img.read(8192)
    with ewfprobe.open_ewf(_first(variants["encase6-fast"])) as whole:
        whole.seek(boundary - 4096)
        assert spanning == whole.read(8192)


def test_a_missing_segment_of_a_real_set_is_refused(tmp_path):
    variants = dict(_variants())
    split = variants["encase6-split"]
    for name in split["files"]:
        shutil.copy(os.path.join(FIXTURES, name), tmp_path / name)
    os.remove(tmp_path / split["files"][-1])
    with pytest.raises(ewfprobe.EwfIncompleteSetError):
        ewfprobe.open_ewf(str(tmp_path / split["files"][0]))


def test_the_image_answers_size_the_way_a_joined_raw_set_does():
    """A consumer that opens either a single file, a joined set of raw segments
    or an E01 asks the object for its size. Answering it here is what lets such
    a consumer take an E01 with no special case."""
    man = _manifest()
    variants = dict(_variants())
    for name in ("encase6-fast", "encase6-split"):
        with ewfprobe.open_ewf(_first(variants[name])) as img:
            assert img.size == img.media_size == man["size"], name
            assert len(img.sizes) == len(variants[name]["files"]), name
            assert all(s > 0 for s in img.sizes), name


def test_metadata_written_by_ewfacquire_is_read_back():
    variants = dict(_variants())
    with ewfprobe.open_ewf(_first(variants["encase6-fast"])) as img:
        meta = img.metadata
    assert meta.get("case_number") == "FIXTURE"
    assert "ewfprobe fixture" in meta.get("description", "")


def test_libewf_smart_fixtures_read_as_smart():
    """Written by ewfacquire -f smart: lowercase segment names, the 94-byte volume
    section and a table header with no base offset."""
    variants = dict(_variants())
    for name in ("smart-fast", "smart-split"):
        assert name in variants, f"the {name} fixture is missing"
        with ewfprobe.open_ewf(_first(variants[name])) as img:
            assert img.format == ewfprobe.FORMAT_S01, name
            assert img.media_type is None, name
            assert {t.base for t in img._tables} == {0}, name
    with ewfprobe.open_ewf(_first(variants["smart-fast"])) as img:
        assert img.compression_level == "fast"


def test_the_smart_split_fixture_opens_from_any_member():
    variants = dict(_variants())
    files = variants["smart-split"]["files"]
    assert len(files) >= 3, "the SMART split fixture did not actually split"
    assert all(f.rsplit(".", 1)[1].startswith("s") for f in files)
    with ewfprobe.open_ewf(os.path.join(FIXTURES, files[-1])) as img:
        assert [os.path.basename(p) for p in img.paths] == files
        assert _media_sha(img) == _manifest()["sha256"]


def test_ftk_imager_fixtures_are_read_like_the_libewf_ones():
    """Written by FTK Imager 4.7.3.61 from the same source image, so a writer that
    is neither this reader nor libewf. Its SMART files carry a digest section with a
    SHA-1 beside the MD5, and its split set opens from any member."""
    variants = dict(_variants())
    for name in ("ftk-smart", "ftk-smart-split", "ftk-e01"):
        assert name in variants, f"the {name} fixture is missing"
        assert variants[name]["writer"].startswith("FTK Imager"), name
    for name in ("ftk-smart", "ftk-smart-split"):
        with ewfprobe.open_ewf(os.path.join(FIXTURES, variants[name]["files"][-1])) as img:
            assert img.format == ewfprobe.FORMAT_S01, name
            assert set(img.stored_hashes) == {"MD5", "SHA1"}, name
            assert len(img.paths) == len(variants[name]["files"]), name
    with ewfprobe.open_ewf(_first(variants["ftk-e01"])) as img:
        assert img.format == ewfprobe.FORMAT_E01


def test_libewf_ex01_fixtures_read_as_ex01():
    """Written by ewfacquire -f encase7-v2 from libewf 20260924. Between them the
    two carry deflated, checksummed-stored and pattern-filled chunks."""
    variants = dict(_variants())
    seen = set()
    for name in ("ex01-fast", "ex01-none"):
        assert name in variants, f"the {name} fixture is missing"
        with open(_first(variants[name]), "rb") as fh:
            assert fh.read(8) == ewfprobe.SIGNATURE_V2, name
        with ewfprobe.open_ewf(_first(variants[name])) as img:
            assert img.format == ewfprobe.FORMAT_EX01, name
            assert set(img.stored_hashes) == {"MD5", "SHA1"}, name
            assert img.metadata.get("case_number") == "FIXTURE", name
            for table in img._tables:
                for k in range(len(table.entries) // 16):
                    seen.add(ewfprobe._TABLE_V2_ENTRY.unpack_from(table.entries, 16 * k)[2])
    assert {0x01, 0x02, 0x05} <= seen, seen


def test_aff_fixtures_cover_every_page_form_and_read_as_aff():
    """affconvert (AFFLIB 3.7.22) with 64 KiB pages writes zero pages, deflated
    pages, LZMA pages and stored pages; FTK Imager's AFF is one 16 MiB page."""
    variants = dict(_variants())
    forms = set()
    for name in ("aff-zlib", "aff-lzma", "aff-none", "ftk-aff"):
        assert name in variants, f"the {name} fixture is missing"
        with ewfprobe.open_ewf(_first(variants[name])) as img:
            assert img.format == ewfprobe.FORMAT_AFF, name
            assert img.missing_page_count == 0, name
            forms |= {arg for _i, _off, _len, arg in img._aff_pages.values()}
    assert {0x00, 0x01, 0x21, 0x33} <= forms, sorted(forms)
    with ewfprobe.open_ewf(_first(variants["ftk-aff"])) as img:
        assert img.metadata["case_number"] == "FIXTURE"
        assert img.metadata["examiner"] == "ewfprobe"
        assert img.sector_size == 512          # FTK Imager stores it as text
        assert img.chunk_size == 16 << 20


def test_afd_fixtures_read_as_one_image_from_the_directory_or_any_file():
    """Two AFD directories from two writers. affconvert's (-M32k) spreads 48 pages over
    five files, with none in the first and the image size and hashes only in the
    last. FTK Imager's (1 MB fragments, compression 0) keeps its one 16 MiB page in
    the middle file and the image size in every file, and writes the sector size as
    text in the first file and as a segment argument in the others."""
    man = _manifest()
    variants = dict(_variants())
    for name, members in (("aff-afd", 5), ("ftk-aff-split", 3)):
        assert name in variants, f"the {name} fixture is missing"
        files = variants[name]["files"]
        assert len(files) == members, name
        for path in [_first(variants[name])] + [os.path.join(FIXTURES, f) for f in files]:
            with ewfprobe.open_ewf(path) as img:
                assert img.format == ewfprobe.FORMAT_AFD, path
                assert [os.path.basename(p) for p in img.paths] == [
                    os.path.basename(f) for f in files], path
                assert img.missing_page_count == 0, path
                assert _media_sha(img) == man["sha256"], path
    with ewfprobe.open_ewf(_first(variants["aff-afd"])) as img:
        holders = {i for i, _o, _l, _a in img._aff_pages.values()}
        assert 0 not in holders and len(holders) >= 3, holders
        assert set(img.stored_hashes) == {"MD5", "SHA1"}
    with ewfprobe.open_ewf(_first(variants["ftk-aff-split"])) as img:
        assert {i for i, _o, _l, _a in img._aff_pages.values()} == {1}
        assert img.sector_size == 512 and img.chunk_size == 16 << 20
        assert img.metadata["case_number"] == "FIXTURE"
        assert img.metadata["ad_unique_desc"] == "ewfprobe fixture ftk-aff-split"


def test_a_missing_file_of_a_real_afd_is_refused(tmp_path):
    """The middle file of FTK Imager's AFD holds the only page, and the last file of
    affconvert's holds the image size."""
    variants = dict(_variants())
    for name, gone, words in (("ftk-aff-split", "file_001.aff", "file_001.aff"),
                              ("aff-afd", "file_004.aff", "image size")):
        folder = tmp_path / os.path.basename(variants[name]["image"])
        shutil.copytree(_first(variants[name]), folder)
        os.remove(folder / gone)
        with pytest.raises(ewfprobe.EwfIncompleteSetError, match=words):
            ewfprobe.open_ewf(str(folder))


def _logical():
    return sorted(_manifest().get("logical", {}).items())


@pytest.mark.parametrize("name,known", _logical())
def test_a_real_l01_reads_as_libewf_exports_it(name, known):
    """An L01 EnCase wrote, from Digital Corpora. The known answers were taken from
    libewf's ewfexport, not from this reader: the media data it exports raw, and
    every file it exports with -f files, as one digest."""
    path = os.path.join(FIXTURES, known["files"][0])
    with ewfprobe.open_ewf(path) as img:
        assert img.format == ewfprobe.FORMAT_L01, name
        assert img.media_size == known["media_size"], name
        assert _media_sha(img) == known["media_sha256"], name
        assert len(img.logical_entries) == known["entries"], name
        assert sum(1 for e in img.logical_entries if e.md5) == known["entry_md5s"], name
        assert sum(1 for e in img.logical_entries
                   if e.children and e.size) == known["entries_with_data_and_children"]
        lines = []
        for entry in img.logical_entries:
            if entry.children or entry.is_folder:
                continue                      # ewfexport writes these as folders
            digest = hashlib.sha256(img.read_entry(entry)).hexdigest()
            lines.append(f"{entry.path}\t{digest}\n")
        assert len(lines) == known["exported_files"], name
        joined = "".join(sorted(lines)).encode("utf-8", "surrogatepass")
        assert hashlib.sha256(joined).hexdigest() == known["exported_files_digest"], name
        sparse = img.find_entry(known["sparse_entry"]["path"])
        assert sparse.flags & ewfprobe.L01_FLAG_SPARSE, name
        data = img.read_entry(sparse)
        assert len(data) == known["sparse_entry"]["size"], name
        assert hashlib.sha256(data).hexdigest() == known["sparse_entry"]["sha256"], name
        result = img.verify()
    assert result["checksum_errors"] == [], name
    assert result["entry_md5_checked"] == known["entry_md5s"], name
    assert result["entry_md5_mismatched"] == [], name
    assert result["computed"]["MD5"] == known["media_md5"], name


def test_the_real_l01_fixture_is_the_file_digital_corpora_publishes():
    for name, known in _logical():
        with open(os.path.join(FIXTURES, known["files"][0]), "rb") as fh:
            assert hashlib.sha256(fh.read()).hexdigest() == known["file_sha256"], name
    assert _logical(), "the L01 fixture is missing from the manifest"


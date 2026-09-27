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
import plistlib
import shutil
import struct
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


# A job that installs pyliblzfse sets this, so the LZFSE fixture has to run there
# rather than skip unseen.
_LZFSE_REQUIRED = bool(os.environ.get("EWFPROBE_REQUIRE_LZFSE"))


def _variants():
    man = _manifest()
    out = []
    for name, v in sorted(man["variants"].items()):
        missing = v.get("needs") == "liblzfse" and ewfprobe.liblzfse is None
        marks = ([pytest.mark.skip(reason="LZFSE needs the optional pyliblzfse package")]
                 if missing and not _LZFSE_REQUIRED else [])
        out.append(pytest.param(name, v, marks=marks, id=name))
    return out


def _readable():
    """The variants this Python can read, as (name, variant) pairs."""
    return [p.values for p in _variants() if not p.marks]


def test_the_lzfse_fixture_runs_where_it_is_required():
    if _LZFSE_REQUIRED:
        assert ewfprobe.liblzfse is not None, "EWFPROBE_REQUIRE_LZFSE is set and pyliblzfse is not installed"


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
    variants = dict(_readable())
    assert "encase5-fast" in variants, "the encase5 fixture is missing"
    with ewfprobe.open_ewf(_first(variants["encase5-fast"])) as img:
        assert _media_sha(img) == _manifest()["sha256"]
        assert {t.base for t in img._tables} == {0}, \
            "encase5 should carry no table base offset"


def test_the_split_fixture_is_genuinely_multi_segment():
    variants = dict(_readable())
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
    variants = dict(_readable())
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
    variants = dict(_readable())
    for name in ("encase6-fast", "encase6-split"):
        with ewfprobe.open_ewf(_first(variants[name])) as img:
            assert img.size == img.media_size == man["size"], name
            assert len(img.sizes) == len(variants[name]["files"]), name
            assert all(s > 0 for s in img.sizes), name


def test_metadata_written_by_ewfacquire_is_read_back():
    variants = dict(_readable())
    with ewfprobe.open_ewf(_first(variants["encase6-fast"])) as img:
        meta = img.metadata
    assert meta.get("case_number") == "FIXTURE"
    assert "ewfprobe fixture" in meta.get("description", "")


def test_libewf_smart_fixtures_read_as_smart():
    """Written by ewfacquire -f smart: lowercase segment names, the 94-byte volume
    section and a table header with no base offset."""
    variants = dict(_readable())
    for name in ("smart-fast", "smart-split"):
        assert name in variants, f"the {name} fixture is missing"
        with ewfprobe.open_ewf(_first(variants[name])) as img:
            assert img.format == ewfprobe.FORMAT_S01, name
            assert img.media_type is None, name
            assert {t.base for t in img._tables} == {0}, name
    with ewfprobe.open_ewf(_first(variants["smart-fast"])) as img:
        assert img.compression_level == "fast"


def test_the_smart_split_fixture_opens_from_any_member():
    variants = dict(_readable())
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
    variants = dict(_readable())
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
    variants = dict(_readable())
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
    variants = dict(_readable())
    forms = set()
    for name in ("aff-zlib", "aff-lzma", "aff-none", "ftk-aff"):
        assert name in variants, f"the {name} fixture is missing"
        with ewfprobe.open_ewf(_first(variants[name])) as img:
            assert img.format == ewfprobe.FORMAT_AFF, name
            assert img.missing_page_count == 0, name
            forms |= {arg for _i, _off, _len, arg, _enc in img._aff_pages.values()}
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
    variants = dict(_readable())
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
        holders = {i for i, _o, _l, _a, _e in img._aff_pages.values()}
        assert 0 not in holders and len(holders) >= 3, holders
        assert set(img.stored_hashes) == {"MD5", "SHA1"}
    with ewfprobe.open_ewf(_first(variants["ftk-aff-split"])) as img:
        assert {i for i, _o, _l, _a, _e in img._aff_pages.values()} == {1}
        assert img.sector_size == 512 and img.chunk_size == 16 << 20
        assert img.metadata["case_number"] == "FIXTURE"
        assert img.metadata["ad_unique_desc"] == "ewfprobe fixture ftk-aff-split"


def test_a_missing_file_of_a_real_afd_is_refused(tmp_path):
    """The middle file of FTK Imager's AFD holds the only page, and the last file of
    affconvert's holds the image size."""
    variants = dict(_readable())
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


def test_apple_disk_images_read_as_hdiutil_wrote_them():
    """hdiutil wrote these from the same source. Each must decode to that source
    (the generic tests above) and must verify every checksum it records about its
    own data: the data fork, each block table over the chunks it stores, and the
    master over the tables' checksums."""
    codecs = {"UDZO": "zlib", "UDBZ": "bzip2", "ULMO": "LZMA", "ULFO": "LZFSE",
              "UDCO": "ADC", "UDRO": "none", "UFBI": "none"}
    seen = set()
    for name, variant in _readable():
        fmt = variant.get("hdiutil_format")
        if not fmt:
            continue
        seen.add(fmt)
        with ewfprobe.open_ewf(_first(variant)) as img:
            if fmt in ("UDSP", "UDSB"):
                assert img.format == {"UDSP": ewfprobe.FORMAT_SPARSEIMAGE,
                                      "UDSB": ewfprobe.FORMAT_SPARSEBUNDLE}[fmt], name
                assert img.verify()["container_checks"] == [], name
                continue
            assert img.format == ewfprobe.FORMAT_UDIF, name
            assert img.compression_level == codecs[fmt], name
            files = [os.path.basename(p) for p in img.paths]
            checks = img.verify()["container_checks"]
        assert files == variant["files"], name
        kinds = [c["what"] for c in checks]
        data = ["data"] if len(files) == 1 else [f"data of {f}" for f in files]
        assert kinds[:len(data)] == data and kinds[-1] == "master", name
        assert len(kinds) >= 3, name
        assert all(c["match"] for c in checks), (name, [c for c in checks if not c["match"]])
        expected = "MD5" if fmt == "UFBI" else "CRC32"
        assert {c["algorithm"] for c in checks} == {expected}, name
    expected_formats = set(codecs) | {"UDSP", "UDSB"}
    if ewfprobe.liblzfse is None and not _LZFSE_REQUIRED:
        expected_formats.discard("ULFO")
    assert seen == expected_formats


def test_segmented_images_hdiutil_wrote_from_a_gpt_disk():
    """hdiutil segment wrote these from a small GPT disk, whose SHA-256 the manifest
    records. That disk gives the image several block tables, and segment writes
    each table's own base as its data offset with entry offsets relative to it, so
    these are the images that fail when that offset is ignored."""
    gpt = _manifest().get("gpt_dmg")
    assert gpt, "the GPT disk images are missing from the manifest"
    for name, variant in sorted(gpt["variants"].items()):
        first = os.path.join(FIXTURES, variant["files"][0])
        with open(first, "rb") as fh:
            raw = fh.read()
        xml_offset, xml_size = struct.unpack_from(">QQ", raw[-512:], 216)
        tables = plistlib.loads(raw[xml_offset:xml_offset + xml_size])
        bases = [struct.unpack_from(">Q", t["Data"], 24)[0]
                 for t in tables["resource-fork"]["blkx"]]
        assert len(bases) > 1 and any(bases), (name, bases)
        with ewfprobe.open_ewf(first) as img:
            assert [os.path.basename(p) for p in img.paths] == variant["files"], name
            assert img.media_size == gpt["size"], name
            assert _media_sha(img) == gpt["sha256"], name
            checks = img.verify()["container_checks"]
        assert checks and all(c["match"] for c in checks), name


# -- encrypted Apple disk images -------------------------------------------------

# A job that installs pycryptodome sets this, so the encrypted fixtures have to run
# there rather than skip unseen.
_CRYPTO_REQUIRED = bool(os.environ.get("EWFPROBE_REQUIRE_CRYPTO"))
_ENCRYPTED_FORMATS = {"udif": ewfprobe.FORMAT_UDIF, "udrw": ewfprobe.FORMAT_UDRW,
                      "sparseimage": ewfprobe.FORMAT_SPARSEIMAGE,
                      "sparsebundle": ewfprobe.FORMAT_SPARSEBUNDLE}


def _encrypted():
    section = _manifest().get("encrypted_dmg", {"variants": {}})
    missing = ewfprobe._AES is None and not _CRYPTO_REQUIRED     # pylint: disable=protected-access
    marks = ([pytest.mark.skip(reason="encrypted images need the optional pycryptodome "
                                      "package")] if missing else [])
    return [pytest.param(name, v, marks=marks, id=name)
            for name, v in sorted(section["variants"].items())]


def test_the_encrypted_fixtures_run_where_they_are_required():
    if _CRYPTO_REQUIRED:
        assert ewfprobe._AES is not None, (     # pylint: disable=protected-access
            "EWFPROBE_REQUIRE_CRYPTO is set and pycryptodome is not installed")
    section = _manifest().get("encrypted_dmg")
    assert section, "the encrypted images are missing from the manifest"
    assert {v["hdiutil_format"] for v in section["variants"].values()} == {
        "UDZO", "UDRW", "UDSP", "UDSB"}
    assert {v["encryption"] for v in section["variants"].values()} == {"AES-128",
                                                                       "AES-256"}


@pytest.mark.parametrize("name,variant", _encrypted())
def test_encrypted_images_read_as_hdiutil_attach_reads_them(name, variant):
    """hdiutil wrote each of these with -encryption, and make_fixtures.py kept it only
    after hdiutil attach, given the password, read back the disk it was made from."""
    section = _manifest()["encrypted_dmg"]
    disk = section["disks"][variant["disk"]]
    path = os.path.join(FIXTURES, variant.get("image", variant["files"][0]))
    assert ewfprobe.apple_image_kind(path) == "ENCRYPTED"
    with ewfprobe.open_ewf(path, password=variant["password"]) as img:
        assert img.format == _ENCRYPTED_FORMATS[variant["format"]]
        assert img.encryption["cipher"] == variant["encryption"]
        assert img.encryption["key_wrap"] == "AES-192"      # what hdiutil writes now
        assert img.media_size == disk["size"]
        assert _media_sha(img) == disk["sha256"]
        if img.format == ewfprobe.FORMAT_UDIF:
            assert [os.path.basename(p) for p in img.paths] == variant["files"]
            checks = img.verify()["container_checks"]
            assert checks and all(c["match"] for c in checks), name
    with pytest.raises(ewfprobe.EwfPasswordRequiredError):
        ewfprobe.open_ewf(path)
    with pytest.raises(ewfprobe.EwfWrongPasswordError):
        ewfprobe.open_ewf(path, password=variant["password"] + "x")


@pytest.mark.parametrize("name,variant", [p for p in _encrypted()
                                          if p.id == "dmg-enc-udzo-non-ascii"])
def test_a_password_outside_ascii_is_used_as_its_utf8_bytes(name, variant):
    """hdiutil refused the NFD spelling of this NFC password when the image was
    measured, so ewfprobe does not normalise either."""
    import unicodedata                  # pylint: disable=import-outside-toplevel
    path = os.path.join(FIXTURES, variant["files"][0])
    decomposed = unicodedata.normalize("NFD", variant["password"])
    assert decomposed != variant["password"], name
    with ewfprobe.open_ewf(path, password=variant["password"].encode("utf-8")) as img:
        assert img.format == ewfprobe.FORMAT_UDIF
    with pytest.raises(ewfprobe.EwfWrongPasswordError):
        ewfprobe.open_ewf(path, password=decomposed)


@pytest.mark.parametrize("name,variant", [p for p in _encrypted()
                                          if p.id == "dmg-enc-segmented-aes128"])
def test_an_encrypted_segment_that_will_not_open_is_named(tmp_path, name, variant):
    """Each file of an encrypted segmented image is its own container, so a .dmgpart
    beside it that the password does not open cannot be matched, and the refusal
    says so rather than only that a segment is missing."""
    for f in variant["files"][:1] + variant["files"][2:]:
        shutil.copy(os.path.join(FIXTURES, f), tmp_path / f)
    foreign = _manifest()["encrypted_dmg"]["variants"]["dmg-enc-udzo-non-ascii"]
    shutil.copy(os.path.join(FIXTURES, foreign["files"][0]), tmp_path / variant["files"][1])
    with pytest.raises(ewfprobe.EwfIncompleteSetError,
                       match="1 encrypted .dmgpart file beside it did not open"):
        ewfprobe.open_ewf(str(tmp_path / variant["files"][0]), password=variant["password"])


# -- AD-encrypted sets FTK Imager wrote ---------------------------------------------

def _ad_source():
    """The disk the AD-encrypted sets were made from, rebuilt the way
    tools/make_fixtures.py ad_source() writes it, so the known answer does not come
    from ewfprobe."""
    out, i = bytearray(), 0
    while len(out) < 2457 * 512:
        out += hashlib.sha256(b"ewfprobe AD encryption fixture %d" % i).digest()
        i += 1
    return bytes(out[:2457 * 512])


def _ad_sets():
    section = _manifest().get("ad_encrypted", {"variants": {}})
    missing = ewfprobe._AES is None and not _CRYPTO_REQUIRED     # pylint: disable=protected-access
    marks = ([pytest.mark.skip(reason="AD-encrypted images need the optional "
                                      "pycryptodome package")] if missing else [])
    return [pytest.param(name, v, marks=marks, id=name)
            for name, v in sorted(section["variants"].items())]


def test_the_ad_source_is_what_ftk_imager_recorded():
    section = _manifest()["ad_encrypted"]
    source = _ad_source()
    assert section["writer"].startswith("FTK Imager")
    assert {v["format"] for v in section["variants"].values()} == {"e01", "raw"}
    assert len(source) == section["source"]["size"]
    assert hashlib.md5(source).hexdigest() == section["ftk_recorded"]["MD5"]
    assert hashlib.sha1(source).hexdigest() == section["ftk_recorded"]["SHA1"]
    assert hashlib.sha256(source).hexdigest() == section["source"]["sha256"]


@pytest.mark.parametrize("name,variant", _ad_sets())
def test_ad_encrypted_sets_read_back_the_disk_ftk_imager_imaged(name, variant):
    """FTK Imager wrote each set with a 1 MB fragment, so every one has two files and
    the second decrypts under the second counter. The E01 also carries the hashes
    FTK Imager stored in it."""
    section = _manifest()["ad_encrypted"]
    files = [os.path.join(FIXTURES, f) for f in variant["files"]]
    assert len(files) == 2
    assert ewfprobe.is_adcrypt(files[0]) and not ewfprobe.is_adcrypt(files[1])
    for start in files:                         # a raw set opens from any member
        if variant["format"] != "raw" and start != files[0]:
            continue
        with ewfprobe.open_ewf(start, password=section["password"]) as img:
            assert img.format == {"e01": ewfprobe.FORMAT_E01,
                                  "raw": ewfprobe.FORMAT_RAW}[variant["format"]]
            assert [os.path.basename(p) for p in img.paths] == variant["files"]
            assert img.media_size == section["source"]["size"]
            assert _media_sha(img) == section["source"]["sha256"]
            assert img.encryption["cipher"] == "AES-256-CTR"
            assert img.encryption["kdf"] == "PBKDF2-HMAC-SHA1 of SHA512"
            assert img.encryption["kdf_rounds"] == 4000
            if variant["format"] == "e01":
                assert img.stored_hashes == section["ftk_recorded"]
    with pytest.raises(ewfprobe.EwfPasswordRequiredError):
        ewfprobe.open_ewf(files[0])
    with pytest.raises(ewfprobe.EwfWrongPasswordError):
        ewfprobe.open_ewf(files[0], password=section["password"] + "x")


# -- encrypted AFF -----------------------------------------------------------------

def _encrypted_aff():
    section = _manifest().get("encrypted_aff", {"variants": {}})
    missing = (ewfprobe._AES is None or ewfprobe._RSA is None) and not _CRYPTO_REQUIRED  # pylint: disable=protected-access
    marks = ([pytest.mark.skip(reason="encrypted AFF needs the optional pycryptodome "
                                      "package")] if missing else [])
    return [pytest.param(name, v, marks=marks, id=name)
            for name, v in sorted(section["variants"].items())]


def _aff_credentials(section, how):
    if how == "password":
        return {"password": section["password"]}
    return {"private_key": os.path.join(FIXTURES, section["key"])}


def test_the_encrypted_aff_fixtures_are_all_there():
    section = _manifest().get("encrypted_aff")
    assert section, "the encrypted AFF images are missing from the manifest"
    kinds = {v["encryption"] for v in section["variants"].values()}
    assert kinds == {"passphrase", "passphrase and certificate", "passphrase, in place",
                     "certificate, in place"}, kinds
    # AFFLIB reads back every one written encrypted, and refuses the ones affcrypto -e
    # encrypted in place, each of which begins with a segment where its header was
    for v in section["variants"].values():
        assert v["afflib_reads"] is (not v["encryption"].endswith("in place")), v
        assert v.get("header_lost", False) is v["encryption"].endswith("in place"), v


@pytest.mark.parametrize("name,variant", _encrypted_aff())
def test_encrypted_aff_reads_as_its_source_with_each_key_that_opens_it(name, variant):
    """AFFLIB wrote each of these from the fixtures' source; the ones it can open it
    read back as that source before make_fixtures.py kept them."""
    man = _manifest()
    section = man["encrypted_aff"]
    for how in variant["opens_with"]:
        with ewfprobe.open_ewf(_first(variant), **_aff_credentials(section, how)) as img:
            assert img.format in (ewfprobe.FORMAT_AFF, ewfprobe.FORMAT_AFD), name
            assert _media_sha(img) == man["sha256"], (name, how)
            assert img.encryption["cipher"] == "AES-256-CBC"
            assert img.encryption["opened_with"].startswith(
                "passphrase" if how == "password" else "private key"), img.encryption
            assert bool(img.aff_header_lost) is variant.get("header_lost", False), name
            # the stored hashes are themselves encrypted segments
            img.seek(0)
            data = img.read()
            assert img.stored_hashes["MD5"] == hashlib.md5(data).hexdigest(), name
            assert img.stored_hashes["SHA1"] == hashlib.sha1(data).hexdigest(), name
            # a segment name longer than the 15 bytes of the IV decrypts too
            target = variant.get("image", variant["files"][0])
            assert img.metadata["acquisition_commandline"].endswith(
                f"-o {target} source.raw"), img.metadata


@pytest.mark.parametrize("name,variant", _encrypted_aff())
def test_encrypted_aff_without_its_key_or_with_the_wrong_one_is_refused(name, variant):
    section = _manifest()["encrypted_aff"]
    with pytest.raises(ewfprobe.EwfPasswordRequiredError) as caught:
        ewfprobe.open_ewf(_first(variant))
    assert caught.value.needs == ("password" if "password" in variant["opens_with"]
                                  else "private key")
    if "password" in variant["opens_with"]:
        with pytest.raises(ewfprobe.EwfWrongPasswordError, match="not its passphrase"):
            ewfprobe.open_ewf(_first(variant), password=section["password"] + "x")
    if "private key" in variant["opens_with"]:
        other = ewfprobe._RSA.generate(2048).export_key()   # pylint: disable=protected-access
        with pytest.raises(ewfprobe.EwfWrongPasswordError, match="opens none"):
            ewfprobe.open_ewf(_first(variant), private_key=other)
    if len(variant["opens_with"]) == 2:
        # a wrong passphrase still leaves the private key to try
        key = os.path.join(FIXTURES, section["key"])
        with ewfprobe.open_ewf(_first(variant), password="not it", private_key=key) as img:
            assert img.encryption["opened_with"].startswith("private key")


@pytest.mark.skipif((ewfprobe._AES is None or ewfprobe._RSA is None)  # pylint: disable=protected-access
                    and not _CRYPTO_REQUIRED,
                    reason="encrypted AFF needs the optional pycryptodome package")
def test_a_sealed_key_whose_inner_layer_is_damaged_is_not_used(tmp_path):
    """The session key opens with the right private key, but the file key it wraps
    no longer ends in valid padding, so it is refused rather than used."""
    section = _manifest()["encrypted_aff"]
    source = os.path.join(FIXTURES, section["variants"]["aff-enc-inplace-cert"]["files"][0])
    with open(source, "rb") as fh:
        data = bytearray(fh.read())
    (name, _arg, _start, end), = [s for s in _aff_segments(bytes(data))
                                  if s[0] == "affkey_evp0"]
    data[end - 9] ^= 0xFF                   # the last byte of the wrapped file key
    path = tmp_path / "damaged.aff"
    path.write_bytes(bytes(data))
    with pytest.raises(ewfprobe.EwfWrongPasswordError, match="opens none"):
        ewfprobe.open_ewf(str(path), private_key=os.path.join(FIXTURES, section["key"]))


@pytest.mark.skipif((ewfprobe._AES is None or ewfprobe._RSA is None)  # pylint: disable=protected-access
                    and not _CRYPTO_REQUIRED,
                    reason="encrypted AFF needs the optional pycryptodome package")
def test_the_command_line_asks_for_the_private_key_and_uses_it(capsys):
    section = _manifest()["encrypted_aff"]
    image = _first(section["variants"]["aff-enc-inplace-cert"])
    assert ewfprobe.main(["info", image]) == 2
    assert "--private-key" in capsys.readouterr().err
    key = os.path.join(FIXTURES, section["key"])
    assert ewfprobe.main(["info", "--private-key", key, image]) == 0
    out = capsys.readouterr().out
    assert "its key opened with the private key (affkey_evp0)" in out
    assert "AFF header      overwritten by a segment" in out
    assert ewfprobe.main(["verify", "-q", "--private-key", key, image]) == 0
    assert capsys.readouterr().out.count("matches the stored hash") == 2


def _aff_segments(data):
    """(name, arg, start, end) of each segment of an AFF file's bytes."""
    at = 8 if data[:8] == ewfprobe.AF_HEADER else 0
    out = []
    while at < len(data):
        _m, name_len, data_len, arg = struct.unpack_from(">4sIII", data, at)
        end = at + 16 + name_len + data_len + 8
        out.append((data[at + 16:at + 16 + name_len].decode(), arg, at, end))
        at = end
    return out


def _aff_segment_bytes(name, value, arg=0):
    raw = name.encode()
    body = struct.pack(">4sIII", b"AFF\x00", len(raw), len(value), arg) + raw + value
    return body + struct.pack(">4sI", b"ATT\x00", len(body) + 8)


@pytest.mark.skipif(ewfprobe._AES is None and not _CRYPTO_REQUIRED,  # pylint: disable=protected-access
                    reason="encrypted AFF needs the optional pycryptodome package")
def test_an_encrypted_page_is_read_over_a_clear_copy_of_it(tmp_path):
    """affcrypto -e leaves clear copies behind when it encrypts in place; AFFLIB reads
    a segment's encrypted form first, and so does ewfprobe."""
    man = _manifest()
    section = man["encrypted_aff"]
    source = os.path.join(FIXTURES, section["variants"]["aff-enc-pass"]["files"][0])
    path = tmp_path / "copy.aff"
    with open(source, "rb") as fh:
        data = fh.read()
    path.write_bytes(data + _aff_segment_bytes("page0", b"\xaa" * 65536, 0)
                     + _aff_segment_bytes("acquisition_commandline", b"a clear copy"))
    with ewfprobe.open_ewf(str(path), password=section["password"]) as img:
        assert _media_sha(img) == man["sha256"]
        assert img.metadata["acquisition_commandline"].endswith("aff-enc-pass.aff source.raw")


@pytest.mark.skipif(ewfprobe._AES is None and not _CRYPTO_REQUIRED,  # pylint: disable=protected-access
                    reason="encrypted AFF needs the optional pycryptodome package")
def test_the_key_segment_padded_to_56_bytes_opens_and_another_version_does_not(tmp_path):
    """Some AFFLIB builds wrote affkey_aes256 padded to 56 bytes (lib/crypto.cpp);
    only version 1 is defined."""
    man = _manifest()
    section = man["encrypted_aff"]
    source = os.path.join(FIXTURES, section["variants"]["aff-enc-pass"]["files"][0])
    with open(source, "rb") as fh:
        data = fh.read()
    (name, arg, start, end), = [s for s in _aff_segments(data) if s[0] == "affkey_aes256"]
    stored = data[start + 16 + len(name):end - 8]
    assert len(stored) == 52
    padded = tmp_path / "padded.aff"
    padded.write_bytes(data[:start] + _aff_segment_bytes(name, stored + bytes(4), arg)
                       + data[end:])
    with ewfprobe.open_ewf(str(padded), password=section["password"]) as img:
        assert _media_sha(img) == man["sha256"]
    other = tmp_path / "version2.aff"
    other.write_bytes(data[:start] + _aff_segment_bytes(
        name, struct.pack(">I", 2) + stored[4:], arg) + data[end:])
    with pytest.raises(ewfprobe.EwfFormatError, match="version 2, not 1"):
        ewfprobe.open_ewf(str(other), password=section["password"])

"""Tests for the AFF4 reader.

Three sources, kept apart because they prove different things:

* The AFF4 reference images (github.com/aff4/ReferenceImages, Evimetry 2.x and 3.x,
  standard and pre-standard, one striped over two files, one 9-exabyte sparse). They
  carry no licence, so they are not in this repository; these tests read them from
  the folder EWFPROBE_AFF4_REFERENCE names, laid out as in that repository at commit
  84773b088bf6cce551a515d8ebb486bad69b58b8, and CI fetches them there. The expected
  SHA-1 of each image is the one pyaff4's own tests record (pyaff4/hashing_test.py at
  6a91158661edec6ed8a865a09e28dbf30d487e38), and every hash the images record about
  themselves has to verify.
* pyaff4-<method>.aff4, written by pyaff4 over known content.
* aff4-<case>.aff4, written by tools/make_aff4_fixtures.py with chunks compressed by
  the lz4, python-snappy and zlib libraries: what neither of the above carries.

The expected MD5s of the last two come from the plain bytes the generator wrote,
before any AFF4 encoding, so they do not depend on this reader.
"""

import hashlib
import os
import shutil
import sys
import zlib

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ewfprobe  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
KNOWN = "8dd04764855150cb5ac7f36dd584571d"      # content(), mapped with a gap and FF
MADE = {
    "pyaff4-stored.aff4": (KNOWN, "stored"),
    "pyaff4-snappy.aff4": (KNOWN, "snappy"),
    "pyaff4-zlib.aff4": (KNOWN, "zlib"),
    "pyaff4-lz4.aff4": (KNOWN, "lz4"),
    "aff4-lz4-raw.aff4": (KNOWN, "lz4"),
    "aff4-deflate-zlibstream.aff4": (KNOWN, "deflate"),
    "aff4-deflate-raw.aff4": (KNOWN, "deflate"),
    "aff4-snappy-always.aff4": ("86d00d95efee2c565dd9f793b55a2d93", "snappy-always"),
    "aff4-gap-unknown.aff4": ("7bf5585b15b110e0eca6947dd5292494", "stored"),
    "aff4-striped_1.aff4": ("66fae939a0fd6b5b9608aa0a1615a71c", "stored"),
    "aff4-striped_2.aff4": ("66fae939a0fd6b5b9608aa0a1615a71c", "stored"),
}


def _fixture(name):
    return os.path.join(FIXTURES, name)


@pytest.mark.parametrize("name", sorted(MADE))
def test_each_container_reads_back_its_content(name):
    want, codec = MADE[name]
    assert ewfprobe.is_image(_fixture(name))
    with ewfprobe.open_ewf(_fixture(name)) as img:
        assert img.format == ewfprobe.FORMAT_AFF4
        assert img.compression_level == codec
        assert hashlib.md5(img.read()).hexdigest() == want
        # a read that starts inside a chunk and crosses into the next
        img.seek(4096 - 7)
        part = img.read(8200)
        img.seek(0)
        assert part == img.read()[4096 - 7:4096 - 7 + 8200]


def test_pyaff4_lz4_chunks_carry_a_length_prefix_and_c_aff4_ones_do_not():
    """The two LZ4 forms: pyaff4's has python-lz4's four-byte length in front, the
    raw block c-aff4 writes does not; both read."""
    for name, prefixed in (("pyaff4-lz4.aff4", True), ("aff4-lz4-raw.aff4", False)):
        with ewfprobe.open_ewf(_fixture(name)) as img:
            stream = img._aff4_parts()[1][0]
            offset, length = stream.bevy_index(0)[3]
            raw = img._aff4.read_member(stream.bevy(0), offset, length)
            assert length < stream.chunk_size
            assert (int.from_bytes(raw[:4], "little") == stream.chunk_size) is prefixed


def test_a_gap_reads_from_the_maps_default_stream_at_its_own_offset():
    """aff4:mapGapDefaultStream (AFF4 Standard 4): the gap reads UnknownData, the
    string repeated from the 1 MiB tile boundary, at the image offset. No sample has
    a gap stream other than aff4:Zero, so this is a constructed case."""
    with ewfprobe.open_ewf(_fixture("aff4-gap-unknown.aff4")) as img:
        start = 5 * 4096 + 100
        img.seek(start)
        got = img.read(3 * 4096)
        assert got == bytes(b"UNKNOWN"[(o % (1 << 20)) % 7]
                            for o in range(start, start + 3 * 4096))
        assert ("(in no map range; read from UnknownData)", 3 * 4096) in img.aff4["coverage"]


def test_a_striped_half_alone_is_refused_as_incomplete(tmp_path):
    shutil.copy(_fixture("aff4-striped_1.aff4"), tmp_path)
    with pytest.raises(ewfprobe.EwfIncompleteSetError, match="none of the AFF4 files"):
        with ewfprobe.open_ewf(str(tmp_path / "aff4-striped_1.aff4")) as img:
            img.read()


def test_an_unrelated_container_beside_a_striped_one_is_not_joined(tmp_path):
    for name in ("aff4-striped_1.aff4", "aff4-striped_2.aff4", "aff4-lz4-raw.aff4"):
        shutil.copy(_fixture(name), tmp_path)
    with ewfprobe.open_ewf(str(tmp_path / "aff4-striped_1.aff4")) as img:
        assert sorted(os.path.basename(p) for p in img.paths) == [
            "aff4-striped_1.aff4", "aff4-striped_2.aff4"]
    with ewfprobe.open_ewf(str(tmp_path / "aff4-lz4-raw.aff4")) as img:
        assert [os.path.basename(p) for p in img.paths] == ["aff4-lz4-raw.aff4"]


@pytest.mark.parametrize("name, error", [
    ("aff4-overlapping-map.aff4", "overlapping ranges"),
    ("aff4-encrypted-stream.aff4", "encrypted AFF4 stream"),
])
def test_what_is_not_read_is_refused_by_name(name, error):
    with pytest.raises(ewfprobe.EwfFormatError, match=error):
        ewfprobe.open_ewf(_fixture(name))


def test_an_ordinary_zip_is_not_taken_for_aff4(tmp_path):
    import zipfile                                          # noqa: PLC0415
    path = tmp_path / "plain.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("information.turtle", "not aff4")
    assert not ewfprobe.is_aff4(str(path))
    assert not ewfprobe.is_image(str(path))


def test_a_missing_bevy_is_refused_rather_than_read_as_empty(tmp_path):
    import zipfile                                          # noqa: PLC0415
    src = _fixture("aff4-lz4-raw.aff4")
    out = tmp_path / "cut.aff4"
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(out, "w") as zout:
        for info in zin.infolist():
            if not info.filename.endswith("/00000001"):
                zout.writestr(info, zin.read(info))
        zout.comment = zin.comment
    with pytest.raises(ewfprobe.EwfIncompleteSetError):
        ewfprobe.open_ewf(str(out))


# ----------------------------------------------------------- the decoders

def test_snappy_examples_from_its_format_description():
    # "xababab": the literal "xab", then a copy of 4 from 2 back (a 2-byte offset copy)
    stream = bytes([7, (3 - 1) << 2]) + b"xab" + bytes([((4 - 1) << 2) | 2, 2, 0])
    assert ewfprobe._snappy_decompress(stream) == b"xababab"
    # a 1-byte offset copy, and a literal whose length takes a following byte
    lit = bytes(range(70))
    stream = bytes([74, 60 << 2, 69]) + lit + bytes([((4 - 4) << 2) | 1, 70])
    assert ewfprobe._snappy_decompress(stream) == lit + lit[:4]


@pytest.mark.parametrize("bad", [
    bytes([4, 0, 0x41, 1 | 0, 0]),                  # a copy with offset 0
    bytes([8, 0, 0x41, 1 | (4 << 2), 9]),           # a copy from before the start
    bytes([5, 4 << 2, 0x41]),                       # a literal longer than the data
    bytes([9, 0, 0x41]),                            # shorter than it declares
])
def test_snappy_refuses_what_its_format_rules_out(bad):
    with pytest.raises(ewfprobe.EwfFormatError):
        ewfprobe._snappy_decompress(bad)


def test_lz4_examples_from_its_block_format():
    # "abcd" then a match of 8 from 4 back, then 5 closing literals
    block = bytes([0x44]) + b"abcd" + bytes([4, 0]) + bytes([0x50]) + b"vwxyz"
    assert ewfprobe._lz4_block_decompress(block) == b"abcd" + b"abcdabcd" + b"vwxyz"
    # a literal length of 48: 15 in the token, then 33
    block = bytes([0xF0, 33]) + bytes(range(48))
    assert ewfprobe._lz4_block_decompress(block) == bytes(range(48))
    with pytest.raises(ewfprobe.EwfFormatError):
        ewfprobe._lz4_block_decompress(bytes([0x14]) + b"a" + bytes([0, 0]))   # offset 0


def test_inflate_takes_a_zlib_stream_a_raw_one_and_ignores_what_follows():
    data = b"deflate me " * 400
    raw = zlib.compressobj(9, zlib.DEFLATED, -15)
    raw = raw.compress(data) + raw.flush()
    assert ewfprobe._aff4_inflate(zlib.compress(data) + bytes(17)) == data
    assert ewfprobe._aff4_inflate(raw) == data
    with pytest.raises(ewfprobe.EwfFormatError):
        ewfprobe._aff4_inflate(b"\x00\x01not deflate at all")


def test_turtle_reads_what_the_writers_produce():
    text = """@prefix : <aff4://vol> .
@prefix aff4: <http://aff4.org/Schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@base <aff4://base> .
<aff4://img> a aff4:Image , aff4:DiskImage ;
    aff4:size 994662584320 ;
    aff4:hash "ab"^^aff4:MD5 , "cd"^^aff4:SHA1 ;
    aff4:notes \"\"\"two
lines\"\"\" ;
    aff4:stored <> ;
    aff4:flag true ;
    aff4:blank [ aff4:x "y"@en ] .
: a aff4:ZipVolume .
"""
    g = ewfprobe._turtle(text)
    img = g["aff4://img"]
    ns = "http://aff4.org/Schema#"
    assert {o[1] for o in img[ewfprobe._RDF_TYPE]} == {ns + "Image", ns + "DiskImage"}
    assert img[ns + "size"] == [("lit", "994662584320",
                                 "http://www.w3.org/2001/XMLSchema#integer")]
    assert img[ns + "hash"] == [("lit", "ab", ns + "MD5"), ("lit", "cd", ns + "SHA1")]
    assert img[ns + "notes"][0][1] == "two\nlines"
    assert img[ns + "stored"] == [("iri", "aff4://base")]
    assert "aff4://vol" in g


# ------------------------------------------------ the AFF4 reference images

REFERENCE = os.environ.get("EWFPROBE_AFF4_REFERENCE")
_REQUIRED = bool(os.environ.get("EWFPROBE_REQUIRE_AFF4_REFERENCE"))
# SHA-1 of each whole image, as pyaff4's hashing_test.py records them
REFERENCE_SHA1 = {
    "AFF4PreStd/Base-Linear.af4": "5d5f183ae7355b8dc8938b67aab77c0215c29ab4",
    "AFF4PreStd/Base-Allocated.af4": "a9f21b04a0a77613a5a34ecdd3af269464984035",
    "AFF4Std/Base-Linear.aff4": "7d3d27f667f95f7ec5b9d32121622c0f4b60b48d",
    "AFF4Std/Base-Linear-AllHashes.aff4": "7d3d27f667f95f7ec5b9d32121622c0f4b60b48d",
    "AFF4Std/Base-Linear-ReadError.aff4": "67e245a640e2784ead30c1ff1a3f8d237b58310f",
    "AFF4Std/Base-Allocated.aff4": "e8650e89b262cf0b4b73c025312488d5a6317a26",
    "AFF4Std/Striped/Base-Linear_1.aff4": "7d3d27f667f95f7ec5b9d32121622c0f4b60b48d",
    "AFF4Std/Striped/Base-Linear_2.aff4": "7d3d27f667f95f7ec5b9d32121622c0f4b60b48d",
}
_ALL_REFERENCE = sorted(REFERENCE_SHA1) + ["AFF4PreStd/Base-Linear-ReadError.af4",
                                           "Errata/Base-ExabyteSparse.aff4"]


def _reference(name):
    path = os.path.join(REFERENCE or "", name)
    if not REFERENCE or not os.path.exists(path):
        if _REQUIRED:
            pytest.fail(f"the AFF4 reference image {name} is not in {REFERENCE!r}")
        pytest.skip("set EWFPROBE_AFF4_REFERENCE to a checkout of aff4/ReferenceImages")
    return path


@pytest.mark.parametrize("name", sorted(REFERENCE_SHA1))
def test_reference_image_reads_as_pyaff4_records(name):
    with ewfprobe.open_ewf(_reference(name)) as img:
        assert img.media_size == 268435456
        digest = hashlib.sha1()
        while True:
            piece = img.read(1 << 22)
            if not piece:
                break
            digest.update(piece)
        assert digest.hexdigest() == REFERENCE_SHA1[name]
        if "Striped" in name:
            assert len(img.paths) == 2


@pytest.mark.parametrize("name", _ALL_REFERENCE)
def test_every_hash_a_reference_image_records_verifies(name):
    with ewfprobe.open_ewf(_reference(name)) as img:
        result = img.verify()
    checks = result["container_checks"]
    assert checks and all(c["match"] for c in checks), [c for c in checks if not c["match"]]
    kinds = {c["what"].split(" ")[0] for c in checks}
    assert {"image", "chunk"} <= kinds
    if name.startswith("AFF4Std/Base-Linear.aff4"):
        # the chain through to the image's own hash: map, block map, image
        assert any(c["what"].startswith("image aff4://") for c in checks)


def test_the_exabyte_sparse_image_reads_at_both_ends():
    """Errata/Base-ExabyteSparse.aff4: 1 MiB of 0xFF at 0 and just before the end of
    a 0x7ffffffffffffe00-byte image, as its README describes, and zeros between."""
    with ewfprobe.open_ewf(_reference("Errata/Base-ExabyteSparse.aff4")) as img:
        assert img.media_size == 0x7FFFFFFFFFFFFE00
        assert img.read(1 << 20) == b"\xff" * (1 << 20)
        img.seek(0x7FFFFFFFFFEFFE00)
        assert img.read() == b"\xff" * (1 << 20)
        img.seek(0x100000000000)
        assert img.read(4096) == bytes(4096)


def test_a_read_error_reads_as_the_unreadable_data_stream():
    with ewfprobe.open_ewf(_reference("AFF4Std/Base-Linear-ReadError.aff4")) as img:
        assert ("UnreadableData", 2097152) in img.aff4["coverage"]
        img.seek(0xF00000)
        assert img.read(28) == b"UNREADABLEDATAUNREADABLEDATA"

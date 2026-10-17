"""Tests for the LZFSE and LZVN decoders an ULFO .dmg needs.

The decoders are a byte-identical copy of qnxprobe.py's (tools/shared_lzfse.py), so
the first test pins that copy: editing it here alone fails, and the fix belongs in
qnxprobe.py first. Set EWFPROBE_QNXPROBE to a qnxprobe.py to compare against it too.

The streams in fixtures/lzfse-streams.json are qnxprobe's
tests/fixtures/decmpfs-streams.json at v1.74 (commit dffd27a), written by its
tools/make_decmpfs_streams.py:
Apple's libcompression encoded each one and decoded it back before it was kept, so
neither side of it is the decoder under test. The ULFO image hdiutil wrote is the
other oracle; test_reference_fixtures.py checks it decodes to its source disk.
"""

import base64
import hashlib
import json
import os
import struct
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import ewfprobe  # noqa: E402
import shared_lzfse  # noqa: E402

FIXTURES = os.path.join(ROOT, "tests", "fixtures")
ULFO = os.path.join(FIXTURES, "dmg-ulfo.dmg")

# The SHA-256 of the shared pieces (tools/shared_lzfse.py digest ewfprobe.py), the
# same as qnxprobe v1.74's (commit dffd27a). When
# qnxprobe.py's decoder changes, copy it with tools/shared_lzfse.py sync and update
# this; never edit the pieces here by hand.
SHARED_DIGEST = "b1ee1ea34580962261bc42415309d12f212bfe6c23765dc3288543d39fd41537"


def _source():
    with open(os.path.join(ROOT, "ewfprobe.py"), encoding="utf-8", newline="") as fh:
        return fh.read()


def _streams():
    with open(os.path.join(FIXTURES, "lzfse-streams.json"), encoding="utf-8") as fh:
        return json.load(fh)["streams"]


def _ulfo_chunks():
    """(blob, decoded size) of every LZFSE chunk in the hdiutil ULFO fixture."""
    img = ewfprobe.open_ewf(ULFO)
    try:
        return [(img._fork_read(offset, stored), length)
                for _start, length, kind, offset, stored in img._runs
                if ewfprobe._UDIF_CODECS.get(kind) == "LZFSE"]
    finally:
        img.close()


def _manifest_sha(name):
    with open(os.path.join(FIXTURES, "manifest.json"), encoding="utf-8") as fh:
        man = json.load(fh)
    assert name in man["variants"]
    return man["sha256"]


# ------------------------------------------------------- the shared copy

def test_the_shared_decoder_is_the_pinned_copy():
    assert shared_lzfse.digest(_source()) == SHARED_DIGEST


def test_the_shared_decoder_matches_qnxprobe_when_given():
    other = os.environ.get("EWFPROBE_QNXPROBE")
    if not other:
        pytest.skip("EWFPROBE_QNXPROBE names no qnxprobe.py to compare with")
    with open(other, encoding="utf-8", newline="") as fh:
        assert shared_lzfse.pieces(fh.read()) == shared_lzfse.pieces(_source())


def test_the_pieces_are_found_by_name_and_a_change_shows():
    text = _source()
    first, second = shared_lzfse.pieces(text)
    assert first.startswith("class DecompressError(Exception):")
    assert second.startswith("# LZVN opcode kinds,")
    assert second.rstrip().endswith('magic {magic!r} at byte {pos:,}")')
    changed = text.replace("_LZFSE_MATCHES_PER_BLOCK = 10000",
                           "_LZFSE_MATCHES_PER_BLOCK = 10001", 1)
    assert changed != text
    assert shared_lzfse.digest(changed) != SHARED_DIGEST


# ------------------------------------------------- streams Apple encoded

@pytest.mark.parametrize("entry", _streams(), ids=lambda e: e["name"])
def test_apples_streams_decode_to_what_they_were_made_from(entry):
    blob = base64.b64decode(entry["stream"])
    if entry["codec"] == "LZFSE":
        out = ewfprobe.lzfse_decompress(blob, entry["size"])
    else:
        out, end = ewfprobe.lzvn_decompress(blob, entry["size"])
        assert end == len(blob)
        out = bytes(out)
    assert len(out) == entry["size"]
    assert hashlib.sha256(out).hexdigest() == entry["sha256"]


def test_every_block_kind_is_among_the_streams():
    kinds = {k for e in _streams() for k in e["blocks"]}
    assert kinds == {"bvx-", "bvxn", "bvx1", "bvx2", "bvx$"}
    assert any(e["codec"] == "LZVN" for e in _streams())


# ----------------------------------------------------------- ULFO images

@pytest.mark.skipif(not os.path.exists(ULFO), reason="reference fixtures absent")
def test_an_ulfo_image_reads_with_no_package_installed(tmp_path):
    """In a fresh interpreter where importing liblzfse fails, the hdiutil ULFO image
    still opens and reads back to the disk it was made from."""
    script = tmp_path / "run.py"
    script.write_text(
        "import hashlib, sys\n"
        "class Block:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name.split('.')[0] == 'liblzfse':\n"
        "            raise ImportError('blocked for the test')\n"
        "sys.meta_path.insert(0, Block())\n"
        f"sys.path.insert(0, {ROOT!r})\n"
        "import ewfprobe\n"
        "h = hashlib.sha256()\n"
        f"with ewfprobe.open_ewf({ULFO!r}) as img:\n"
        "    assert img.compression_level == 'LZFSE', img.compression_level\n"
        "    while True:\n"
        "        b = img.read(1 << 20)\n"
        "        if not b:\n"
        "            break\n"
        "        h.update(b)\n"
        "assert 'liblzfse' not in sys.modules\n"
        "print(h.hexdigest())\n", encoding="utf-8")
    out = subprocess.run([sys.executable, str(script)], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, check=True).stdout.strip()
    assert out == _manifest_sha("dmg-ulfo")


@pytest.mark.skipif(not os.path.exists(ULFO), reason="reference fixtures absent")
def test_each_ulfo_chunk_ends_exactly_at_its_end_marker():
    chunks = _ulfo_chunks()
    assert chunks
    for blob, length in chunks:
        assert blob.endswith(b"bvx$")
        assert len(ewfprobe.lzfse_decompress(blob, length)) == length


# --------------------------------------------------------- hostile input

def _damaged_image(tmp_path, change):
    """A copy of the ULFO fixture with its first LZFSE chunk's stored bytes passed
    through ``change`` (same length, so the block table still fits)."""
    img = ewfprobe.open_ewf(ULFO)
    try:
        _start, _length, _kind, offset, stored = next(
            r for r in img._runs if ewfprobe._UDIF_CODECS.get(r[2]) == "LZFSE")
        base = img._forks[0][2]
    finally:
        img.close()
    with open(ULFO, "rb") as fh:
        data = bytearray(fh.read())
    piece = bytes(data[base + offset:base + offset + stored])
    new = change(piece)
    assert len(new) == len(piece) and new != piece
    data[base + offset:base + offset + stored] = new
    path = tmp_path / "damaged.dmg"
    path.write_bytes(bytes(data))
    return str(path)


def _read_all(path):
    with ewfprobe.open_ewf(path) as img:
        while img.read(1 << 20):
            pass


@pytest.mark.skipif(not os.path.exists(ULFO), reason="reference fixtures absent")
@pytest.mark.parametrize("change, why", [
    (lambda b: b[:-4] + b"bvx?", "unknown LZFSE block magic"),
    (lambda b: b"bvx9" + b[4:], "unknown LZFSE block magic"),
    # the first block's decoded size, one byte more than its header said
    (lambda b: b[:4] + struct.pack("<I", struct.unpack_from("<I", b, 4)[0] + 1) + b[8:],
     "LZFSE block gives"),
    # a decoded size larger than the chunk may hold, refused before decoding
    (lambda b: b[:4] + struct.pack("<I", 0xFFFFFFF0) + b[8:], "more than the"),
], ids=["end marker", "first magic", "block size", "size past the chunk"])
def test_a_damaged_chunk_is_refused_by_name(tmp_path, change, why):
    path = _damaged_image(tmp_path, change)
    with pytest.raises(ewfprobe.EwfFormatError) as caught:
        _read_all(path)
    message = str(caught.value)
    assert "LZFSE chunk at sector" in message and why in message, message


@pytest.mark.skipif(not os.path.exists(ULFO), reason="reference fixtures absent")
def test_a_cut_chunk_is_refused_not_zero_filled():
    blob, length = _ulfo_chunks()[0]
    for cut in (0, 3, 4, 31, len(blob) // 2, len(blob) - 5, len(blob) - 1):
        with pytest.raises(ewfprobe.DecompressError):
            ewfprobe.lzfse_decompress(blob[:cut], length)


def test_declared_sizes_are_bounded_before_any_output():
    # a raw block naming 4 GiB, with 4 bytes behind it
    with pytest.raises(ewfprobe.DecompressError, match="cut short"):
        ewfprobe.lzfse_decompress(b"bvx-" + struct.pack("<I", 0xFFFFFFFF) + b"abcd", 1 << 20)
    # a raw block whose bytes are all there, but more than the caller expects
    with pytest.raises(ewfprobe.DecompressError, match="more than 3 bytes"):
        ewfprobe.lzfse_decompress(b"bvx-" + struct.pack("<I", 4) + b"abcd" + b"bvx$", 3)
    # an LZVN block naming more output than the limit
    with pytest.raises(ewfprobe.DecompressError, match="more than"):
        ewfprobe.lzfse_decompress(b"bvxn" + struct.pack("<II", 0x7FFFFFFF, 8)
                                  + b"\x06" + bytes(7) + b"bvx$", 1 << 20)
    # an LZVN match reaching before the first byte
    with pytest.raises(ewfprobe.DecompressError, match="before"):
        ewfprobe.lzvn_decompress(b"\x01\x05" + b"\x06" + bytes(7), 100)
    # an undefined LZVN opcode
    with pytest.raises(ewfprobe.DecompressError, match="undefined LZVN opcode"):
        ewfprobe.lzvn_decompress(b"\x70" + b"\x06" + bytes(7), 100)

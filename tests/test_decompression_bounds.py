"""A compressed chunk may not decode to more than the size its container gives it.

Each container records, or implies, how large a decoded chunk is: a UDIF block table
entry its sector count, an E01 or Ex01 its chunk size, an AFF its page size, an AD1,
AFF4, VMDK or QCOW its chunk, grain or cluster. A chunk built to inflate far past that
(a decompression bomb, here a long run of zeros in a few bytes) is refused, naming
the chunk, and the decoder is never asked for more than one byte past the size. The
bombs are made here, from the standard library's own compressors.
"""

import bz2
import lzma
import os
import struct
import sys
import tracemalloc
import zlib

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ewfprobe  # noqa: E402
import test_apple_images as apple  # noqa: E402
import test_ewfprobe as ewf  # noqa: E402

BOMB = 16 << 20                                   # what each bomb inflates to


def _bomb(codec, size=BOMB):
    """``size`` zero bytes compressed with ``codec``, fed in pieces so the test
    never holds the inflated bytes itself."""
    c = {"zlib": lambda: zlib.compressobj(9), "deflate": lambda: zlib.compressobj(
        9, zlib.DEFLATED, -15), "bzip2": bz2.BZ2Compressor,
         # a 1 MiB dictionary, so what the decoder allocates is its output, not
         # the 8 MiB dictionary of the default preset
         "lzma": lambda: lzma.LZMACompressor(filters=[{"id": lzma.FILTER_LZMA2,
                                                         "dict_size": 1 << 20}])}[codec]()
    piece, out = bytes(min(size, 1 << 20)), bytearray()
    for _ in range(size // len(piece)):
        out += c.compress(piece)
    return bytes(out + c.flush())


_UDIF_KIND = {"zlib": 0x80000005, "bzip2": 0x80000006, "lzma": 0x80000008}


# ---------------------------------------------------------------- UDIF

@pytest.mark.parametrize("codec", sorted(_UDIF_KIND))
def test_a_udif_bomb_is_refused_without_inflating_it(tmp_path, codec):
    bomb = _bomb(codec)
    data = apple._disk(16)
    blobs = [bomb, zlib.compress(data[4096:])]   # the first chunk is the bomb
    path = apple.write_udif(tmp_path / "bomb.dmg", data,
                            tables=[[(_UDIF_KIND[codec], 8), (apple.ZLIB, 8)]],
                            encode=lambda kind, piece: blobs.pop(0))
    tracemalloc.start()
    try:
        with ewfprobe.open_ewf(path) as img:
            with pytest.raises(ewfprobe.EwfFormatError) as caught:
                img.read(4096)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    message = str(caught.value)
    assert "chunk at sector 0" in message and "more than 4,096 bytes" in message, message
    assert peak < 2 << 20, f"{peak:,} bytes allocated reading a 4,096-byte chunk"


@pytest.mark.parametrize("codec", sorted(_UDIF_KIND))
def test_a_udif_chunk_that_decodes_short_or_cut_is_refused(tmp_path, codec):
    data = apple._disk(16)
    make = {"zlib": zlib.compress, "bzip2": bz2.compress, "lzma": lzma.compress}[codec]
    for name, encode in (("short", lambda kind, piece: make(piece[:-1])),
                         ("cut", lambda kind, piece: make(piece)[:-6])):
        path = apple.write_udif(tmp_path / f"{name}.dmg", data,
                                tables=[[(_UDIF_KIND[codec], 16)]], encode=encode)
        with ewfprobe.open_ewf(path) as img:
            with pytest.raises(ewfprobe.EwfFormatError, match="chunk at sector 0"):
                img.read(512)


@pytest.mark.parametrize("codec", ["bzip2", "lzma"])
def test_bytes_after_a_udif_bzip2_or_lzma_stream_are_refused(tmp_path, codec):
    data = apple._disk(16)
    make = {"bzip2": bz2.compress, "lzma": lzma.compress}[codec]
    path = apple.write_udif(tmp_path / "tail.dmg", data, tables=[[(_UDIF_KIND[codec], 16)]],
                            encode=lambda kind, piece: make(piece) + b"junk")
    with ewfprobe.open_ewf(path) as img:
        with pytest.raises(ewfprobe.EwfFormatError, match="follow the end"):
            img.read(512)


# ------------------------------------------------------------- E01 and AFF

def _with_bomb_for(monkeypatch, marker, bomb):
    """Make zlib.compress return ``bomb`` for the one input equal to ``marker``, so a
    writer that compresses each chunk itself stores the bomb in that chunk's place."""
    real = zlib.compress

    def compress(data, *args, **kwargs):
        return bomb if data == marker else real(data, *args, **kwargs)
    monkeypatch.setattr(zlib, "compress", compress)


def test_an_e01_chunk_that_inflates_past_its_chunk_is_refused(tmp_path, monkeypatch):
    chunk = b"A" * 1024
    bomb = _bomb("zlib", 512 << 10)               # under 1,024 bytes, so it is stored
    assert len(bomb) < len(chunk)
    data = chunk + b"B" * 1024
    _with_bomb_for(monkeypatch, chunk, bomb)
    paths = ewf.write_ewf(str(tmp_path), "bomb", data)
    monkeypatch.undo()
    with ewfprobe.open_ewf(paths[0]) as img:
        with pytest.raises(ewfprobe.EwfFormatError, match=r"chunk 0: .*more than 1,024"):
            img.read(1024)


def test_an_aff_page_that_inflates_past_its_page_is_refused(tmp_path, monkeypatch):
    page = b"C" * 1024
    _with_bomb_for(monkeypatch, page, _bomb("zlib", 512 << 10))
    path = ewf.write_aff(tmp_path / "bomb.aff", page + b"D" * 1024, kinds="zz")
    monkeypatch.undo()
    with ewfprobe.open_ewf(path) as img:
        with pytest.raises(ewfprobe.EwfFormatError, match=r"page 0: .*more than 1,024"):
            img.read(1024)


# ----------------------------------------------- the decoders, one by one

@pytest.mark.parametrize("codec", ["zlib", "bzip2", "lzma"])
def test_the_bounded_decompressor_never_returns_past_its_limit(codec):
    bomb = _bomb(codec)
    tracemalloc.start()
    try:
        with pytest.raises(ewfprobe.EwfFormatError, match="more than 4,096 bytes"):
            ewfprobe._decompress_bounded(codec, bomb, 4096)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 2 << 20
    exact = {"zlib": zlib.compress, "bzip2": bz2.compress, "lzma": lzma.compress}[codec]
    assert ewfprobe._decompress_bounded(codec, exact(b"x" * 4096), 4096) == b"x" * 4096


def test_an_aff4_deflate_bomb_is_refused():
    for codec in ("zlib", "deflate"):
        with pytest.raises(ewfprobe.EwfFormatError, match="more than 4,096 bytes"):
            ewfprobe._aff4_inflate(_bomb(codec, 1 << 20), 4096)


def test_a_snappy_chunk_declaring_more_than_a_chunk_is_refused_before_decoding():
    size, varint = 1 << 30, bytearray()            # the declared length, as a varint
    while True:
        byte = size & 0x7F
        size >>= 7
        varint.append(byte | (0x80 if size else 0))
        if not size:
            break
    with pytest.raises(ewfprobe.EwfFormatError, match="more than the 4,096"):
        ewfprobe._snappy_decompress(bytes(varint) + b"\x00a", 4096)


def test_an_lz4_match_past_the_chunk_is_refused_before_it_is_copied():
    # one literal "a", then a match of 15 + 4 + 255 * 4000 + 0 from one byte back
    block = bytes([0x1F]) + b"a" + struct.pack("<H", 1) + b"\xff" * 4000 + b"\x00"
    tracemalloc.start()
    try:
        with pytest.raises(ewfprobe.EwfFormatError, match="more than 4,096 bytes"):
            ewfprobe._lz4_block_decompress(block, 4096)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 1 << 20


def test_an_lzma_header_asking_for_a_huge_dictionary_is_refused():
    # an .lzma (alone) stream whose header's dictionary size is rewritten to 4 GiB - 1
    good = lzma.compress(b"x" * 4096, format=lzma.FORMAT_ALONE)
    huge = good[:1] + struct.pack("<I", 0xFFFFFFFF) + good[5:]
    with pytest.raises(ewfprobe.EwfFormatError, match="does not decompress"):
        ewfprobe._decompress_bounded("lzma", huge, 4096)


@pytest.mark.parametrize("codec", ["bzip2", "lzma"])
def test_two_streams_in_one_udif_chunk_are_refused(tmp_path, codec):
    # bz2.decompress and lzma.decompress join concatenated streams; a chunk is one
    data = apple._disk(16)
    make = {"bzip2": bz2.compress, "lzma": lzma.compress}[codec]
    path = apple.write_udif(tmp_path / "two.dmg", data, tables=[[(_UDIF_KIND[codec], 16)]],
                            encode=lambda kind, piece: make(piece[:4096]) + make(piece[4096:]))
    with ewfprobe.open_ewf(path) as img:
        with pytest.raises(ewfprobe.EwfFormatError, match="follow the end"):
            img.read(512)

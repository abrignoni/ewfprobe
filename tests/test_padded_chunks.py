"""A chunk, grain or cluster whose data runs out is read with zeros, as before, and is
now listed in ``padded_chunks`` and by ``verify``.

An E01 chunk whose zlib stream is cut, a VMDK grain and a QCOW cluster whose streams
decode to half their size are each built here from a clean image. Each must read as
the bytes it decodes to followed by zeros, which is what ewfprobe 0.13.0 read, and be
listed once with where it is. A clean image, including an E01 whose last chunk is
partial because the disk is not a whole number of chunks, lists nothing.
"""

import gzip
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

VIRTUAL = os.path.join(HERE, "fixtures", "virtual")


def _read_all(img):
    img.seek(0)
    return img.read()


def _unpack(folder, name, where):
    target = os.path.join(where, name)
    with gzip.open(os.path.join(VIRTUAL, folder, name + ".gz")) as src, \
            open(target, "wb") as dst:
        shutil.copyfileobj(src, dst)
    return target


# ---------------------------------------------------------------- E01

def _e01_with(tmp_path, monkeypatch, chunk, stored):
    """An E01 of three 1,024-byte chunks and a 512-byte tail whose second chunk,
    ``chunk``, is stored as ``stored`` in place of its zlib stream."""
    data = b"A" * 1024 + chunk + b"C" * 1024 + b"D" * 512
    real = zlib.compress
    monkeypatch.setattr(zlib, "compress", lambda d, *a, **k: stored if d == chunk
                        else real(d, *a, **k))
    paths = ewf.write_ewf(str(tmp_path), "pad", data)
    monkeypatch.undo()
    return paths[0], data


def test_a_clean_e01_with_a_partial_last_chunk_lists_nothing(tmp_path):
    data = ewf.sample_bytes()                     # its tail leaves the last chunk partial
    paths = ewf.write_ewf(str(tmp_path), "clean", data)
    with ewfprobe.open_ewf(paths[0]) as img:
        assert img.media_size % img.chunk_size
        _read_all(img)
        assert img.padded_chunks == []
        assert img.verify()["padded_chunks"] == []
        assert img.info()["padded_chunks"] == []


def test_a_cut_e01_chunk_reads_as_before_and_is_listed(tmp_path, monkeypatch, capsys):
    chunk = bytes(range(256)) * 4
    whole = zlib.compress(chunk, 6)
    cut = whole[:len(whole) // 2]
    inflated = zlib.decompressobj().decompress(cut)
    assert 0 < len(inflated) < 1024
    path, data = _e01_with(tmp_path, monkeypatch, chunk, cut)
    with ewfprobe.open_ewf(path) as img:
        got = _read_all(img)
        expected = data[:1024] + inflated + bytes(1024 - len(inflated)) + data[2048:]
        assert got == expected
        _read_all(img)                            # read again: still listed once
        assert img.padded_chunks == [{
            "unit": "chunk", "index": 1, "offset": 1024, "length": 1024,
            "decoded": len(inflated), "zeros": 1024 - len(inflated), "cut": True}]
        assert img.verify()["padded_chunks"] == img.padded_chunks
    assert ewfprobe.main(["verify", "-q", path]) in (0, 1)
    out = capsys.readouterr().out
    assert "chunks whose data ran out, read with zeros in its place: 1" in out
    assert "chunk 1 at byte 1,024" in out and "stream cut" in out


def test_a_complete_e01_stream_that_is_short_is_listed(tmp_path, monkeypatch):
    chunk = b"B" * 1024
    path, data = _e01_with(tmp_path, monkeypatch, chunk, zlib.compress(b"B" * 300))
    with ewfprobe.open_ewf(path) as img:
        assert _read_all(img) == data[:1024] + b"B" * 300 + bytes(724) + data[2048:]
        assert [(p["index"], p["decoded"], p["zeros"], p["cut"])
                for p in img.padded_chunks] == [(1, 300, 724, False)]


# ---------------------------------------------------------------- VMDK

def test_a_short_vmdk_grain_reads_as_before_and_is_listed(tmp_path):
    path = _unpack("qemu-compact", "vmdk-streamOptimized.vmdk", str(tmp_path))
    with ewfprobe.open_ewf(path) as img:
        clean = _read_all(img)
        assert img.padded_chunks == []
        grain = img._vmdk_extents[0]["grain"]
    data = bytearray(open(path, "rb").read())
    # walk qemu-img's grain markers from the first, for a grain whose second half is
    # not zeros, so the zeros read in its place differ from what it held
    at = 128 * 512
    while True:
        lba, size = struct.unpack_from("<QI", data, at)
        assert size, "no grain with data in its second half"
        decoded = zlib.decompress(bytes(data[at + 12:at + 12 + size]))
        if any(decoded[grain // 2:]):
            break
        at += -(-(12 + size) // 512) * 512
    index = lba * 512 // grain
    assert len(decoded) == grain
    half = zlib.compress(decoded[:grain // 2], 9)
    assert len(half) <= size
    data[at + 8:at + 12] = struct.pack("<I", len(half))
    data[at + 12:at + 12 + size] = half + bytes(size - len(half))
    open(path, "wb").write(bytes(data))
    with ewfprobe.open_ewf(path) as img:
        got = _read_all(img)
        start = index * grain
        assert got != clean
        assert got == (clean[:start] + decoded[:grain // 2] + bytes(grain - grain // 2)
                       + clean[start + grain:])
        listed = img.padded_chunks
    assert len(listed) == 1
    assert {k: listed[0][k] for k in ("unit", "index", "offset", "length", "decoded",
                                      "zeros", "cut")} == {
        "unit": "grain", "index": index, "offset": index * grain, "length": grain,
        "decoded": grain // 2, "zeros": grain - grain // 2, "cut": False}
    assert listed[0]["file"].endswith("vmdk-streamOptimized.vmdk")


# ---------------------------------------------------------------- QCOW

def _compressed_clusters(img):
    """(index, host offset, stored length) of each compressed cluster, in order."""
    cluster = img.qcow["cluster_size"]
    bits = cluster.bit_length() - 1
    for index in range(img.media_size // cluster):
        l1_index, l2_index = divmod(index, img._qcow_l2_entries)
        table = img._qcow_l2_table(l1_index) if l1_index < len(img._qcow_l1) else None
        entry = table[l2_index] if table else 0
        if entry & ewfprobe._QCOW_COMPRESSED:
            entry &= ~(ewfprobe._QCOW_COPIED | ewfprobe._QCOW_COMPRESSED)
            x = 62 - (bits - 8)
            offset = entry & ((1 << x) - 1)
            sectors = (entry >> x) & ((1 << (62 - x)) - 1)
            yield index, offset, (sectors + 1) * 512 - (offset & 511)


def test_a_short_qcow_cluster_reads_as_before_and_is_listed(tmp_path):
    path = _unpack("qemu-compact", "qcow2-zlib.qcow2", str(tmp_path))
    with ewfprobe.open_ewf(path) as img:
        clean = _read_all(img)
        assert img.padded_chunks == []
        cluster = img.qcow["cluster_size"]
        found = list(_compressed_clusters(img))
    data = bytearray(open(path, "rb").read())
    # the first compressed cluster whose second half is not zeros
    for index, offset, length in found:
        decoded = zlib.decompressobj(-15).decompress(bytes(data[offset:offset + length]))
        if any(decoded[cluster // 2:]):
            break
    else:
        raise AssertionError("no compressed cluster with data in its second half")
    assert decoded == clean[index * cluster:(index + 1) * cluster]
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    half = c.compress(decoded[:cluster // 2]) + c.flush()
    assert len(half) <= length
    # only the new stream is written: qemu-img packs compressed clusters end to end,
    # so the sectors this one's length covers can hold the start of the next one
    data[offset:offset + len(half)] = half
    open(path, "wb").write(bytes(data))
    with ewfprobe.open_ewf(path) as img:
        got = _read_all(img)
        start = index * cluster
        assert got != clean
        assert got == (clean[:start] + decoded[:cluster // 2] + bytes(cluster - cluster // 2)
                       + clean[start + cluster:])
        assert img.padded_chunks == [{
            "unit": "cluster", "index": index, "offset": start, "length": cluster,
            "decoded": cluster // 2, "zeros": cluster - cluster // 2, "cut": False}]


@pytest.mark.parametrize("folder, name", [("qemu-compact", "qcow2-zlib.qcow2"),
                                          ("qemu-compact", "vmdk-streamOptimized.vmdk")])
def test_clean_compressed_virtual_disks_list_nothing(tmp_path, folder, name):
    with ewfprobe.open_ewf(_unpack(folder, name, str(tmp_path))) as img:
        _read_all(img)
        assert img.padded_chunks == []

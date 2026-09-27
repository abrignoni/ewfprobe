"""Tests for the virtual disk readers: VHD, VHDX, VMDK and QCOW.

fixtures/virtual holds gzipped disks, each listed in manifest.json with the files it
needs and the SHA-256 and size of the disk it reads as:

  windows/              made by Windows 11 (10.0.26200) with diskpart: fixed, expandable
                        and differencing VHD and VHDX of 64 MiB holding NTFS; the known
                        answer is the disk as Windows presented it, read through
                        \\\\.\\PhysicalDriveN after a read-only attach
  qemu-compact/         made by qemu-img 10.2.1 from a 16 MiB GPT disk holding ext4, in
                        every VHD, VHDX, VMDK and QCOW form it writes; the answers are
                        that disk (padded to the CHS size qemu-img gives a VHD), a disk 7
                        sectors longer, and the disks the delta, overlay, snapshot and
                        zeroed samples should read as, made by plain file writes
  constructed-compact/  built from the formats' own documents: a VHDX whose log holds an
                        update not yet applied, an ESXi sparse extent, and a QCOW version
                        1 image with compressed clusters, which qemu-img 10.2.1 refused
                        to write; qemu reads all three as their answers

The full-size sets are on the corpus drive under Built_Test_Volumes/
virtual-disks-2026-09-27, with the scripts that made them.

EWFPROBE_VMDK_REFERENCE names VMware's Photon OS 2.0 OVA
(photon-custom-hw11-2.0-304b817.ova), whose stream-optimized VMDK VMware's own tools
wrote with the grain directory in a footer; EWFPROBE_REQUIRE_VMDK_REFERENCE makes its
absence a failure.
"""

import gzip
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import uuid

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ewfprobe  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
VIRTUAL = os.path.join(HERE, "fixtures", "virtual")
CASES = json.load(open(os.path.join(VIRTUAL, "manifest.json")))["cases"]
BY_NAME = {c["name"]: c for c in CASES}
_ZSTD = ewfprobe._zstd_decompressor() is not None
PHOTON_SHA1 = "b8c183785bbf582bcd1be7cde7c22e5758fb3f16"
PHOTON_DISK_SHA256 = "9d2c2ad3a3ee5922a7749da1dde4c830b3d577848f1074640792285737c70668"


def _unpack(case, where):
    """The case's files, ungzipped into ``where``; the path to open."""
    for name in case["files"]:
        with gzip.open(os.path.join(VIRTUAL, case["folder"], name + ".gz")) as src, \
                open(os.path.join(where, name), "wb") as dst:
            shutil.copyfileobj(src, dst)
    return os.path.join(where, case["open"])


def _digest(img):
    h = hashlib.sha256()
    img.seek(0)
    while True:
        piece = img.read(1 << 20)
        if not piece:
            break
        h.update(piece)
    return h.hexdigest()


def _crc32c(data):
    """CRC-32C written bit by bit, independent of the reader's table-driven one."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def _reader_cases():
    out = []
    for case in CASES:
        marks = []
        if case["name"] == "qemu-qcow2-zstd":
            marks.append(pytest.mark.skipif(not _ZSTD, reason="zstd needs Python 3.14 or "
                                                              "backports.zstd"))
        out.append(pytest.param(case, id=case["name"], marks=marks))
    return out


@pytest.mark.parametrize("case", _reader_cases())
def test_every_sample_reads_as_its_disk(tmp_path, case):
    path = _unpack(case, str(tmp_path))
    if case.get("refused"):
        with pytest.raises(ewfprobe.EwfFormatError, match=case["refused"]):
            ewfprobe.open_ewf(path)
        return
    with ewfprobe.open_ewf(path) as img:
        assert img.media_size == case["size"]
        assert _digest(img) == case["sha256"]


def test_a_differencing_disk_takes_each_sector_from_where_its_bitmap_says(tmp_path):
    # Windows wrote these children through a partly written block, so their bitmaps
    # hold bytes with bits both set and clear; reading a VHD bitmap least significant
    # bit first, or a VHDX one most significant bit first, gives another disk.
    for name, attr in (("windows-diff", "_vhd_bat"), ("windows-diffx", "_vhdx_bat")):
        case = BY_NAME[name]
        where = tmp_path / name
        where.mkdir()
        with ewfprobe.open_ewf(_unpack(case, str(where))) as img:
            assert img.parent is not None
            assert getattr(img, attr)
            assert _digest(img) == case["sha256"]


def test_the_format_is_named_from_the_bytes(tmp_path):
    kinds = {"windows-fixed": "VHD", "windows-dynamicx": "VHDX",
             "qemu-vmdk-streamOptimized": "VMDK", "qemu-qcow1": "QCOW",
             "qemu-qcow2-v3": "QCOW"}
    for name, kind in kinds.items():
        where = tmp_path / name
        where.mkdir()
        path = _unpack(BY_NAME[name], str(where))
        assert ewfprobe.virtual_disk_kind(path) == kind
        renamed = str(where / "evidence.bin")
        os.rename(path, renamed)
        assert ewfprobe.virtual_disk_kind(renamed) == kind
    raw = tmp_path / "plain.raw"
    raw.write_bytes(bytes(65536))
    assert ewfprobe.virtual_disk_kind(str(raw)) is None


def test_verify_reports_the_disk_hashes_with_nothing_stored(tmp_path):
    case = BY_NAME["qemu-vhdx-dynamic"]
    with ewfprobe.open_ewf(_unpack(case, str(tmp_path))) as img:
        result = img.verify()
        disk = hashlib.md5()
        img.seek(0)
        disk.update(img.read())
    assert result["match"] is None
    assert result["computed"]["MD5"] == disk.hexdigest()


def test_info_prints_each_format(tmp_path):
    for name, text in (("windows-diff", "parent locator  W2ru"),
                       ("windows-diffx", "relative_path"),
                       ("qemu-vmdk-delta", "content id"),
                       ("qemu-qcow2-overlay", "backing file"),
                       ("qemu-qcow2-snapshot", "snapshot        before-write"),
                       ("constructed-dirty-log", "1 entries replayed")):
        where = tmp_path / name
        where.mkdir()
        path = _unpack(BY_NAME[name], str(where))
        out = subprocess.run([sys.executable, os.path.join(os.path.dirname(HERE),
                                                           "ewfprobe.py"), "info", path],
                             capture_output=True, text=True, check=True).stdout
        assert text in out, name


# -- VHD ---------------------------------------------------------------------------

def _vhd_checksum(block, at):
    total = sum(block) - sum(block[at:at + 4])
    return (~total) & 0xFFFFFFFF


def _fix_footer(footer):
    footer = bytearray(footer)
    struct.pack_into(">I", footer, 64, _vhd_checksum(footer, 64))
    return footer


def test_a_vhd_footer_that_fails_its_checksum_is_read_from_its_copy(tmp_path):
    case = BY_NAME["windows-dynamic"]
    path = _unpack(case, str(tmp_path))
    data = bytearray(open(path, "rb").read())
    data[-512 + 100] ^= 0xFF                     # a reserved byte, so only the sum breaks
    open(path, "wb").write(data)
    with ewfprobe.open_ewf(path) as img:
        assert "copy at the start" in img.vhd["footer"]
        assert _digest(img) == case["sha256"]
    data[100] ^= 0xFF                            # break the copy too
    open(path, "wb").write(data)
    with pytest.raises(ewfprobe.EwfFormatError, match="no VHD footer"):
        ewfprobe.open_ewf(path)


def test_a_511_byte_footer_is_read(tmp_path):
    # Images older than Virtual PC 2004 end in a 511-byte footer (the VHD specification).
    case = BY_NAME["windows-fixed"]
    path = _unpack(case, str(tmp_path))
    data = open(path, "rb").read()
    assert data[-1] == 0                          # the last reserved byte
    open(path, "wb").write(data[:-1])
    with ewfprobe.open_ewf(path) as img:
        assert "511-byte" in img.vhd["footer"]
        assert _digest(img) == case["sha256"]


@pytest.mark.parametrize("what,change,error", [
    ("version", lambda f: struct.pack_into(">I", f, 12, 0x00020000), "version 2.0"),
    ("type", lambda f: struct.pack_into(">I", f, 60, 5), "disk type 5"),
    ("size", lambda f: struct.pack_into(">Q", f, 48, 16 * 1048576 + 5), "whole number"),
])
def test_a_vhd_footer_outside_what_is_read_is_refused(tmp_path, what, change, error):
    path = _unpack(BY_NAME["qemu-vhd-fixed"], str(tmp_path))
    data = bytearray(open(path, "rb").read())
    footer = data[-512:]
    change(footer)
    data[-512:] = _fix_footer(footer)
    open(path, "wb").write(data)
    with pytest.raises(ewfprobe.EwfFormatError, match=error):
        ewfprobe.open_ewf(path)


def test_a_vhd_dynamic_header_that_fails_its_checksum_is_refused(tmp_path):
    path = _unpack(BY_NAME["windows-dynamic"], str(tmp_path))
    data = bytearray(open(path, "rb").read())
    header_at = struct.unpack_from(">Q", data, len(data) - 512 + 16)[0]
    data[header_at + 1000] ^= 0xFF              # a reserved byte, so only the sum breaks
    open(path, "wb").write(data)
    with pytest.raises(ewfprobe.EwfFormatError, match="does not match its checksum"):
        ewfprobe.open_ewf(path)


def test_a_vhd_cut_short_is_refused(tmp_path):
    for name in ("qemu-vhd-fixed", "qemu-vhd-dynamic"):
        where = tmp_path / name
        where.mkdir()
        path = _unpack(BY_NAME[name], str(where))
        data = open(path, "rb").read()
        # keep the footer, lose data before it
        open(path, "wb").write(data[:len(data) // 2] + data[-512:])
        with pytest.raises(ewfprobe.EwfIncompleteSetError, match="cut short"):
            ewfprobe.open_ewf(path)


def test_a_differencing_vhd_needs_its_parent_and_the_right_one(tmp_path):
    case = BY_NAME["windows-diff"]
    path = _unpack(case, str(tmp_path))
    parent = tmp_path / "dynamic.vhd"
    moved = tmp_path / "elsewhere.vhd"
    os.rename(parent, moved)
    with pytest.raises(ewfprobe.EwfIncompleteSetError, match="not beside it"):
        ewfprobe.open_ewf(path)
    # a VHD of the parent's name that is another disk
    shutil.copy(_unpack(BY_NAME["windows-fixed"], str(tmp_path)), parent)
    with pytest.raises(ewfprobe.EwfFormatError, match="is disk"):
        ewfprobe.open_ewf(path)


# -- VHDX --------------------------------------------------------------------------

def _vhdx_fix(data, at, size):
    struct.pack_into("<I", data, at + 4, 0)
    struct.pack_into("<I", data, at + 4, _crc32c(bytes(data[at:at + size])))


def test_the_vhdx_header_with_the_greater_sequence_number_is_used(tmp_path):
    case = BY_NAME["windows-dynamicx"]
    path = _unpack(case, str(tmp_path))
    data = bytearray(open(path, "rb").read())
    seqs = [(struct.unpack_from("<Q", data, at + 8)[0], at) for at in (65536, 131072)]
    _seq, newer = max(seqs)
    data[newer + 100] ^= 0xFF                     # the newer one fails its CRC
    open(path, "wb").write(data)
    with ewfprobe.open_ewf(path) as img:
        assert img.vhdx["header_sequence"] == min(seqs)[0]
        assert _digest(img) == case["sha256"]
    data[min(seqs)[1] + 100] ^= 0xFF
    open(path, "wb").write(data)
    with pytest.raises(ewfprobe.EwfFormatError, match="no VHDX header"):
        ewfprobe.open_ewf(path)


def test_a_vhdx_region_or_item_it_must_understand_is_refused(tmp_path):
    case = BY_NAME["windows-dynamicx"]
    path = _unpack(case, str(tmp_path))
    base = bytearray(open(path, "rb").read())
    # a third region, marked required, in both copies of the region table
    data = bytearray(base)
    for at in (196608, 262144):
        count = struct.unpack_from("<I", data, at + 8)[0]
        struct.pack_into("<16sQII", data, at + 16 + 32 * count, uuid.uuid4().bytes_le,
                         64 << 20, 1 << 20, 1)
        struct.pack_into("<I", data, at + 8, count + 1)
        _vhdx_fix(data, at, 65536)
    open(path, "wb").write(data)
    with pytest.raises(ewfprobe.EwfFormatError, match="region marked required"):
        ewfprobe.open_ewf(path)
    # both copies of the region table broken
    data = bytearray(base)
    for at in (196608, 262144):
        data[at + 100] ^= 0xFF
    open(path, "wb").write(data)
    with pytest.raises(ewfprobe.EwfFormatError, match="no region table"):
        ewfprobe.open_ewf(path)


def test_a_vhdx_log_that_holds_nothing_valid_is_refused(tmp_path):
    case = BY_NAME["windows-dynamicx"]
    path = _unpack(case, str(tmp_path))
    data = bytearray(open(path, "rb").read())
    for at in (65536, 131072):                    # both headers name a log that is empty
        data[at + 48:at + 64] = uuid.uuid4().bytes_le
        _vhdx_fix(data, at, 4096)
    open(path, "wb").write(data)
    with pytest.raises(ewfprobe.EwfFormatError, match="no complete, valid"):
        ewfprobe.open_ewf(path)


def test_the_replayed_vhdx_log_is_what_makes_the_disk(tmp_path):
    case = BY_NAME["constructed-dirty-log"]
    path = _unpack(case, str(tmp_path))
    with ewfprobe.open_ewf(path) as img:
        assert img.vhdx["log_entries_replayed"] == 1
        assert _digest(img) == case["sha256"]
    # the file's own BAT, without the log, reads the updated block as zeros
    data = bytearray(open(path, "rb").read())
    for at in (65536, 131072):
        data[at + 48:at + 64] = bytes(16)
        _vhdx_fix(data, at, 4096)
    open(path, "wb").write(data)
    with ewfprobe.open_ewf(path) as img:
        assert img.vhdx["log_entries_replayed"] == 0
        assert _digest(img) != case["sha256"]


def test_a_vhdx_log_entry_that_fails_its_crc_is_not_replayed(tmp_path):
    path = _unpack(BY_NAME["constructed-dirty-log"], str(tmp_path))
    data = bytearray(open(path, "rb").read())
    log_at = struct.unpack_from("<Q", data, 65536 + 72)[0]
    assert data[log_at:log_at + 4] == b"loge"
    data[log_at + 4096 + 100] ^= 0xFF            # a byte of the update the entry carries
    open(path, "wb").write(data)
    with pytest.raises(ewfprobe.EwfFormatError, match="no complete, valid"):
        ewfprobe.open_ewf(path)


def test_a_vhdx_log_that_says_the_file_was_longer_is_refused(tmp_path):
    case = BY_NAME["constructed-dirty-log"]
    path = _unpack(case, str(tmp_path))
    data = open(path, "rb").read()
    open(path, "wb").write(data[:len(data) - (1 << 20)])
    with pytest.raises(ewfprobe.EwfIncompleteSetError, match="cut short"):
        ewfprobe.open_ewf(path)


def test_a_differencing_vhdx_needs_its_parent_and_the_right_one(tmp_path):
    case = BY_NAME["windows-diffx"]
    path = _unpack(case, str(tmp_path))
    os.rename(tmp_path / "dynamicx.vhdx", tmp_path / "moved.vhdx")
    with pytest.raises(ewfprobe.EwfIncompleteSetError, match="not beside it"):
        ewfprobe.open_ewf(path)
    shutil.copy(_unpack(BY_NAME["windows-fixedx"], str(tmp_path)),
                tmp_path / "dynamicx.vhdx")
    with pytest.raises(ewfprobe.EwfFormatError, match="DataWriteGuid"):
        ewfprobe.open_ewf(path)


# -- VMDK --------------------------------------------------------------------------

def test_a_vmdk_extent_opened_on_its_own_finds_its_descriptor(tmp_path):
    for name, extent in (("qemu-vmdk-twoGbMaxExtentSparse",
                          "vmdk-twoGbMaxExtentSparse-s001.vmdk"),
                         ("constructed-cowd", "cowd-delta.vmdk")):
        where = tmp_path / name
        where.mkdir()
        case = BY_NAME[name]
        _unpack(case, str(where))
        with ewfprobe.open_ewf(str(where / extent)) as img:
            assert _digest(img) == case["sha256"]
        shutil.copy(where / case["open"], where / "second.vmdk")
        with pytest.raises(ewfprobe.EwfIncompleteSetError, match="several descriptor"):
            ewfprobe.open_ewf(str(where / extent))


def _descriptor(path, change):
    text = open(path, "rb").read().split(b"\0")[0].decode()
    open(path, "w").write(change(text))


def test_a_vmdk_whose_extents_cannot_be_read_is_refused(tmp_path):
    case = BY_NAME["qemu-vmdk-monolithicFlat"]
    path = _unpack(case, str(tmp_path))
    text = open(path, "rb").read().split(b"\0")[0].decode()
    for changed, error in ((text.replace("RW ", "NOACCESS "), "NOACCESS"),
                           (text.replace('"monolithicFlat"', '"fullDevice"'), "physical"),
                           (text.replace(" FLAT ", " SESPARSE "), "SESPARSE")):
        open(path, "w").write(changed)
        with pytest.raises(ewfprobe.EwfFormatError, match=error):
            ewfprobe.open_ewf(path)
    open(path, "w").write(text)
    os.remove(tmp_path / "vmdk-monolithicFlat-flat.vmdk")
    with pytest.raises(ewfprobe.EwfIncompleteSetError, match="not beside"):
        ewfprobe.open_ewf(path)


def test_a_vmdk_delta_whose_parent_changed_is_refused(tmp_path):
    case = BY_NAME["qemu-vmdk-delta"]
    path = _unpack(case, str(tmp_path))
    base = tmp_path / "vmdk-base.vmdk"
    data = bytearray(open(base, "rb").read())
    at = data.index(b"CID=") + 4
    data[at:at + 8] = b"deadbeef"
    open(base, "wb").write(data)
    with pytest.raises(ewfprobe.EwfFormatError, match="content id"):
        ewfprobe.open_ewf(path)


def _vmware_stream(path):
    """qemu-img's stream-optimized VMDK rewritten the way VMware's tools lay it out:
    GD_AT_END in the header, and a footer marker, a footer holding the grain
    directory's offset, and an end-of-stream marker as the file's last three
    sectors."""
    data = bytearray(open(path, "rb").read())
    header = bytes(data[:512])
    struct.pack_into("<Q", data, 56, 0xFFFFFFFFFFFFFFFF)
    data.extend(bytes(-len(data) % 512))
    data += struct.pack("<QII", 1, 0, 3) + bytes(496)
    data += header
    data += bytes(512)
    open(path, "wb").write(data)


def test_a_stream_optimized_vmdk_with_its_directory_in_a_footer_is_read(tmp_path):
    case = BY_NAME["qemu-vmdk-streamOptimized"]
    path = _unpack(case, str(tmp_path))
    _vmware_stream(path)
    with ewfprobe.open_ewf(path) as img:
        assert _digest(img) == case["sha256"]
    data = bytearray(open(path, "rb").read())
    data[-1024:-1020] = b"XXXX"
    open(path, "wb").write(data)
    with pytest.raises(ewfprobe.EwfFormatError, match="no footer"):
        ewfprobe.open_ewf(path)


def test_a_compressed_grain_marked_for_another_place_is_refused(tmp_path):
    case = BY_NAME["qemu-vmdk-streamOptimized"]
    path = _unpack(case, str(tmp_path))
    data = bytearray(open(path, "rb").read())
    at = 128 * 512                                # qemu-img's first grain marker
    lba, size = struct.unpack_from("<QI", data, at)
    assert size and lba == 0
    struct.pack_into("<Q", data, at, 128)
    open(path, "wb").write(data)
    with ewfprobe.open_ewf(path) as img:
        with pytest.raises(ewfprobe.EwfFormatError, match="records sector 128"):
            img.read(512)


@pytest.mark.skipif(not os.environ.get("EWFPROBE_VMDK_REFERENCE")
                    and not os.environ.get("EWFPROBE_REQUIRE_VMDK_REFERENCE"),
                    reason="set EWFPROBE_VMDK_REFERENCE to the Photon OS 2.0 OVA")
def test_vmwares_own_stream_optimized_vmdk_reads_as_qemu_reads_it(tmp_path):
    ova = os.environ.get("EWFPROBE_VMDK_REFERENCE", "")
    assert os.path.isfile(ova), "EWFPROBE_VMDK_REFERENCE names no file"
    sha1 = hashlib.sha1()
    with open(ova, "rb") as fh:
        for piece in iter(lambda: fh.read(1 << 20), b""):
            sha1.update(piece)
    assert sha1.hexdigest() == PHOTON_SHA1
    with tarfile.open(ova) as tf:
        member = next(m for m in tf.getmembers() if m.name.endswith(".vmdk"))
        with tf.extractfile(member) as src, open(tmp_path / "disk.vmdk", "wb") as dst:
            shutil.copyfileobj(src, dst)
    with ewfprobe.open_ewf(str(tmp_path / "disk.vmdk")) as img:
        assert img.vmdk["create_type"] == "streamOptimized"
        assert img.vmdk["extents"][0]["this_file"]
        assert _digest(img) == PHOTON_DISK_SHA256


# -- QCOW --------------------------------------------------------------------------

def test_a_qcow_with_an_incompatible_feature_it_does_not_know_is_refused(tmp_path):
    path = _unpack(BY_NAME["qemu-qcow2-v3"], str(tmp_path))
    data = bytearray(open(path, "rb").read())
    struct.pack_into(">Q", data, 72, struct.unpack_from(">Q", data, 72)[0] | 1 << 40)
    open(path, "wb").write(data)
    with pytest.raises(ewfprobe.EwfFormatError, match="incompatible feature"):
        ewfprobe.open_ewf(path)


def test_zstd_clusters_without_a_decompressor_are_refused(tmp_path, monkeypatch):
    path = _unpack(BY_NAME["qemu-qcow2-zstd"], str(tmp_path))
    monkeypatch.setattr(ewfprobe, "_zstd_decompressor", lambda: None)
    with pytest.raises(ewfprobe.EwfFormatError, match="backports.zstd"):
        ewfprobe.open_ewf(path)


def test_a_qcow_needs_its_backing_file_and_its_data_file(tmp_path):
    for name, gone in (("qemu-qcow2-overlay", "qcow2-base.qcow2"),
                       ("qemu-qcow2-extdata", "qcow2-extdata.data")):
        where = tmp_path / name
        where.mkdir()
        path = _unpack(BY_NAME[name], str(where))
        os.remove(where / gone)
        with pytest.raises(ewfprobe.EwfIncompleteSetError, match="not beside"):
            ewfprobe.open_ewf(path)


def test_a_chain_of_backing_files_that_loops_is_refused(tmp_path):
    path = _unpack(BY_NAME["qemu-qcow2-overlay"], str(tmp_path))
    data = bytearray(open(path, "rb").read())
    at = struct.unpack_from(">Q", data, 8)[0]
    name = b"qcow2-overlay.qcow2"
    data[at:at + len(name)] = name
    struct.pack_into(">I", data, 16, len(name))
    # the backing format extension names qcow2, which is right for itself
    open(path, "wb").write(data)
    with pytest.raises(ewfprobe.EwfFormatError, match="loops"):
        ewfprobe.open_ewf(path)


def test_a_split_vhd_is_refused(tmp_path):
    for name in ("disk.vhd", "disk.v01"):
        (tmp_path / name).write_bytes(bytes(4096))
    for name in ("disk.vhd", "disk.v01"):
        with pytest.raises(ewfprobe.EwfFormatError, match="split into files"):
            ewfprobe.open_ewf(str(tmp_path / name))


def test_every_virtual_disk_counts_as_an_image(tmp_path):
    for name in ("windows-fixed", "windows-diffx", "qemu-vmdk-monolithicSparse",
                 "qemu-qcow1", "constructed-cowd"):
        where = tmp_path / name
        where.mkdir()
        assert ewfprobe.is_image(_unpack(BY_NAME[name], str(where))), name

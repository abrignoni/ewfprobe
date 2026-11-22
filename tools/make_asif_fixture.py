#!/usr/bin/env python3
"""Write the ASIF fixtures with macOS's own disk image stack (macOS 26 or later).

    python tools/make_asif_fixture.py tests/fixtures

Each image gets whole chunks, an unmapped chunk, a partly unmapped chunk, a few
written sectors and a write at the very end of a disk that stops inside a chunk. The
data is generated. macOS then reads the disk back, and that read must equal the model
of what was written before its hash goes into asif-manifest.json. The encrypted
fixture keeps only the start of the file, so it proves the image opens at its size.
"""

import ctypes
import fcntl
import gzip
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from collections import Counter

SIZE = 8_000_000
SECTOR = 512
CHUNK = 1 << 20
PASSWORD = "asif-fixture-test"      # protects generated data only
DKIOCUNMAP = 0x8010641F
# Every block of an encrypted image is incompressible, so only its start is kept:
# the encryption header and both directories, enough to open it.
ENCRYPTED_HEAD = 0x90000


class Extent(ctypes.Structure):
    _fields_ = [("offset", ctypes.c_uint64), ("length", ctypes.c_uint64)]


class Unmap(ctypes.Structure):
    _fields_ = [("extents", ctypes.POINTER(Extent)), ("count", ctypes.c_uint32),
                ("options", ctypes.c_uint32)]


def pattern(offset, length):
    """Sector-numbered bytes: every sector differs, and the data still compresses."""
    out = bytearray()
    for sector in range(offset // SECTOR, (offset + length) // SECTOR):
        out += struct.pack(">QQ", sector, sector ^ 0x4153494600000000) * (SECTOR // 16)
    return bytes(out)


def run(command, password=None):
    done = subprocess.run(command, input=None if password is None else password.encode(),
                          stdin=None if password is not None else subprocess.DEVNULL,
                          capture_output=True, check=False)
    if done.returncode:
        raise SystemExit(f"{command[:3]} failed: {done.stderr.decode(errors='replace')[:300]}")
    return done.stdout.decode(errors="replace") + done.stderr.decode(errors="replace")


def attach(image, password, *flags):
    command = ["diskutil", "image", "attach", *flags, "--noMount"]
    if password:
        command.append("--stdinpassphrase")
    found = re.search(r"/dev/disk\d+", run([*command, image], password))
    if not found:
        raise SystemExit("attach named no disk")
    return found.group(0)


def detach(disk):
    run(["hdiutil", "detach", disk])


def write_states(raw):
    """Write the layout, returning the bytes the disk should then read as."""
    model = bytearray(SIZE)
    fd = os.open(raw, os.O_RDWR)
    try:
        def write(offset, length):
            data = pattern(offset, length)
            if os.pwrite(fd, data, offset) != length:
                raise SystemExit("short write")
            model[offset:offset + length] = data

        def unmap(offset, length):
            extent = Extent(offset, length)
            fcntl.ioctl(fd, DKIOCUNMAP, Unmap(ctypes.pointer(extent), 1, 0))
            model[offset:offset + length] = bytes(length)

        write(1 * CHUNK, CHUNK)                       # whole chunk
        write(2 * CHUNK, CHUNK)
        unmap(2 * CHUNK, CHUNK)                       # whole chunk unmapped
        write(3 * CHUNK, CHUNK)
        unmap(3 * CHUNK + 256 * 1024, 256 * 1024)     # part of a chunk unmapped
        write(5 * CHUNK + 3 * SECTOR, 7 * SECTOR)     # a few sectors
        write(SIZE - 8 * SECTOR, 8 * SECTOR)          # the end, inside a chunk
        os.fsync(fd)
    finally:
        os.close(fd)
    return bytes(model)


def data_states(path):
    """How many of the first group's data entries are in each state."""
    with open(path, "rb") as fh:
        head = fh.read(80)
        first, second = struct.unpack_from(">QQ", head, 16)
        chunk = struct.unpack_from(">I", head, 64)[0]
        versions = []
        for offset in (first, second):
            fh.seek(offset)
            versions.append((struct.unpack(">Q", fh.read(8))[0], offset))
        fh.seek(max(versions)[1] + 8)
        table = struct.unpack(">Q", fh.read(8))[0]
        fh.seek(table * chunk)
        entries = struct.unpack(">2048Q", fh.read(2048 * 8))
    return {str(state): count for state, count in
            sorted(Counter(entry >> 62 for entry in entries).items())}


def build(folder, name, password):
    work = os.path.join(folder, name)
    command = ["diskutil", "image", "create", "blank", "--format", "ASIF", "--size", str(SIZE),
               "--fs", "None"]
    if password:
        command += ["--encrypt", "--stdinpassphrase"]
    run([*command, work], password)
    disk = attach(work, password)
    try:
        model = write_states("/dev/r" + disk[len("/dev/"):])
    finally:
        detach(disk)
    disk = attach(work, password, "--readOnly")
    try:
        with open("/dev/r" + disk[len("/dev/"):], "rb") as fh:
            seen = fh.read(SIZE + CHUNK)
    finally:
        detach(disk)
    if seen != model:
        raise SystemExit(f"{name}: macOS did not read back what was written")
    return work, model


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    out = os.path.abspath(sys.argv[1])
    manifest = {"note": "written and read back by macOS; the data is generated", "images": {}}
    with tempfile.TemporaryDirectory() as folder:
        for name, password in (("asif-states.asif", None),
                               ("asif-encrypted.asif", PASSWORD)):
            work, model = build(folder, name, password)
            target = os.path.join(out, name + ".gz")
            with open(work, "rb") as src, open(target, "wb") as raw:
                with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
                    gz.write(src.read(ENCRYPTED_HEAD) if password else src.read())
            entry = {"file": name + ".gz", "logical_size": len(model),
                     "logical_sha256": hashlib.sha256(model).hexdigest()}
            if password:
                entry["password"] = password
                entry["stored_head_bytes"] = ENCRYPTED_HEAD
            else:
                entry["data_entry_states"] = data_states(work)
            manifest["images"][name] = entry
            print(name, os.path.getsize(work), "bytes,", os.path.getsize(target), "gzipped")
    with open(os.path.join(out, "asif-manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")


if __name__ == "__main__":
    main()

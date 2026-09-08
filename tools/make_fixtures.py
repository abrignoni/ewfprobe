"""Build the EWF fixtures the tests read, and a manifest of known answers.

This is a development tool, not part of ewfprobe. It shells out to ewfacquire
from libewf to write real EWF files, because a fixture written by the reference
implementation is evidence about the format in a way that one written by our own
test writer is not. libewf is LGPL and is used here only to produce test data:
nothing from it ships, and ewfprobe imports nothing.

    python tools/make_fixtures.py <output folder> [--small]

``--small`` writes the compact set that is committed under tests/fixtures: a
1 MiB source in three variants, enough to cover the current and older table
layouts and a multi-segment set without putting megabytes into the repository.

It writes a raw source image with synthetic media at known offsets, acquires it
in several EWF format variants, and records a manifest giving each variant's
files and each embedded file's offset, length and SHA-256. The media is
generated here, so no evidence content is involved.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import random
import shutil
import struct
import subprocess
import sys

# Acquisition variants. Between them these cover the older table layout with no
# base offset, the current one, several compression settings including none at
# all, two chunk geometries, and a multi-segment set.
VARIANTS = [
    # name,           format,     compression,   sectors/chunk, segment size
    ("encase6-fast",  "encase6",  "fast",        64,            None),
    ("encase6-none",  "encase6",  "none",        64,            None),
    ("encase6-best",  "encase6",  "best",        64,            None),
    ("encase5-fast",  "encase5",  "fast",        64,            None),
    ("encase7-fast",  "encase7",  "fast",        64,            None),
    ("ftk-fast",      "ftk",      "fast",        64,            None),
    ("encase6-chunk16", "encase6", "fast",       16,            None),
    ("encase6-chunk256", "encase6", "fast",      256,           None),
    # uncompressed so the source is big enough for -S to actually split it
    ("encase6-split", "encase6",  "none",        64,            "1M"),
]


def _jpeg(w, h, colour, seed):
    from PIL import Image
    rnd = random.Random(seed)
    im = Image.new("RGB", (w, h), colour)
    px = im.load()
    for _ in range((w * h) // 8):
        px[rnd.randrange(w), rnd.randrange(h)] = (
            rnd.randrange(256), rnd.randrange(256), rnd.randrange(256))
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=85)
    return buf.getvalue()


def _png(w, h, colour, seed):
    from PIL import Image
    rnd = random.Random(seed)
    im = Image.new("RGB", (w, h), colour)
    px = im.load()
    for _ in range((w * h) // 16):
        px[rnd.randrange(w), rnd.randrange(h)] = (
            rnd.randrange(256), rnd.randrange(256), rnd.randrange(256))
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()


def _gif(w, h, seed):
    from PIL import Image
    rnd = random.Random(seed)
    im = Image.new("P", (w, h))
    im.putpalette([rnd.randrange(256) for _ in range(768)])
    buf = io.BytesIO()
    im.save(buf, "GIF")
    return buf.getvalue()


def build_raw(path, *, sector_size=512, size=8 << 20, seed=4):
    """A raw image holding synthetic media at known offsets.

    Media is placed on sector boundaries with unrelated filler between, which is
    what a carver has to cope with. The returned manifest is the known answer.
    """
    rnd = random.Random(seed)
    blob = bytearray(size)

    # filler: mostly zeros with a few noisy regions, so the image compresses
    # unevenly and both stored and compressed chunks occur.
    for start in range(0, size, 1 << 20):
        if (start // (1 << 20)) % 3 == 1:
            noise = bytes(rnd.randrange(256) for _ in range(1 << 16))
            blob[start:start + len(noise)] = noise

    items = []
    offset = 4096
    payloads = [
        ("jpeg", _jpeg(160, 120, (200, 40, 40), 1)),
        ("png", _png(120, 90, (40, 160, 60), 2)),
        ("jpeg", _jpeg(200, 150, (30, 60, 200), 3)),
        ("gif", _gif(64, 64, 4)),
        ("jpeg", _jpeg(96, 96, (240, 200, 20), 5)),
        ("png", _png(80, 60, (10, 10, 10), 6)),
    ]
    for kind, data in payloads:
        offset = (offset + sector_size - 1) // sector_size * sector_size
        blob[offset:offset + len(data)] = data
        items.append({
            "kind": kind,
            "offset": offset,
            "length": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
        offset += len(data) + rnd.randrange(3000, 40000)

    with open(path, "wb") as fh:
        fh.write(bytes(blob))
    return {
        "raw": os.path.basename(path),
        "size": size,
        "sector_size": sector_size,
        "sha256": hashlib.sha256(bytes(blob)).hexdigest(),
        "media": items,
    }


def acquire(raw_path, out_dir, name, fmt, compression, sectors_per_chunk, segment_size):
    target = os.path.join(out_dir, name)
    os.makedirs(out_dir, exist_ok=True)
    for stale in os.listdir(out_dir):
        if stale.startswith(name + "."):
            os.remove(os.path.join(out_dir, stale))
    cmd = [
        "ewfacquire", "-u", "-t", target, "-f", fmt, "-c", compression,
        "-b", str(sectors_per_chunk), "-d", "sha1",
        "-C", "FIXTURE", "-D", f"ewfprobe fixture {name}", "-E", "1",
        "-e", "ewfprobe", "-N", "synthetic test data, no evidence content",
        "-m", "fixed", "-M", "logical",
    ]
    if segment_size:
        cmd += ["-S", segment_size]
    cmd.append(raw_path)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"ewfacquire failed for {name}:\n{result.stdout}\n{result.stderr}")
    made = sorted(f for f in os.listdir(out_dir) if f.startswith(name + ".E"))
    return made


SMALL_VARIANTS = [
    ("encase6-fast",  "encase6",  "fast",        64,            None),
    ("encase5-fast",  "encase5",  "fast",        64,            None),
    # 1 MiB is libewf's minimum segment size, so the source must exceed it
    ("encase6-split", "encase6",  "none",        64,            "1M"),
]


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    small = "--small" in argv
    if len(args) != 1:
        print(__doc__)
        return 2
    out = os.path.abspath(args[0])
    os.makedirs(out, exist_ok=True)
    if not shutil.which("ewfacquire"):
        raise SystemExit("ewfacquire not found; install libewf (test tool only)")

    raw_path = os.path.join(out, "source.raw")
    manifest = build_raw(raw_path, size=(3 << 20) if small else (8 << 20))
    print(f"raw source: {manifest['size']:,} bytes, {len(manifest['media'])} media items")

    manifest["variants"] = {}
    for name, fmt, comp, spc, seg in (SMALL_VARIANTS if small else VARIANTS):
        made = acquire(raw_path, out, name, fmt, comp, spc, seg)
        manifest["variants"][name] = {
            "format": fmt, "compression": comp, "sectors_per_chunk": spc,
            "segment_size": seg, "files": made,
        }
        total = sum(os.path.getsize(os.path.join(out, f)) for f in made)
        print(f"  {name:<20} {fmt:<9} {comp:<5} b={spc:<4} "
              f"{len(made)} file(s) {total:>10,} bytes")

    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    print(f"\nmanifest written to {os.path.join(out, 'manifest.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

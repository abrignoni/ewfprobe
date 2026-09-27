"""Build the EWF fixtures the tests read, and a manifest of known answers.

This is a development tool, not part of ewfprobe. It shells out to ewfacquire
from libewf to write real EWF files, because a fixture written by the reference
implementation is evidence about the format in a way that one written by our own
test writer is not. libewf is LGPL and is used here only to produce test data:
nothing from it ships, and ewfprobe imports nothing.

    python tools/make_fixtures.py <output folder> [--small]
    python tools/make_fixtures.py <output folder> --add <variant> [<variant> ...]

``--small`` writes the compact set that is committed under tests/fixtures: a
3 MiB source in a few variants, enough to cover the current and older table
layouts, SMART, and multi-segment sets without putting megabytes into the
repository.

``--add`` writes only the named variants into a folder that already holds a
manifest, leaving the existing fixtures alone. The source image is not
committed, so it is rebuilt by reading an existing fixture back, and it must
hash to the manifest's recorded SHA-256 before anything is written. Rebuilding
it from the generator instead would depend on the imaging library encoding the
same JPEG bytes years later.

Variants whose ``writer`` in the manifest is not ewfacquire were written by
hand in another tool (FTK Imager, from the same source image) and copied in.
``--add`` leaves them alone; ``--small`` rebuilds the manifest from scratch and
would drop them, so re-add them afterwards from the tool that wrote them.

``EWFACQUIRE`` selects the ewfacquire binary (default: the one on PATH). Each
variant records the version that wrote it, because libewf releases differ in
what they can write: 20140817 writes Ex01 as an ordinary E01, 20260924 does not.

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

EWFACQUIRE = os.environ.get("EWFACQUIRE", "ewfacquire")
AFFCONVERT = os.environ.get("AFFCONVERT", "affconvert")

# AFF variants, written by affconvert from AFFLIB. A 64 KiB page (the default is
# 16 MiB) gives the 3 MiB source 48 pages, so zero pages, deflated pages, LZMA
# pages and stored pages all occur.
AFF_VARIANTS = [
    # name,        affconvert options
    ("aff-zlib",   ["-s64k"]),
    ("aff-lzma",   ["-L", "-s64k"]),
    ("aff-none",   ["-x", "-s64k"]),
]

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
    ("smart-fast",    "smart",    "fast",        64,            None),
    # SMART compresses every chunk; "none" stores them at zlib level 0, so the
    # source stays large enough to split
    ("smart-split",   "smart",    "none",        64,            "1M"),
    # Ex01 needs libewf 20260924 or later; 20140817 writes an E01 when asked for it
    ("ex01-fast",     "encase7-v2", "fast",      64,            None),
    # Ex01 stores runs of one byte value as pattern-fill chunks, so this source
    # cannot be made to split: a multi-segment Ex01 set is written by the test
    # suite's own writer instead.
    ("ex01-none",     "encase7-v2", "none",      64,            None),
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
        EWFACQUIRE, "-u", "-t", target, "-f", fmt, "-c", compression,
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
    made = sorted(f for f in os.listdir(out_dir)
                  if f.startswith(name + ".") and f[len(name) + 1:][:1] in "Es")
    return made


def acquire_aff(raw_path, out_dir, name, options):
    """One AFF variant. affconvert records its command line in the image, so it runs
    in the output folder with relative names, keeping local paths out of the fixture."""
    target = name + ".aff"
    stale = os.path.join(out_dir, target)
    if os.path.exists(stale):
        os.remove(stale)
    result = subprocess.run(
        [AFFCONVERT, "-q", *options, "-o", target, os.path.basename(raw_path)],
        cwd=out_dir, capture_output=True, text=True, check=False)
    if result.returncode != 0 or not os.path.exists(stale):
        raise SystemExit(f"affconvert failed for {name}:\n{result.stdout}\n{result.stderr}")
    return [target]


def writer_version(tool=None):
    out = subprocess.run([tool or EWFACQUIRE, "-V"], capture_output=True, text=True,
                         check=False).stdout
    return out.strip().splitlines()[0] if out.strip() else "unknown"


def rebuild_source(out, manifest):
    """The raw source, read back from a fixture and checked against the manifest."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import ewfprobe
    first = next(os.path.join(out, v["files"][0]) for v in manifest["variants"].values())
    raw_path = os.path.join(out, manifest["raw"])
    digest = hashlib.sha256()
    with ewfprobe.open_ewf(first) as img, open(raw_path, "wb") as fh:
        while True:
            block = img.read(1 << 20)
            if not block:
                break
            digest.update(block)
            fh.write(block)
    if digest.hexdigest() != manifest["sha256"]:
        os.remove(raw_path)
        raise SystemExit(f"the source read back from {os.path.basename(first)} does not "
                         f"match the manifest's sha256; nothing written")
    return raw_path


SMALL_VARIANTS = [
    ("encase6-fast",  "encase6",  "fast",        64,            None),
    ("encase5-fast",  "encase5",  "fast",        64,            None),
    # 1 MiB is libewf's minimum segment size, so the source must exceed it
    ("encase6-split", "encase6",  "none",        64,            "1M"),
    ("smart-fast",    "smart",    "fast",        64,            None),
    ("smart-split",   "smart",    "none",        64,            "1M"),
    ("ex01-fast",     "encase7-v2", "fast",      64,            None),
    ("ex01-none",     "encase7-v2", "none",      64,            None),
]


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    small = "--small" in argv
    add = "--add" in argv
    if not args or (len(args) != 1 and not add) or (add and len(args) < 2):
        print(__doc__)
        return 2
    out = os.path.abspath(args[0])
    os.makedirs(out, exist_ok=True)
    aff_known = dict(AFF_VARIANTS)
    ewf_wanted = not add or any(a not in aff_known for a in args[1:])
    aff_wanted = not add or any(a in aff_known for a in args[1:])
    if ewf_wanted and not shutil.which(EWFACQUIRE):
        raise SystemExit(f"{EWFACQUIRE} not found; install libewf (test tool only)")
    if aff_wanted and not shutil.which(AFFCONVERT):
        raise SystemExit(f"{AFFCONVERT} not found; install AFFLIB (test tool only)")
    writer = writer_version() if ewf_wanted else None

    if add:
        with open(os.path.join(out, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        known = {v[0]: v for v in VARIANTS + SMALL_VARIANTS}
        unknown = [a for a in args[1:] if a not in known and a not in aff_known]
        if unknown:
            raise SystemExit(f"unknown variant(s): {', '.join(unknown)}")
        chosen = [known[a] for a in args[1:] if a in known]
        chosen_aff = [(a, aff_known[a]) for a in args[1:] if a in aff_known]
        raw_path = rebuild_source(out, manifest)
        print(f"raw source rebuilt and matches the manifest: {manifest['sha256'][:16]}")
    else:
        raw_path = os.path.join(out, "source.raw")
        manifest = build_raw(raw_path, size=(3 << 20) if small else (8 << 20))
        print(f"raw source: {manifest['size']:,} bytes, "
              f"{len(manifest['media'])} media items")
        manifest["variants"] = {}
        chosen = SMALL_VARIANTS if small else VARIANTS
        chosen_aff = list(AFF_VARIANTS)

    for name, fmt, comp, spc, seg in chosen:
        made = acquire(raw_path, out, name, fmt, comp, spc, seg)
        manifest["variants"][name] = {
            "format": fmt, "compression": comp, "sectors_per_chunk": spc,
            "segment_size": seg, "files": made, "writer": writer,
        }
        total = sum(os.path.getsize(os.path.join(out, f)) for f in made)
        print(f"  {name:<20} {fmt:<9} {comp:<5} b={spc:<4} "
              f"{len(made)} file(s) {total:>10,} bytes")

    aff_writer = ("affconvert " + writer_version(AFFCONVERT).split()[-1]
                  if chosen_aff else None)
    for name, options in chosen_aff:
        made = acquire_aff(raw_path, out, name, options)
        manifest["variants"][name] = {
            "format": "aff", "options": options, "files": made, "writer": aff_writer,
        }
        size = os.path.getsize(os.path.join(out, made[0]))
        print(f"  {name:<20} aff       {' '.join(options):<14} {size:>10,} bytes")

    if add:
        os.remove(raw_path)
    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    print(f"\nmanifest written to {os.path.join(out, 'manifest.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

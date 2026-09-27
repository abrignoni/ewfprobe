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

The manifest's ``gpt_dmg`` section describes images hdiutil segment wrote from
a small GPT disk of their own (``--add dmg-gpt`` rebuilds them); its known answer
is that disk's SHA-256.

The manifest's ``encrypted_dmg`` section describes encrypted images hdiutil
wrote from a small disk of their own, with the test password it records (``--add
dmg-encrypted`` rebuilds them). Each one is attached by hdiutil with that password
and its /dev/rdisk read back before it is kept, so its known answer, the disk's
SHA-256, is macOS's own reading and not ewfprobe's.

The manifest's ``encrypted_aff`` section describes AFF images AFFLIB encrypted
from this tool's own source (``--add aff-encrypted`` rebuilds them): written
encrypted by affconvert with a passphrase set, sealed to a certificate as well by
affcrypto -A, and encrypted in place by affcrypto -e with a passphrase or a
certificate. The test key and certificate are generated once and kept beside the
fixtures. Each image AFFLIB can open is read back by affconvert -r with its
passphrase or key and must give the source; the ones encrypted in place are kept
because AFFLIB 3.7.22 cannot open them (affcrypto -e writes its first segment over
the file's header), and the manifest records that AFFLIB refused each.

The manifest's ``ad_encrypted`` section describes sets FTK Imager wrote with AD
encryption, from a small disk of their own that ``ad_source()`` regenerates
(``--ad-source <file>`` writes it for FTK Imager to image), with the test
password it records. FTK Imager cannot be driven from here, so the files are made
by hand and copied in; the known answer is that disk's hashes, which FTK Imager
also recorded. Both modes keep that section as it is.

The manifest's ``logical`` section describes an L01 EnCase wrote, copied from
Digital Corpora with known answers taken from libewf's ewfexport. It has its own
source rather than this tool's, so both modes keep that section as it is.

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
AFFCRYPTO = os.environ.get("AFFCRYPTO", "affcrypto")
HDIUTIL = os.environ.get("HDIUTIL", "hdiutil")

# Apple disk image variants, written by hdiutil (so macOS only) from the same
# source. Between them they cover every chunk codec a UDIF image can use, stored
# chunks with and without compression, a sparse image, a sparse bundle, and the
# UDZO image split by hdiutil segment into .dmgpart files. ULFO needs the optional
# pyliblzfse package to read, and the tests skip it where that is absent.
DMG_VARIANTS = [
    # name,              hdiutil format
    ("dmg-udzo",         "UDZO"),        # zlib
    ("dmg-udbz",         "UDBZ"),        # bzip2
    ("dmg-ulmo",         "ULMO"),        # LZMA
    ("dmg-ulfo",         "ULFO"),        # LZFSE
    ("dmg-udco",         "UDCO"),        # ADC
    ("dmg-udro",         "UDRO"),        # stored, with unstored runs left out
    ("dmg-ufbi",         "UFBI"),        # stored whole, MD5 checksums
    ("dmg-sparse",       "UDSP"),        # a .sparseimage
    ("dmg-sparsebundle", "UDSB"),        # a .sparsebundle of 1 MiB bands
    ("dmg-segmented",    "UDZO/40k"),    # hdiutil segment: three files
]

# The shared source has no partition map, so hdiutil gives each of those images
# one block table. hdiutil segment writes each table's own base as its data offset
# and entry offsets relative to it, which only shows with several tables, so these
# come from a small GPT disk of their own. Their known answer is that disk's
# SHA-256: a UDRW image is the disk's bytes with nothing added.
GPT_DMG_VARIANTS = [
    # name,                 segment size
    ("dmg-gpt-segmented",   "40k"),      # several .dmgpart files
    ("dmg-gpt-segment-one", "100m"),     # hdiutil segment, still one file
]
_DMG_SUFFIX = {"UDSP": ".sparseimage", "UDSB": ".sparsebundle"}

# Encrypted images (hdiutil -encryption). Most come from a 192 KiB disk: data, a
# stretch of zeros, then data. hdiutil takes no sparse bundle band under 1 MiB and
# writes every band in full, so the sparse bundle comes from a disk of three 1 MiB
# bands (zeros; data then zeros; a short last band of data), and after writing it
# its first band file, all zeros, is removed and its second cut after the data:
# hdiutil reads a band with no file, and a band file's missing end, as zeros, as it
# leaves unwritten bands of the images it creates. Every image is attached by
# hdiutil afterwards and must give back its disk. One image uses a password outside
# ASCII, which hdiutil uses as the UTF-8 bytes given, with no normalisation.
ENC_PASSWORD = "ewfprobe-test-password"
ENC_PASSWORD_NON_ASCII = "p\u00e4ssw\u00f6rd-\u00fc"   # NFC
ENC_DMG_VARIANTS = [
    # name,                         hdiutil format, encryption, password,  disk
    ("dmg-enc-udzo-aes128",         "UDZO",        "AES-128", ENC_PASSWORD, "small"),
    ("dmg-enc-udzo-aes256",         "UDZO",        "AES-256", ENC_PASSWORD, "small"),
    ("dmg-enc-udrw-aes256",         "UDRW",        "AES-256", ENC_PASSWORD, "small"),
    ("dmg-enc-sparse-aes128",       "UDSP",        "AES-128", ENC_PASSWORD, "small"),
    ("dmg-enc-segmented-aes128",    "UDZO/20k",    "AES-128", ENC_PASSWORD, "small"),
    ("dmg-enc-udzo-non-ascii",      "UDZO",        "AES-128", ENC_PASSWORD_NON_ASCII,
     "small"),
    ("dmg-enc-sparsebundle-aes256", "UDSB",        "AES-256", ENC_PASSWORD, "banded"),
]

# AFF variants, written by affconvert from AFFLIB. A 64 KiB page (the default is
# 16 MiB) gives the 3 MiB source 48 pages, so zero pages, deflated pages, LZMA
# pages and stored pages all occur.
AFF_VARIANTS = [
    # name,        affconvert options
    ("aff-zlib",   ["-s64k"]),
    ("aff-lzma",   ["-L", "-s64k"]),
    ("aff-none",   ["-x", "-s64k"]),
    # Written as an AFD (see acquire_aff): a directory of AFF files, with -M capping
    # each file, so the pages spread across them and the image size and hashes land
    # in the last one.
    ("aff-afd",    ["-s64k", "-M32k"]),
    # Written as an AFM (see acquire_aff): the metadata in an .afm beside the disk as
    # raw files, one file, or split at -M into .000, .001 and on.
    ("aff-afm",       ["--afm", "-s64k"]),
    ("aff-afm-split", ["--afm", "-s64k", "-M1m"]),
]

# Encrypted AFF variants, by AFFLIB, from the same source: (name, affconvert options,
# how it is encrypted). A variant ending -afd is written as an AFD, as above.
AFF_PASSWORD = "ewfprobe-aff-password"
AFF_TEST_KEY = "aff-enc-test-key.pem"
AFF_TEST_CERT = "aff-enc-test-cert.pem"
ENC_AFF_VARIANTS = [
    ("aff-enc-pass",          ["-s64k"],          "passphrase"),
    ("aff-enc-lzma",          ["-L", "-s64k"],    "passphrase"),
    ("aff-enc-afd",           ["-s64k", "-M32k"], "passphrase"),
    ("aff-enc-both",          ["-s64k"],          "passphrase and certificate"),
    ("aff-enc-inplace-pass",  ["-s64k"],          "passphrase, in place"),
    ("aff-enc-inplace-cert",  ["-s64k"],          "certificate, in place"),
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


def acquire_aff(raw_path, out_dir, name, options, env=None):
    """One AFF variant, as (the path to open, the files written). affconvert records
    its command line in the image, so it runs in the output folder with relative
    names, keeping local paths out of the fixture. A variant with a file size cap
    (-M) is written to a name ending .afd, which makes affconvert write an AFD
    directory, and its files are the .aff files inside it. An --afm variant is
    written to a name ending .afm, which makes affconvert write an AFM: that file,
    and the disk as raw files beside it (.000, then .001 and on at the -M cap)."""
    afm = "--afm" in options
    options = [o for o in options if o != "--afm"]
    afd = not afm and any(o.startswith("-M") for o in options)
    target = name + (".afm" if afm else ".afd" if afd else ".aff")
    for stale_raw in os.listdir(out_dir) if afm else []:
        if stale_raw.startswith(name + ".") and stale_raw[len(name) + 1:].isdigit():
            os.remove(os.path.join(out_dir, stale_raw))
    stale = os.path.join(out_dir, target)
    if os.path.isdir(stale):
        shutil.rmtree(stale)
    elif os.path.exists(stale):
        os.remove(stale)
    result = subprocess.run(
        [AFFCONVERT, "-q", *options, "-o", target, os.path.basename(raw_path)],
        cwd=out_dir, capture_output=True, text=True, check=False, env=env)
    if result.returncode != 0 or not os.path.exists(stale):
        raise SystemExit(f"affconvert failed for {name}:\n{result.stdout}\n{result.stderr}")
    if afm:
        files = [target] + sorted(f for f in os.listdir(out_dir)
                                  if f.startswith(name + ".") and f[len(name) + 1:].isdigit())
    elif afd:
        files = [f"{target}/{f}" for f in sorted(os.listdir(stale))
                 if f.lower().endswith(".aff")]
    else:
        files = [target]
    for f in files:
        os.chmod(os.path.join(out_dir, f), 0o644)   # affconvert creates them 0777
    return target, files


def _afflib_reads(out_dir, image, source_sha256, env):
    """True when AFFLIB's affconvert -r, with ``env`` giving it the passphrase or
    key, reads ``image`` back as the source; False when it refuses the image."""
    work = os.path.join(out_dir, "aff-enc-check")
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    try:
        local = os.path.join(work, "check" + (".afd" if image.endswith(".afd") else ".aff"))
        if os.path.isdir(os.path.join(out_dir, image)):
            shutil.copytree(os.path.join(out_dir, image), local)
        else:
            shutil.copy(os.path.join(out_dir, image), local)
        subprocess.run([AFFCONVERT, "-q", "-r", os.path.basename(local)], cwd=work,
                       capture_output=True, text=True, check=False, env=env)
        raw = os.path.join(work, "check.raw")
        if not os.path.exists(raw):
            return False
        with open(raw, "rb") as fh:
            got = hashlib.sha256(fh.read()).hexdigest()
        if got != source_sha256:
            raise SystemExit(f"{image}: AFFLIB reads it as another disk")
        return True
    finally:
        shutil.rmtree(work, ignore_errors=True)


def build_encrypted_affs(out_dir, raw_path, source_sha256):
    """The encrypted AFF images, as the manifest section."""
    key, cert = (os.path.join(out_dir, f) for f in (AFF_TEST_KEY, AFF_TEST_CERT))
    if not (os.path.exists(key) and os.path.exists(cert)):
        result = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
             "-out", cert, "-days", "36500", "-subj", "/CN=ewfprobe AFF test"],
            capture_output=True, text=True, check=False)
        if result.returncode:
            raise SystemExit(f"openssl could not make the test key:\n{result.stderr}")
        os.chmod(key, 0o644)                 # a test key, published with the fixtures
    section = {"writer": "AFFLIB " + writer_version(AFFCONVERT).split()[-1],
               "password": AFF_PASSWORD, "key": AFF_TEST_KEY, "certificate": AFF_TEST_CERT,
               "variants": {}}
    plain = {k: v for k, v in os.environ.items() if not k.startswith("AFFLIB_")}
    with_password = dict(plain, AFFLIB_PASSPHRASE=AFF_PASSWORD)
    for name, options, how in ENC_AFF_VARIANTS:
        in_place = how.endswith("in place")
        image, made = acquire_aff(raw_path, out_dir, name, options,
                                  env=plain if in_place else with_password)
        if how == "passphrase and certificate":
            step = [AFFCRYPTO, "-A", "-C", AFF_TEST_CERT, "-p", AFF_PASSWORD, image]
        elif how == "passphrase, in place":
            step = [AFFCRYPTO, "-e", "-N", AFF_PASSWORD, image]
        elif how == "certificate, in place":
            step = [AFFCRYPTO, "-e", "-C", AFF_TEST_CERT, image]
        else:
            step = None
        if step:
            result = subprocess.run(step, cwd=out_dir, capture_output=True, text=True,
                                    check=False, env=plain)
            if result.returncode:
                raise SystemExit(f"affcrypto failed for {name}:\n{result.stdout}"
                                 f"{result.stderr}")
        opens = []
        if "passphrase" in how:
            opens.append("password")
        if "certificate" in how:
            opens.append("private key")
        env = dict(plain, **({"AFFLIB_PASSPHRASE": AFF_PASSWORD} if "password" in opens
                             else {"AFFLIB_DECRYPTING_PRIVATE_KEYFILE": key}))
        entry = {"encryption": how, "opens_with": opens, "options": options,
                 "files": made, "afflib_reads": _afflib_reads(out_dir, image,
                                                              source_sha256, env)}
        if in_place:
            if entry["afflib_reads"]:
                raise SystemExit(f"{name}: AFFLIB now reads a file encrypted in place; "
                                 f"the note on it is out of date")
            with open(os.path.join(out_dir, image), "rb") as fh:
                entry["header_lost"] = fh.read(8) != b"AFF10\r\n\x00"
        elif not entry["afflib_reads"]:
            raise SystemExit(f"{name}: AFFLIB cannot read it back")
        if "private key" in opens and "password" in opens:
            entry["afflib_reads_with_key"] = _afflib_reads(
                out_dir, image, source_sha256,
                dict(plain, AFFLIB_DECRYPTING_PRIVATE_KEYFILE=key))
        if image != made[0]:
            entry["image"] = image
        section["variants"][name] = entry
        size = sum(os.path.getsize(os.path.join(out_dir, f)) for f in made)
        print(f"  {name:<24} {how:<28} {size:>9,} bytes, AFFLIB reads it: "
              f"{entry['afflib_reads']}")
    return section


def _hdiutil(out_dir, name, *args):
    result = subprocess.run([HDIUTIL, *args], cwd=out_dir, capture_output=True,
                            text=True, check=False)
    if result.returncode != 0:
        raise SystemExit(f"hdiutil failed for {name}:\n{result.stdout}\n{result.stderr}")


def acquire_dmg(raw_path, out_dir, name, fmt):
    """One Apple disk image variant, as (the path to open, the files written).
    hdiutil takes a raw disk image only under a name it recognises, so the source is
    copied to a .img beside it first and removed afterwards. A "FORMAT/SIZE" variant
    is converted to FORMAT and then passed through hdiutil segment with that segment
    size."""
    fmt, _slash, segment = fmt.partition("/")
    target = name + _DMG_SUFFIX.get(fmt, ".dmg")
    stem = os.path.join(out_dir, name)
    for stale in [os.path.join(out_dir, target)] + [
            os.path.join(out_dir, f) for f in os.listdir(out_dir)
            if f.startswith(name + ".") and f.endswith(".dmgpart")]:
        if os.path.isdir(stale):
            shutil.rmtree(stale)
        elif os.path.exists(stale):
            os.remove(stale)
    source = stem + "-source.img"
    shutil.copyfile(raw_path, source)
    whole = stem + "-whole.dmg"
    try:
        options = ["-imagekey", "sparse-band-size=2048"] if fmt == "UDSB" else []
        _hdiutil(out_dir, name, "convert", "-quiet", os.path.basename(source), "-format",
                 fmt, *options, "-o", os.path.basename(whole) if segment else target)
        if segment:
            _hdiutil(out_dir, name, "segment", "-quiet", "-segmentSize", segment, "-o",
                     name, os.path.basename(whole))
    finally:
        for temp in (source, whole):
            if os.path.exists(temp):
                os.remove(temp)
    if fmt == "UDSB":
        base = os.path.join(out_dir, target)
        made = sorted(os.path.relpath(os.path.join(d, f), out_dir)
                      for d, _dirs, files in os.walk(base) for f in files)
    else:
        made = [target] + sorted(
            (f for f in os.listdir(out_dir)
             if f.startswith(name + ".") and f.endswith(".dmgpart")),
            key=lambda f: int(f.split(".")[-2]))
    for f in made:
        os.chmod(os.path.join(out_dir, f), 0o644)
    return target, [f.replace(os.sep, "/") for f in made]


def build_gpt_dmgs(out_dir):
    """The GPT disk and its hdiutil segment images, as the manifest section."""
    work = os.path.join(out_dir, "gpt-work")
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(os.path.join(work, "files"))
    r = random.Random(20260927)
    for i in range(6):                  # generated content, some of it incompressible
        with open(os.path.join(work, "files", f"file-{i}.bin"), "wb") as fh:
            fh.write(r.randbytes(30000) + bytes(20000))
    try:
        _hdiutil(work, "gpt", "create", "-quiet", "-srcfolder", "files", "-fs", "HFS+",
                 "-layout", "GPTSPUD", "-volname", "GPTFIX", "-format", "UDRW",
                 "disk.dmg")
        with open(os.path.join(work, "disk.dmg"), "rb") as fh:
            disk = fh.read()
        _hdiutil(work, "gpt", "convert", "-quiet", "disk.dmg", "-format", "UDZO", "-o",
                 "whole.dmg")
        section = {"sha256": hashlib.sha256(disk).hexdigest(), "size": len(disk),
                   "writer": hdiutil_version(), "variants": {}}
        for name, size in GPT_DMG_VARIANTS:
            for stale in os.listdir(out_dir):
                if stale == name + ".dmg" or (stale.startswith(name + ".")
                                              and stale.endswith(".dmgpart")):
                    os.remove(os.path.join(out_dir, stale))
            _hdiutil(out_dir, name, "segment", "-quiet", "-segmentSize", size, "-o", name,
                     os.path.join(work, "whole.dmg"))
            made = [name + ".dmg"] + sorted(
                (f for f in os.listdir(out_dir)
                 if f.startswith(name + ".") and f.endswith(".dmgpart")),
                key=lambda f: int(f.split(".")[-2]))
            for f in made:
                os.chmod(os.path.join(out_dir, f), 0o644)
            section["variants"][name] = {"files": made, "hdiutil_format": "UDZO",
                                         "hdiutil_segment_size": size}
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return section


def _attached_disk(image, password):
    """The bytes hdiutil gives for ``image`` attached read-only with ``password``,
    read from /dev/rdisk: macOS's own reading of an encrypted image."""
    import re                           # pylint: disable=import-outside-toplevel
    out = subprocess.run([HDIUTIL, "attach", "-readonly", "-nomount", "-noverify",
                          "-stdinpass", image], input=password, capture_output=True,
                         text=True, timeout=120, check=False)
    if out.returncode:
        raise SystemExit(f"hdiutil could not attach {image}: {out.stderr.strip()}")
    dev = re.search(r"^(/dev/disk\d+)\s", out.stdout, re.M).group(1)
    try:
        # a raw disk takes whole-sector reads only, so read it in large blocks
        fd = os.open(dev.replace("/dev/disk", "/dev/rdisk"), os.O_RDONLY)
        try:
            pieces = []
            while True:
                piece = os.read(fd, 1 << 20)
                if not piece:
                    return b"".join(pieces)
                pieces.append(piece)
        finally:
            os.close(fd)
    finally:
        subprocess.run([HDIUTIL, "detach", "-quiet", dev], timeout=60, check=False)


def _encrypted_disks():
    r = random.Random(20260927)
    text = b"ewfprobe encrypted fixture, generated content. " * 2000
    k64, mib = 64 << 10, 1 << 20
    small = (r.randbytes(k64 // 2) + bytes(k64 // 2) + bytes(k64)
             + r.randbytes(k64 // 4) + text[:k64 * 3 // 4])
    banded = (bytes(mib) + r.randbytes(32 << 10) + bytes(mib - (32 << 10))
              + r.randbytes(16 << 10) + text[:16 << 10])
    return {"small": small, "banded": banded}


def _trim_encrypted_bundle(bundle):
    """Remove the first band file (its disk band is all zeros) and cut the second
    after its data, in whole 512-byte encrypted blocks."""
    bands = os.path.join(bundle, "bands")
    os.remove(os.path.join(bands, "0"))
    with open(os.path.join(bands, "1"), "r+b") as fh:
        fh.truncate(32 << 10)


def build_encrypted_dmgs(out_dir):
    """The encrypted images and their disks, as the manifest section."""
    work = os.path.join(out_dir, "enc-work")
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    disks = _encrypted_disks()
    section = {"writer": hdiutil_version(), "disks": {}, "variants": {}}
    try:
        for label, disk in disks.items():
            with open(os.path.join(work, label + ".img"), "wb") as fh:
                fh.write(disk)
            section["disks"][label] = {"sha256": hashlib.sha256(disk).hexdigest(),
                                       "size": len(disk)}
        for name, fmt, cipher, password, label in ENC_DMG_VARIANTS:
            fmt, _slash, segment = fmt.partition("/")
            target = name + _DMG_SUFFIX.get(fmt, ".dmg")
            for stale in os.listdir(out_dir):
                if stale == target or (stale.startswith(name + ".")
                                       and stale.endswith(".dmgpart")):
                    path = os.path.join(out_dir, stale)
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                    else:
                        os.remove(path)
            options = {"UDSB": ["-imagekey", "sparse-band-size=2048"],
                       "UDSP": ["-imagekey", "sparse-band-size=128"]}.get(fmt, [])
            if segment:
                options += ["-segmentSize", segment]
            result = subprocess.run(
                [HDIUTIL, "convert", "-quiet", os.path.join(work, label + ".img"),
                 "-format", fmt, *options, "-encryption", cipher, "-stdinpass", "-o",
                 os.path.join(out_dir, name if segment else target)],
                input=password, capture_output=True, text=True, timeout=300, check=False)
            if result.returncode:
                raise SystemExit(f"hdiutil failed for {name}:\n{result.stdout}"
                                 f"{result.stderr}")
            entry = {"format": {"UDSP": "sparseimage", "UDSB": "sparsebundle",
                                "UDRW": "udrw"}.get(fmt, "udif"),
                     "hdiutil_format": fmt, "encryption": cipher, "password": password,
                     "disk": label}
            if fmt == "UDSB":
                _trim_encrypted_bundle(os.path.join(out_dir, target))
                entry["trimmed"] = ("band file 0 (all zeros) removed and band file 1 "
                                    "cut to 32 KiB after writing; hdiutil attach "
                                    "reads the same disk")
                base = os.path.join(out_dir, target)
                made = sorted(os.path.relpath(os.path.join(d, f), out_dir)
                              for d, _dirs, files in os.walk(base) for f in files)
            else:
                made = [target] + sorted(
                    (f for f in os.listdir(out_dir)
                     if f.startswith(name + ".") and f.endswith(".dmgpart")),
                    key=lambda f: int(f.split(".")[-2]))
            for f in made:
                os.chmod(os.path.join(out_dir, f), 0o644)
            attached = _attached_disk(os.path.join(out_dir, target), password)
            if hashlib.sha256(attached).hexdigest() != section["disks"][label]["sha256"]:
                raise SystemExit(f"{name}: hdiutil attach does not give back the disk")
            entry["checked_by"] = "hdiutil attach -stdinpass, /dev/rdisk read back"
            entry["files"] = [f.replace(os.sep, "/") for f in made]
            if segment:
                entry["hdiutil_segment_size"] = segment
            if target != made[0]:
                entry["image"] = target
            section["variants"][name] = entry
            size = sum(os.path.getsize(os.path.join(out_dir, f)) for f in made)
            print(f"  {name:<30} {fmt:<5} {cipher} {len(made)} file(s) {size:>9,} bytes")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return section


def hdiutil_version():
    out = subprocess.run(["sw_vers", "-productVersion"], capture_output=True, text=True,
                         check=False).stdout.strip()
    return f"hdiutil, macOS {out}" if out else "hdiutil"


def writer_version(tool=None):
    out = subprocess.run([tool or EWFACQUIRE, "-V"], capture_output=True, text=True,
                         check=False).stdout
    return out.strip().splitlines()[0] if out.strip() else "unknown"


def rebuild_source(out, manifest):
    """The raw source, read back from a fixture and checked against the manifest."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import ewfprobe
    first = next(os.path.join(out, v.get("image", v["files"][0]))
                 for v in manifest["variants"].values())
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


AD_SECTORS = 2457                   # just over 1 MB, so a 1 MB fragment makes two files


def ad_source():
    """The disk the AD-encrypted fixtures were made from: a SHA-256 counter stream,
    so nothing in it compresses and it can be rebuilt rather than committed."""
    out = bytearray()
    i = 0
    while len(out) < AD_SECTORS * 512:
        out += hashlib.sha256(b"ewfprobe AD encryption fixture %d" % i).digest()
        i += 1
    return bytes(out[:AD_SECTORS * 512])


def main(argv):
    if "--ad-source" in argv:
        target = argv[argv.index("--ad-source") + 1]
        with open(target, "wb") as fh:
            fh.write(ad_source())
        print(f"wrote {target}: {AD_SECTORS * 512:,} bytes, "
              f"sha256 {hashlib.sha256(ad_source()).hexdigest()}")
        return 0
    args = [a for a in argv[1:] if not a.startswith("--")]
    small = "--small" in argv
    add = "--add" in argv
    if not args or (len(args) != 1 and not add) or (add and len(args) < 2):
        print(__doc__)
        return 2
    out = os.path.abspath(args[0])
    os.makedirs(out, exist_ok=True)
    aff_known = dict(AFF_VARIANTS)
    dmg_known = dict(DMG_VARIANTS)
    gpt_wanted = not add or "dmg-gpt" in args[1:]
    enc_wanted = not add or "dmg-encrypted" in args[1:]
    enc_aff_wanted = not add or "aff-encrypted" in args[1:]
    args = ([a for a in args if a not in ("dmg-gpt", "dmg-encrypted", "aff-encrypted")]
            if add else args)
    ewf_wanted = not add or any(a not in aff_known and a not in dmg_known for a in args[1:])
    aff_wanted = not add or any(a in aff_known for a in args[1:])
    dmg_wanted = not add or any(a in dmg_known for a in args[1:])
    if (dmg_wanted or gpt_wanted or enc_wanted) and not shutil.which(HDIUTIL):
        raise SystemExit(f"{HDIUTIL} not found; the Apple disk image variants are written "
                         f"on macOS (test tool only)")
    if ewf_wanted and not shutil.which(EWFACQUIRE):
        raise SystemExit(f"{EWFACQUIRE} not found; install libewf (test tool only)")
    if (aff_wanted or enc_aff_wanted) and not shutil.which(AFFCONVERT):
        raise SystemExit(f"{AFFCONVERT} not found; install AFFLIB (test tool only)")
    writer = writer_version() if ewf_wanted else None

    if add:
        with open(os.path.join(out, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        known = {v[0]: v for v in VARIANTS + SMALL_VARIANTS}
        unknown = [a for a in args[1:]
                   if a not in known and a not in aff_known and a not in dmg_known]
        if unknown:
            raise SystemExit(f"unknown variant(s): {', '.join(unknown)}")
        chosen = [known[a] for a in args[1:] if a in known]
        chosen_aff = [(a, aff_known[a]) for a in args[1:] if a in aff_known]
        chosen_dmg = [(a, dmg_known[a]) for a in args[1:] if a in dmg_known]
        raw_path = rebuild_source(out, manifest)
        print(f"raw source rebuilt and matches the manifest: {manifest['sha256'][:16]}")
    else:
        kept = kept_ad = None
        if os.path.exists(os.path.join(out, "manifest.json")):
            with open(os.path.join(out, "manifest.json"), encoding="utf-8") as fh:
                previous = json.load(fh)
            kept, kept_ad = previous.get("logical"), previous.get("ad_encrypted")
        raw_path = os.path.join(out, "source.raw")
        manifest = build_raw(raw_path, size=(3 << 20) if small else (8 << 20))
        if kept:
            manifest["logical"] = kept
        if kept_ad:
            manifest["ad_encrypted"] = kept_ad
        print(f"raw source: {manifest['size']:,} bytes, "
              f"{len(manifest['media'])} media items")
        manifest["variants"] = {}
        chosen = SMALL_VARIANTS if small else VARIANTS
        chosen_aff = list(AFF_VARIANTS)
        chosen_dmg = list(DMG_VARIANTS)

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
        image, made = acquire_aff(raw_path, out, name, options)
        manifest["variants"][name] = {
            "format": "afm" if "--afm" in options else "aff",
            "options": [o for o in options if o != "--afm"], "files": made,
            "writer": aff_writer,
        }
        if image != made[0]:
            manifest["variants"][name]["image"] = image
        size = sum(os.path.getsize(os.path.join(out, f)) for f in made)
        print(f"  {name:<20} {manifest['variants'][name]['format']:<9} "
              f"{' '.join(options):<14} {size:>10,} bytes")

    dmg_writer = hdiutil_version() if chosen_dmg else None
    for name, fmt in chosen_dmg:
        image, made = acquire_dmg(raw_path, out, name, fmt)
        base_fmt, _slash, segment = fmt.partition("/")
        manifest["variants"][name] = {
            "format": {"UDSP": "sparseimage", "UDSB": "sparsebundle"}.get(base_fmt, "udif"),
            "hdiutil_format": base_fmt, "files": made, "writer": dmg_writer,
            # UDIF records checksums of its own data, not a hash of the disk
            "stores_no_hash": True,
        }
        if segment:
            manifest["variants"][name]["hdiutil_segment_size"] = segment
        if image != made[0]:
            manifest["variants"][name]["image"] = image
        if fmt == "ULFO":
            manifest["variants"][name]["needs"] = "liblzfse"
        size = sum(os.path.getsize(os.path.join(out, f)) for f in made)
        print(f"  {name:<20} {fmt:<9} {size:>10,} bytes")

    if gpt_wanted:
        manifest["gpt_dmg"] = build_gpt_dmgs(out)
        print(f"  gpt disk             {manifest['gpt_dmg']['size']:,} bytes, "
              f"{len(manifest['gpt_dmg']['variants'])} segmented images")

    if enc_aff_wanted:
        manifest["encrypted_aff"] = build_encrypted_affs(out, raw_path, manifest["sha256"])
        print(f"  {len(manifest['encrypted_aff']['variants'])} encrypted AFF images")

    if enc_wanted:
        manifest["encrypted_dmg"] = build_encrypted_dmgs(out)
        print(f"  {len(manifest['encrypted_dmg']['variants'])} encrypted images, each "
              f"checked with hdiutil attach")

    if add:
        os.remove(raw_path)
    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    print(f"\nmanifest written to {os.path.join(out, 'manifest.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

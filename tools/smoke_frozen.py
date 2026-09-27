"""Check that a built ewfprobe gives the same output as the Python file it was built from.

    python tools/smoke_frozen.py <source folder> <executable> [<executable args> ...]

<source folder> is a checkout holding ewfprobe.py and tests/fixtures (the build workflow
checks out the tag being released there). The fixtures were written by libewf's ewfacquire,
affconvert, FTK Imager or EnCase, not by ewfprobe. For each one (EnCase 5 and 6, SMART, Ex01 and
AFF, single files, multi-segment sets and AFD directories) `info`, `verify` and a full
`export` are run once through `python ewfprobe.py` and once through the executable. Their
output must be byte-identical, verify must report the stored hashes as matching (or, for an
image that stores none, say so), and the export must hash to the source disk the manifest
records. A byte range exported to stdout must equal the manifest's media item at that
offset, and a split set with a segment missing must be refused the same way by both. For
each L01 under "logical" in the manifest, `info`, `verify`, `files`, a full `export` and an
`export --entry` of its sparse entry must also be byte-identical between the two, the
exports must hash to the manifest's known answers, and verify must report every stored
entry MD5 as matching. For each encrypted Apple disk image under "encrypted_dmg", `info`,
`verify` and a full `export`, given its password through --password-env, must be
byte-identical between the two, the export must hash to the disk hdiutil read back from it,
and a wrong password must be refused the same way by both; so the executable carries the
cipher package. The same holds for each set FTK Imager encrypted with AD encryption, under
"ad_encrypted", whose export must hash to the disk it was made from, and for each AFF
AFFLIB encrypted, under "encrypted_aff", opened with its passphrase or, when it is sealed
only to a certificate, the test private key (so the executable carries the RSA code too),
whose export must hash to the source. For the AFF4
containers in AFF4_KNOWN (written by pyaff4 or by tools/make_aff4_fixtures.py, one Snappy,
one LZ4, one deflate and a striped pair), `info`, `verify` and a full `export` must be
byte-identical between the two and the export must hash to the content the container was
written from. For the AD1s in AD1_KNOWN, written by FTK Imager (one of them AD-encrypted),
`info`, `verify`, `files` and an `export --entry` must be byte-identical between the two,
verify must report FTK's logged hashes and every entry's hashes as matching, the entry must
hash to the content written to it, and a set missing a file must be refused the same way
by both. For the virtual disks in VIRTUAL_KNOWN (from tests/fixtures/virtual), `info`,
`verify` and a full `export` must be byte-identical between the two and the export must
hash to the disk the fixtures' manifest records. The executable's --version must name the
source's __version__.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


# MD5 of the content each AFF4 fixture was written from (tools/make_aff4_fixtures.py)
AFF4_KNOWN = {
    "pyaff4-snappy.aff4": "8dd04764855150cb5ac7f36dd584571d",
    "pyaff4-lz4.aff4": "8dd04764855150cb5ac7f36dd584571d",
    "aff4-deflate-zlibstream.aff4": "8dd04764855150cb5ac7f36dd584571d",
    "aff4-striped_1.aff4": "66fae939a0fd6b5b9608aa0a1615a71c",
}


# AD1s FTK Imager wrote (tests/fixtures/ad1): the password, if any, one entry and the MD5
# of the content written to it
# Virtual disks from tests/fixtures/virtual/manifest.json: each is ungzipped and has to
# export as the disk the manifest records. zstd is left out, since whether a build has a
# zstd decompressor depends on the Python it was made with.
VIRTUAL_KNOWN = ["windows-diff", "windows-diffx", "qemu-vmdk-streamOptimized",
                 "qemu-vmdk-twoGbMaxExtentSparse", "qemu-qcow2-zlib", "qemu-qcow2-overlay",
                 "qemu-qcow1", "qemu-qcow2-zeroed", "constructed-dirty-log",
                 "constructed-cowd", "constructed-qcow1-compressed"]

AD1_KNOWN = [
    ("lean-src-c0-1mb.ad1", None, "docs/exact-64k.bin", "931c16b5fb19651e435e08b9db899364"),
    ("lean-src-c6-1mb-adcrypt.ad1", "Ad1Test-2026!", "docs/pattern-2300k.bin",
     "b8015224bde72d81265895d4bd95979d"),
    ("lean-multi-ntfs-c9.ad1", None, "U:\\:AD1LEAN [NTFS]/[root]/known/readme.txt/extra",
     "7680f5e1acfeff91e96ea53619522e02"),
]


def run(cmd: list[str], cwd: Path, want: int = 0, env=None) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, check=False, env=env)
    if r.returncode != want:
        sys.exit(f"FAILED (exit {r.returncode}, wanted {want}): {' '.join(cmd)}\n"
                 f"{r.stdout[-2000:]!r}\n{r.stderr[-4000:]!r}")
    return r


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.exit(__doc__)
    src = Path(argv[0]).resolve()
    exe = [str(Path(argv[1]).resolve()) if Path(argv[1]).exists() else argv[1], *argv[2:]]
    py = [sys.executable, str(src / "ewfprobe.py")]
    fixtures = src / "tests" / "fixtures"
    manifest = json.loads((fixtures / "manifest.json").read_text(encoding="utf-8"))

    source_version = run(py + ["--version"], src).stdout.strip()
    built_version = run(exe + ["--version"], src).stdout.strip()
    print("source:", source_version.decode(), "| built:", built_version.decode())
    assert built_version == source_version, (built_version, source_version)

    checks = 0
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for name, variant in sorted(manifest["variants"].items()):
            image = str(fixtures / variant.get("image", variant["files"][0]))
            if variant.get("needs") == "liblzfse":
                # The executables do not bundle pyliblzfse, so an LZFSE image is
                # refused, and the refusal has to name what is missing.
                b = run(exe + ["info", image], work, want=2)
                assert b"pyliblzfse" in b.stderr, (name, b.stderr)
                checks += 1
                print(f"{name}: refused, naming the optional package it needs")
                continue
            out = {}
            for who, cmd in (("py", py), ("exe", exe)):
                raw = work / f"{name}-{who}.raw"
                out[who] = (run(cmd + ["info", image], work).stdout,
                            run(cmd + ["verify", "-q", image], work).stdout,
                            run(cmd + ["export", "-q", image, "-o", str(raw)], work).stdout,
                            raw.read_bytes())
            assert out["py"] == out["exe"], f"{name}: the executable's output differs from the source's"
            verify = out["exe"][1].decode()
            if variant.get("stores_no_hash"):
                assert "recorded no hash" in verify and "does not match" not in verify.lower(), verify
            else:
                assert verify.count("matches the stored hash") >= 1 and "does not match" not in verify.lower(), verify
            assert hashlib.sha256(out["exe"][3]).hexdigest() == manifest["sha256"], f"{name}: export hash"
            checks += 1
            print(f"{name}: info, verify and a {len(out['exe'][3]):,} byte export identical; "
                  f"the export matches the source disk's SHA-256")

        # a byte range to stdout, which also exercises binary stdout on Windows
        item = manifest["media"][0]
        image = str(fixtures / manifest["variants"]["encase6-split"]["files"][0])
        rng = ["export", "-q", image, "--offset", str(item["offset"]), "--length", str(item["length"])]
        a, b = run(py + rng, work).stdout, run(exe + rng, work).stdout
        assert a == b and hashlib.sha256(b).hexdigest() == item["sha256"], "range export to stdout"
        checks += 1
        print(f"a {item['length']:,} byte range exported to stdout matches the manifest's {item['kind']}")

        # a split set with its third segment missing is refused, the same way by both
        cut = work / "cut"
        cut.mkdir()
        for f in manifest["variants"]["encase6-split"]["files"]:
            if not f.endswith(".E03"):
                shutil.copy(fixtures / f, cut / f)
        a = run(py + ["info", "cut/encase6-split.E01"], work, want=2)
        b = run(exe + ["info", "cut/encase6-split.E01"], work, want=2)
        assert a.stderr.replace(b"\r\n", b"\n") == b.stderr.replace(b"\r\n", b"\n") and b.stderr, (a.stderr, b.stderr)
        checks += 1
        print("a set missing a segment is refused by both:", b.stderr.decode().strip())

        for name, known in sorted(manifest.get("logical", {}).items()):
            image = str(fixtures / known["files"][0])
            entry = known["sparse_entry"]
            out = {}
            for who, cmd in (("py", py), ("exe", exe)):
                media = work / f"{name}-{who}.media"
                sparse = work / f"{name}-{who}.entry"
                out[who] = (run(cmd + ["info", image], work).stdout,
                            run(cmd + ["verify", "-q", image], work).stdout,
                            run(cmd + ["files", image], work).stdout,
                            run(cmd + ["export", "-q", image, "-o", str(media)], work).stdout,
                            run(cmd + ["export", image, "--entry", entry["path"],
                                       "-o", str(sparse)], work).stdout,
                            media.read_bytes(), sparse.read_bytes())
            assert out["py"] == out["exe"], f"{name}: the executable's output differs"
            verify = out["exe"][1].decode()
            assert f"{known['entry_md5s']:,} checked, all match" in verify, verify
            assert hashlib.sha256(out["exe"][5]).hexdigest() == known["media_sha256"], name
            assert hashlib.sha256(out["exe"][6]).hexdigest() == entry["sha256"], name
            listed = out["exe"][2].decode("utf-8").splitlines()
            assert len(listed) == known["entries"] + 1, (name, len(listed))
            checks += 1
            print(f"{name}: info, verify, files and exports identical; the media data and its "
                  f"sparse entry match libewf's export, {known['entry_md5s']} entry MD5s match")

        encrypted = manifest.get("encrypted_dmg", {"variants": {}})
        for name, variant in sorted(encrypted["variants"].items()):
            image = str(fixtures / variant.get("image", variant["files"][0]))
            pw = ["--password-env", "EWFPROBE_SMOKE_PASSWORD"]
            env = dict(os.environ, EWFPROBE_SMOKE_PASSWORD=variant["password"])
            out = {}
            for who, cmd in (("py", py), ("exe", exe)):
                raw = work / f"{name}-{who}.raw"
                out[who] = (run(cmd + ["info", *pw, image], work, env=env).stdout,
                            run(cmd + ["verify", "-q", *pw, image], work, env=env).stdout,
                            run(cmd + ["export", "-q", *pw, image, "-o", str(raw)], work,
                                env=env).stdout,
                            raw.read_bytes())
            assert out["py"] == out["exe"], f"{name}: the executable's output differs"
            disk = encrypted["disks"][variant["disk"]]
            assert hashlib.sha256(out["exe"][3]).hexdigest() == disk["sha256"], f"{name}: export"
            bad = dict(os.environ, EWFPROBE_SMOKE_PASSWORD=variant["password"] + "x")
            a = run(py + ["info", *pw, image], work, want=2, env=bad).stderr
            b = run(exe + ["info", *pw, image], work, want=2, env=bad).stderr
            assert a.replace(b"\r\n", b"\n") == b.replace(b"\r\n", b"\n"), (a, b)
            assert b"does not open" in b, b
            checks += 1
            print(f"{name}: decrypted with its password, info, verify and a "
                  f"{len(out['exe'][3]):,} byte export identical; the export matches the disk "
                  f"hdiutil read back, and a wrong password is refused by both")

        enc_aff = manifest.get("encrypted_aff", {"variants": {}})
        for name, variant in sorted(enc_aff["variants"].items()):
            image = str(fixtures / variant.get("image", variant["files"][0]))
            if "password" in variant["opens_with"]:
                given = ["--password-env", "EWFPROBE_SMOKE_PASSWORD"]
            else:
                given = ["--private-key", str(fixtures / enc_aff["key"])]
            env = dict(os.environ, EWFPROBE_SMOKE_PASSWORD=enc_aff["password"])
            out = {}
            for who, cmd in (("py", py), ("exe", exe)):
                raw = work / f"{name}-{who}.raw"
                out[who] = (run(cmd + ["info", *given, image], work, env=env).stdout,
                            run(cmd + ["verify", "-q", *given, image], work, env=env).stdout,
                            run(cmd + ["export", "-q", *given, image, "-o", str(raw)], work,
                                env=env).stdout,
                            raw.read_bytes())
            assert out["py"] == out["exe"], f"{name}: the executable's output differs"
            assert hashlib.sha256(out["exe"][3]).hexdigest() == manifest["sha256"], name
            a = run(py + ["info", image], work, want=2).stderr
            b = run(exe + ["info", image], work, want=2).stderr
            assert a.replace(b"\r\n", b"\n") == b.replace(b"\r\n", b"\n"), (a, b)
            assert b"encrypted AFF" in b, b
            checks += 1
            print(f"{name}: opened with its {'password' if '--password-env' in given else 'private key'}, info, "
                  f"verify and a {len(out['exe'][3]):,} byte export identical; the export "
                  f"matches the source, and without it both refuse the image")

        certified = manifest.get("certificate_dmg", {"variants": {}})
        for name, variant in sorted(certified["variants"].items()):
            image = str(fixtures / variant.get("image", variant["files"][0]))
            key = str(fixtures / certified["keys"][str(variant["key_bits"])]["key"])
            out = {}
            for who, cmd in (("py", py), ("exe", exe)):
                raw = work / f"{name}-{who}.raw"
                out[who] = (run(cmd + ["info", "--private-key", key, image], work).stdout,
                            run(cmd + ["verify", "-q", "--private-key", key, image],
                                work).stdout,
                            run(cmd + ["export", "-q", "--private-key", key, image, "-o",
                                       str(raw)], work).stdout,
                            raw.read_bytes())
            assert out["py"] == out["exe"], f"{name}: the executable's output differs"
            disk = certified["disks"][variant["disk"]]
            assert hashlib.sha256(out["exe"][3]).hexdigest() == disk["sha256"], name
            a = run(py + ["info", image], work, want=2).stderr
            b = run(exe + ["info", image], work, want=2).stderr
            assert a.replace(b"\r\n", b"\n") == b.replace(b"\r\n", b"\n"), (a, b)
            checks += 1
            print(f"{name}: opened with its certificate's private key, info, verify and a "
                  f"{len(out['exe'][3]):,} byte export identical; the export matches the "
                  f"disk, and without the key both refuse the image")

        ad = manifest.get("ad_encrypted", {"variants": {}})
        for name, variant in sorted(ad["variants"].items()):
            image = str(fixtures / variant["files"][0])
            pw = ["--password-env", "EWFPROBE_SMOKE_PASSWORD"]
            env = dict(os.environ, EWFPROBE_SMOKE_PASSWORD=ad["password"])
            out = {}
            for who, cmd in (("py", py), ("exe", exe)):
                raw = work / f"{name}-{who}.raw"
                out[who] = (run(cmd + ["info", *pw, image], work, env=env).stdout,
                            run(cmd + ["verify", "-q", *pw, image], work, env=env).stdout,
                            run(cmd + ["export", "-q", *pw, image, "-o", str(raw)], work,
                                env=env).stdout,
                            raw.read_bytes())
            assert out["py"] == out["exe"], f"{name}: the executable's output differs"
            assert hashlib.sha256(out["exe"][3]).hexdigest() == ad["source"]["sha256"], name
            bad = dict(os.environ, EWFPROBE_SMOKE_PASSWORD=ad["password"] + "x")
            a = run(py + ["info", *pw, image], work, want=2, env=bad).stderr
            b = run(exe + ["info", *pw, image], work, want=2, env=bad).stderr
            assert a.replace(b"\r\n", b"\n") == b.replace(b"\r\n", b"\n"), (a, b)
            assert b"does not open" in b, b
            checks += 1
            print(f"{name}: AD encryption opened with its password, info, verify and a "
                  f"{len(out['exe'][3]):,} byte export identical; the export matches the disk "
                  f"FTK Imager imaged, and a wrong password is refused by both")

        for name, md5 in sorted(AFF4_KNOWN.items()):
            image = str(fixtures / name)
            out = {}
            for who, cmd in (("py", py), ("exe", exe)):
                raw = work / f"{name}-{who}.raw"
                out[who] = (run(cmd + ["info", image], work).stdout,
                            run(cmd + ["verify", "-q", image], work).stdout,
                            run(cmd + ["export", "-q", image, "-o", str(raw)], work).stdout,
                            raw.read_bytes())
            assert out["py"] == out["exe"], f"{name}: the executable's output differs"
            assert hashlib.md5(out["exe"][3]).hexdigest() == md5, name
            checks += 1
            print(f"{name}: AFF4 info, verify and a {len(out['exe'][3]):,} byte export "
                  f"identical; the export matches the content it was written from")

        for name, password, entry, md5 in AD1_KNOWN:
            image = str(fixtures / "ad1" / name)
            pw = ["--password-env", "EWFPROBE_SMOKE_PASSWORD"] if password else []
            env = dict(os.environ, EWFPROBE_SMOKE_PASSWORD=password or "")
            out = {}
            for who, cmd in (("py", py), ("exe", exe)):
                got = work / f"{name}-{who}.entry"
                out[who] = (run(cmd + ["info", *pw, image], work, env=env).stdout,
                            run(cmd + ["verify", "-q", *pw, image], work, env=env).stdout,
                            run(cmd + ["files", *pw, image], work, env=env).stdout,
                            run(cmd + ["export", "-q", *pw, image, "--entry", entry,
                                       "-o", str(got)], work, env=env).stdout,
                            got.read_bytes())
            assert out["py"] == out["exe"], f"{name}: the executable's output differs"
            verify = out["exe"][1]
            assert verify.count(b"matches the stored hash") == 2, (name, verify)
            assert b"DO NOT MATCH" not in verify, (name, verify)
            assert hashlib.md5(out["exe"][4]).hexdigest() == md5, name
            checks += 1
            print(f"{name}: AD1 info, verify, files and an entry export identical; FTK's "
                  f"logged hashes and every entry's match, and the entry matches its content")
        short = work / "ad1-short"
        short.mkdir()
        for n in (1, 2, 3):
            shutil.copy(fixtures / "ad1" / f"lean-src-c0-1mb.ad{n}", short)
        a = run(py + ["info", str(short / "lean-src-c0-1mb.ad1")], work, want=2).stderr
        b = run(exe + ["info", str(short / "lean-src-c0-1mb.ad1")], work, want=2).stderr
        assert a.replace(b"\r\n", b"\n") == b.replace(b"\r\n", b"\n"), (a, b)
        assert b"records 4 files" in b, b
        checks += 1
        print("an AD1 set missing a file is refused the same way by both")

        virtual = json.loads((fixtures / "virtual" / "manifest.json").read_text(
            encoding="utf-8"))["cases"]
        by_name = {c["name"]: c for c in virtual}
        for name in VIRTUAL_KNOWN:
            case = by_name[name]
            where = work / name
            where.mkdir()
            for f in case["files"]:
                with gzip.open(fixtures / "virtual" / case["folder"] / (f + ".gz")) as g:
                    (where / f).write_bytes(g.read())
            image = str(where / case["open"])
            out = {}
            for who, cmd in (("py", py), ("exe", exe)):
                raw = work / f"{name}-{who}.raw"
                out[who] = (run(cmd + ["info", image], work).stdout,
                            run(cmd + ["verify", "-q", image], work).stdout,
                            run(cmd + ["export", "-q", image, "-o", str(raw)], work).stdout,
                            raw.read_bytes())
            assert out["py"] == out["exe"], f"{name}: the executable's output differs"
            assert hashlib.sha256(out["exe"][3]).hexdigest() == case["sha256"], name
            checks += 1
            print(f"{name}: virtual disk info, verify and export identical; the export "
                  f"matches the disk its manifest records")

    assert checks == (len(manifest["variants"]) + len(manifest.get("logical", {})) + 2
                      + len(manifest.get("encrypted_dmg", {}).get("variants", {}))
                      + len(manifest.get("ad_encrypted", {}).get("variants", {}))
                      + len(manifest.get("encrypted_aff", {}).get("variants", {}))
                      + len(manifest.get("certificate_dmg", {}).get("variants", {}))
                      + len(AFF4_KNOWN) + len(AD1_KNOWN) + 1 + len(VIRTUAL_KNOWN)), checks
    print(f"{checks} checks: the executable wrote the same bytes as the source")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

"""Check that a built ewfprobe gives the same output as the Python file it was built from.

    python tools/smoke_frozen.py <source folder> <executable> [<executable args> ...]

<source folder> is a checkout holding ewfprobe.py and tests/fixtures (the build workflow
checks out the tag being released there). The fixtures were written by libewf's ewfacquire,
affconvert or FTK Imager, not by ewfprobe. For each one (EnCase 5 and 6, SMART, Ex01 and
AFF, single files and multi-segment sets) `info`, `verify` and a full `export` are run once
through `python ewfprobe.py` and once through the executable. Their output must be
byte-identical, verify must report the stored hashes as matching (or, for an image that
stores none, say so), and the export must hash to the source disk the manifest records. A
byte range exported to stdout must equal the manifest's media item at that offset, and a
split set with a segment missing must be refused the same way by both. The executable's
--version must name the source's __version__.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def run(cmd: list[str], cwd: Path, want: int = 0) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, check=False)
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
            image = str(fixtures / variant["files"][0])
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

    assert checks == len(manifest["variants"]) + 2, checks
    print(f"{checks} checks: the executable wrote the same bytes as the source")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

# ewfprobe

A read-only reader for EnCase/EWF (`.E01`, `.Ex01`) and SMART (`.s01`) forensic images. One file, pure
Python, standard library only. No compiler, no network, nothing to install.

It opens an acquisition, joins its segments, and presents the acquired disk as
an ordinary seekable file object, so anything that can read a raw image can read
an E01 without changing how it reads.

```python
import ewfprobe

with ewfprobe.open_ewf("evidence.E01") as img:
    img.seek(0)
    boot = img.read(512)
```

The object answers `seek`, `tell`, `read` and `close` and works as a context
manager. That is the whole interface a volume or filesystem parser needs, which
means an existing parser written against `open(path, "rb")` takes an E01 with a
one-line change at the point the image is opened.

## Why this exists

The established library for this format is libewf, which is excellent and is
LGPL, ships as a C extension, and has no wheels for several of the platforms and
Python versions we target. This reader exists so an MIT-licensed tool can accept
an E01 with no copyleft dependency, no build toolchain, and no install step:
copy one file in and it works on Windows, macOS and Linux alike.

Nothing here is derived from libewf or from any other EWF implementation. It is
written from the public format documentation, credited below.

## Command line

```
ewfprobe info    evidence.E01     # geometry, segments, metadata, stored hashes
ewfprobe verify  evidence.E01     # recompute MD5 and SHA-1, compare with stored
ewfprobe export  evidence.E01 -o out.raw
ewfprobe export  evidence.E01 -o - --offset 1048576 --length 65536
```

`verify` exits non-zero when the recomputed hash does not match the one the
acquisition recorded.

## What it reads

Reads EWF-E01, which is what EnCase 6 and 7, FTK Imager and `ewfacquire` write,
and by far the most common form in the field. Also reads EWF-S01, the variant
ASR Data's SMART writes, with segments named `.s01`, `.s02` and on. Multi-segment
sets are joined automatically from any member of the set.

A SMART image records less than an E01 does. Its volume section has no media
type, so `info` says "not recorded" rather than guessing, and its compression
level is read from the header section instead.

Reads Ex01 (EWF2), the format EnCase 7 introduced: segments named `.Ex01`,
`.Ex02` and on, chunks stored deflated, stored with a checksum, or as a repeated
eight-byte pattern, and the MD5 and SHA-1 the acquisition recorded. Case and drive
details are reported under the specification's own names; the two times it keeps,
target time and actual time, are shown as stored, seconds since 1970 in UTC.

Refused with a message naming the reason rather than read wrongly:

- **Encrypted Ex01.** EnCase can encrypt an Ex01, and the encryption is not
  publicly documented.
- **Ex01 compressed with bzip2.** The format allows it, EnCase does not appear to
  offer it, and no sample exists to check a reader against.
- **Logical evidence** (`.L01`, `.Lx01`). These hold files, not a disk image.

It never writes.

Two behaviours worth knowing:

- **An incomplete segment set is refused, not read.** A partial set otherwise
  reads as a small clean image and reports the data it is missing as empty,
  which is the kind of quiet wrong answer that matters here.
- **Encrypted content stays encrypted.** An image of a BitLocker, FileVault or
  encrypted APFS volume reads back as the ciphertext that was acquired. The
  reader is working; there is simply nothing plain in there to find.

## How it was validated

Three layers, and they are different strengths, so they are listed separately.

**Against the specification.** A small EWF writer in the test suite, a separate
program from the reader, builds fixtures from the format documentation. The
reader must return the exact bytes that went in. Four deliberate breaks confirm
the tests fail when they should: ignoring the per-chunk compression flag,
ignoring the table base offset, accepting an incomplete set, and dropping the
chunk checksum check.

**Against the reference implementation.** Fixtures written by `ewfacquire` from
libewf, in nine variants covering the encase5, encase6, encase7 and ftk formats,
compression set to none, fast and best, chunk geometries of 16, 64 and 256
sectors, and a multi-segment set. Every variant reproduces its source byte for
byte and matches its own stored hash. Three of those variants are committed
under `tests/fixtures` so the suite runs without libewf present.

SMART is covered the same way: two variants written by `ewfacquire -f smart`
(libewf 20260924), one of them a four-segment set, are committed beside the
E01 fixtures, and libewf 20140817 writes the same layout. So are SMART images
written by FTK Imager 4.7.3.61 from the same source, one a single file and one a
four-segment set, together with an FTK Imager E01: every one reproduces the
source and matches the MD5 and SHA-1 FTK Imager recorded. SMART has not been
checked against an image written by ASR Data's own SMART.

The compression a SMART image reports is the value its header records, and FTK
Imager records it inaccurately: its four-segment set was written at compression
0, holds stored chunks, and its header still says "fast". FTK Imager's E01 errs
the other way, as described below. Read that line as what the image
claims, not as a measurement.

Ex01 is covered by two fixtures written by `ewfacquire -f encase7-v2` (libewf
20260924; the libewf 20140817 that Homebrew installs writes an ordinary E01 when
asked for Ex01), which between them hold all three chunk forms, and by a
multi-segment set built by the test suite's own writer. A nine-segment set from
libewf was also checked by hand. No Ex01 written by EnCase itself has been
available, so Ex01 support rests on the EWF2 documentation and on libewf's writer
until one is.

**Against real evidence.** Physical acquisitions written by FTK Imager, from
28.6 GiB to 238 GiB, including 15-segment sets. Decoded ranges are byte
identical to `ewfexport`'s output for the same ranges, including ranges that
span a segment boundary, and full-image MD5 and SHA-1 match the hashes the
acquisition tool itself recorded. That last check is the strongest available,
because the expected value comes from neither this reader nor libewf.

One detail those images surfaced: FTK Imager can declare "no compression" in the
volume header while still writing compressed chunks. A reader that decides
compression from the header rather than from each chunk's own flag produces
garbage on such an image.

## Standalone executables

Each release carries `ewfprobe` built as a single executable with PyInstaller on
Python 3.14, for Windows x64 and arm64, macOS on Apple silicon and Intel, and Linux x64
and arm64, beside `ewfprobe.py` itself. The workflow that builds them
(`.github/workflows/build-executables.yml`) runs each executable on the reference images
in `tests/fixtures`. It requires `info`, `verify` and `export` to write the same bytes as
`python ewfprobe.py`, the export to match the source disk's SHA-256, and a set missing a
segment to be refused, before it is packaged with `SHA256SUMS.txt` and a README. The
executables are not code signed; the README inside each archive says what Windows
SmartScreen and macOS Gatekeeper will ask.

## Tests

```
python -m pytest tests -q
```

The reference fixtures are regenerated with:

```
python tools/make_fixtures.py tests/fixtures --small
```

To add variants without rewriting the committed ones, `--add` rebuilds the
source image from an existing fixture, checks it against the manifest's SHA-256,
and writes only the variants named. `EWFACQUIRE` picks which `ewfacquire` to run,
and the manifest records which version wrote each variant:

```
EWFACQUIRE=/path/to/ewfacquire python tools/make_fixtures.py tests/fixtures --add smart-fast smart-split
```

That tool shells out to `ewfacquire` and is for development only. libewf is used
there solely to produce test data. Nothing from it ships and `ewfprobe` imports
nothing.

## Format reference

Joachim Metz, *Expert Witness Compression Format (EWF)* and *Expert Witness
Compression Format 2 (EWF2)*, in the
[libyal/libewf](https://github.com/libyal/libewf) repository under
`documentation/`. The format is publicly documented, which is what makes an
independent implementation possible.

## License

MIT. See `LICENSE`.

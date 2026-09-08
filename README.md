# ewfprobe

A read-only reader for EnCase/EWF (`.E01`) forensic images. One file, pure
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
and by far the most common form in the field. Multi-segment sets are joined
automatically from any member of the set.

It does not read the newer Ex01 (EWF2), the SMART `.s01` variant, or logical
`.L01` evidence, and it never writes.

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

## Tests

```
python -m pytest tests -q
```

The reference fixtures are regenerated with:

```
python tools/make_fixtures.py tests/fixtures --small
```

That tool shells out to `ewfacquire` and is for development only. libewf is used
there solely to produce test data. Nothing from it ships and `ewfprobe` imports
nothing.

## Format reference

Joachim Metz, *Expert Witness Compression Format (EWF)*, in the
[libyal/libewf](https://github.com/libyal/libewf) repository under
`documentation/`. The format is publicly documented, which is what makes an
independent implementation possible.

## License

MIT. See `LICENSE`.

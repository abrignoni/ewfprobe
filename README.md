# ewfprobe

A read-only reader for EnCase/EWF (`.E01`, `.Ex01`), SMART (`.s01`) and AFF (`.aff`, `.afd`) forensic images. One file, pure
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

Reads AFF, the Advanced Forensic Format that AFFLIB and FTK Imager write: pages
stored deflated, LZMA-compressed, as a run of zeros or as they are, and the MD5,
SHA-1 and SHA-256 the file recorded. Case details AFF shares with EWF (case
number, examiner, notes, acquisition date) are reported under the same names;
every other text segment keeps the name AFFLIB stores it under. A page that is
missing from the file is read the way AFFLIB reads it, filled with the file's own
bad-sector marker, and `info` and `verify` count it. FTK Imager's AFF stores no
hash of the disk (FTK Imager keeps its hashes in its text log), so `verify` has
nothing to compare against on one.

Reads AFD, the form of AFF split across files: a directory named `.afd` holding
ordinary AFF files, which AFFLIB names `file_000.aff`, `file_001.aff` and on.
`affconvert` writes one when its output name ends `.afd`, splitting at the size
given with `-M`. FTK Imager 4.7.3.61 wrote one in each of two runs where the
source was larger than the AFF fragment size: a 3 MiB source with 1 MB
fragments, and a 1,600 MiB source with the 1500 MB its dialog pre-fills, which
came out as an AFD holding a single file. A 3 MiB source with that 1500 MB came
out as one `.aff`, and the dialog notes that 0 means do not fragment. Open the
directory or any `.aff` file in it: one file can hold only some of the pages, so
the whole directory is read either way. Given one file, AFFLIB's own `affcat`
reads that file alone, and on FTK Imager's AFD it wrote nothing for the first
and last files and reported no error.

The files are joined the way AFFLIB joins them (`lib/vnode_afd.cpp`): a segment
is read from the first file that holds it, and the image size is the largest any
file records. AFFLIB takes the files in the order the directory lists them,
which differs between filesystems, so a page, a hash, the page size, the sector
size or the bad-sector marker that two files record differently is refused
rather than settled by that order. When the files carry AFFLIB's names, a gap in
the numbering is refused as a missing file. A missing last file cannot be seen
from the numbering: when it held the image size, as it does in an AFD from
`affconvert`, the image is refused; otherwise its pages are counted as missing
pages by `info` and `verify`.

`open_image()` is the same function as `open_ewf()`, and `is_image()` is true for
every signature ewfprobe reads and for an AFD directory, where `is_ewf()` stays
true for EWF alone.

Refused with a message naming the reason rather than read wrongly:

- **Encrypted Ex01.** EnCase can encrypt an Ex01, and the encryption is not
  publicly documented.
- **Ex01 compressed with bzip2.** The format allows it, EnCase does not appear to
  offer it, and no sample exists to check a reader against.
- **Logical evidence** (`.L01`, `.Lx01`). These hold files, not a disk image.
- **Encrypted AFF**, and **AFF pages compressed with bzip2**, which AFFLIB itself
  never implemented.
- **An AFF file with no image size.** AFF records the size when the acquisition
  finishes, so its absence means the file may be incomplete.
- **An AFD with a gap in its file numbering**, or whose files disagree on a page,
  a hash, the page size, the sector size or the bad-sector marker.
- **AFM**, AFF metadata kept beside the image as split raw files (`.000`, `.001`
  and on).

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

AFF is covered by three fixtures written by `affconvert` from AFFLIB 3.7.22, with
a 64 KiB page so that zero pages, deflated pages, LZMA pages and stored pages all
occur, and one written by FTK Imager 4.7.3.61. FTK Imager's AFF names AFFLIB
3.7.18 as its writer, so it is a second AFFLIB version rather than an independent
implementation. Every one reproduces the source, and the three from `affconvert`
match the MD5 and SHA-1 they recorded. A writer in the test suite covers the
cases the fixtures cannot: a missing page, encrypted segments, a truncated file,
the older `seg` page names, and an image size above 4 GiB.

AFD is covered by two fixtures. One is written by `affconvert -s64k -M32k`, which
spreads the 48 pages over five files, with none in the first and the image size
and hashes only in the last. The other is written by FTK Imager 4.7.3.61 with 1 MB
fragments and compression 0: three files, its only page in the middle one, the
image size in all three, and the sector size stored as text in the first and
as a number in the others. Both reproduce the source when opened from the
directory and from every file in it, and AFFLIB's `affcat` reads both back to the
same SHA-256. The one from `affconvert` matches the MD5 and SHA-1 it recorded;
FTK Imager's matches the MD5 and SHA-1 in FTK Imager's own log, checked by hand,
since the image stores none. The test writer covers pages spread over files, a
page stored twice, files that disagree, gaps in the numbering and a lost last
file.

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

That tool shells out to `ewfacquire` and `affconvert` and is for development only.
libewf and AFFLIB are used there solely to produce test data. Nothing from them
ships and `ewfprobe` imports nothing.

## Format reference

Joachim Metz, *Expert Witness Compression Format (EWF)* and *Expert Witness
Compression Format 2 (EWF2)*, in the
[libyal/libewf](https://github.com/libyal/libewf) repository under
`documentation/`. The format is publicly documented, which is what makes an
independent implementation possible.

For AFF: AFFLIB's own documentation (`doc/affdoc.doc`) and the segment names and
flag values in its public header, `include/afflib/afflib.h`, in the
[sshock/AFFLIBv3](https://github.com/sshock/AFFLIBv3) repository, and for AFD how
AFFLIB finds, names and joins the files of one, in `lib/vnode_afd.cpp` at commit
[`f35df6c`](https://github.com/sshock/AFFLIBv3/blob/f35df6c1d2610e3233c30d50054c00e29d7d5a23/lib/vnode_afd.cpp).
No AFFLIB code is copied.

## License

MIT. See `LICENSE`.

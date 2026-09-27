# ewfprobe

A read-only reader for EnCase/EWF (`.E01`, `.Ex01`), SMART (`.s01`) and AFF (`.aff`, `.afd`) forensic images, Apple disk images (`.dmg`, including one split into `.dmgpart` files, `.sparseimage`, `.sparsebundle`), and EnCase logical evidence (`.L01`). One file, pure
Python, standard library only. No compiler, no network, nothing to install (an
LZFSE-compressed `.dmg` needs the optional `pyliblzfse` package, and an encrypted Apple
disk image or an acquisition FTK Imager encrypted with AD encryption the optional
`pycryptodome` package).

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
ewfprobe verify  acquisition.dmg  # also checks the checksums a .dmg records
ewfprobe files   evidence.L01     # an L01's entries: kind, size, stored MD5, path
ewfprobe export  evidence.L01 --entry "Folder/photo.jpg" -o photo.jpg
ewfprobe info    --password-file pw.txt encrypted.dmg
ewfprobe verify  --password-env CASE_PW evidence.E01   # FTK Imager AD encryption
```

`verify` exits non-zero when the recomputed hash does not match the one the
acquisition recorded.

An encrypted image (an Apple disk image, or an acquisition FTK Imager wrote with AD
encryption) needs its password. `--password-file FILE` reads it
from the first line of a file and `--password-env NAME` from an environment
variable; without either, ewfprobe asks for it at a terminal. It is never taken as
an argument's value, which would put it in the process list and the shell history.

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

Reads L01, EnCase's logical evidence: files collected from a device rather than a
disk, in segments named `.L01`, `.L02` and on. The image object's stream is the
L01's media data, the content of every entry back to back, and
`logical_entries` lists the entries in tree order:

```python
with ewfprobe.open_ewf("evidence.L01") as img:
    for entry in img.logical_entries:
        print(entry.path, entry.size, entry.md5)
    photo = img.read_entry(img.find_entry("Folder/photo.jpg"))
```

Each entry carries its names (a name can itself hold "/" or "\\", so `path`, the
names joined by "/", is for display), its size, the MD5 and SHA-1 stored for it
where set, its flags, the times that are set, its children, and `values`, every
column exactly as the ltree stores it. `open_entry()` gives an entry's content as
a seekable file and `read_entry()` reads it whole. `ewfprobe files` lists the
entries, `ewfprobe export --entry` writes one out, and `verify` checks every MD5
EnCase stored for an entry.

Measured on the five real L01s described under validation:

- **An entry can hold data of its own and have children.** 123 to 191 entries
  per file do, among them plists, photos and databases. Their own data begins
  with the bytes `02 00 00 00` in every case and usually names the entry in
  UTF-16, and most have a child of the same name, with parsed content such as a
  plist's keys beside it. For the plist examined and for 30 photos checked against
  a separate logical dump, that child holds the file's bytes. What EnCase means by
  the parent's data is not documented, so it is read as stored. libewf's
  `ewfexport -f files` writes the child and treats the parent as a plain folder.
- **A sparse entry's duplicate data offset (`du`) is decimal**, where extent
  offsets are hexadecimal. Read as decimal, the one sparse entry in each file gives
  content matching its stored MD5; read as hexadecimal it does not. A sparse entry
  without a duplicate offset repeats its one stored byte, as the specification
  describes; none of the tested files holds one.
- **Names are reported as stored.** The specification describes a middle dot
  (U+00B7) as the separator of an NTFS alternate data stream. In the tested files
  middle dots appear in the names of parsed plist keys, so a middle dot does not
  by itself mark a stream. Unpaired surrogates, which the specification says the
  ltree allows, are kept.

Times (`cr`, `ac`, `wr`, `mo`, `dl`, `aq`) are read as the POSIX values the
specification describes. None of the tested files sets them, so that part rests on
the specification alone.

Reads Apple disk images: UDIF (`.dmg`), the format `hdiutil` writes and macOS
acquisition tools deliver, including one `hdiutil segment` split into `.dmgpart`
files, sparse images (`.sparseimage`) and sparse bundles (`.sparsebundle`). Fuji, the open-source
macOS acquisition tool, copies the files into a sparse image and then converts it
with `hdiutil convert -format UDZO` (`acquisition/abstract.py`, line 405 at
[`d9cf00f`](https://github.com/Lazza/Fuji/blob/d9cf00f913970204fd75b94440206f9e6f09906d/acquisition/abstract.py#L405)),
so its Rsync, ASR and Ditto acquisitions are UDZO `.dmg` files; its sysdiagnose
method writes a zip instead.

| `hdiutil` format | What the chunks are | Reads with |
| --- | --- | --- |
| UDZO | zlib | the standard library |
| UDBZ | bzip2 | the standard library |
| ULMO | LZMA | the standard library |
| UDCO | ADC | this file (ADC is short and documented) |
| ULFO | LZFSE | the optional `pyliblzfse` package; without it the image is refused, saying so |
| UDRO, UFBI | stored, not compressed | this file |
| UDSP (`.sparseimage`) | 1 MiB bands, stored in the order they were written | this file |
| UDSB (`.sparsebundle`) | a folder of band files, 8 MiB by default | this file |
| any of the UDIF formats, split by `hdiutil segment` | a `.dmg` and `.dmgpart` files | this file |

A UDIF image is recognised by the 512-byte `koly` trailer at the end of the file, not
by its name. An uncompressed read-write image (UDRW) and a `.cdr` have no trailer:
they are the disk's bytes as they are and read as a raw image, so they need no
reader. Runs of the disk that were never written are not stored and read as zeros.

`verify` also checks what a UDIF image records about itself: the checksum of its
stored data, each block table's checksum, and the master checksum over the
tables' checksums. These were measured on images `hdiutil` wrote: type 2 is CRC32,
type 4 (used by UFBI) is MD5, and a block table's checksum covers only the chunks it
stores. None of them is a hash of the disk as a whole, since runs that were never
written are left out, so `verify` prints the disk's MD5 and SHA-1 with "none stored"
beside them.

A chunk sits at its block table's data offset plus the offset its entry records.
`hdiutil convert` writes a data offset of 0 and full offsets in the entries, while
`hdiutil segment` writes each table's own base there and entry offsets relative to
it, even when the image stays in one file. ewfprobe 0.3.0 read the entry offset
alone. It refused the images `hdiutil segment` wrote, with a decompression error, and
on a constructed image whose chunks all decompress to the same length it returned the
wrong chunks' bytes for 24 of its 32 sectors without an error.

Those positions count from the start of the data fork, which the trailer places.
`hdiutil` writes the fork at the start of the file, where the two are the same.
Measured with a copy moved 512 bytes into its file: `hdiutil attach` read it with
the positions left as they were, and called it corrupt with them shifted by 512, so
ewfprobe adds the fork's offset too (0.5.0 did not, and got both copies wrong). Some
images also count a byte or two past the end of their property list in the XML
length the trailer records ([dmgwiz issue 19](https://github.com/citruz/dmgwiz/issues/19));
`hdiutil attach` read the same image with NUL bytes and with text added there, and so
does ewfprobe, which reads the property list to its `</plist>`.

A segmented image is opened from its `.dmg`. Measured on images `hdiutil segment`
wrote: every segment ends in its own trailer, which records one identifier shared by
the whole set, the number of segments, the segment's own number, and where its data
starts in the data of the whole set. Only the first segment holds the block tables,
and the segments' data laid end to end is byte for byte the data of the same image
kept in one file, so a chunk can run from one segment into the next. ewfprobe finds
the other segments among the `.dmgpart` files in the same folder by that identifier
and number, not by their names, and `verify` checks each segment's own data checksum.

A sparse bundle is a folder, opened as the folder: `Info.plist` gives the band size
and the disk's size in bytes, and `bands/` holds the bands, each named by its number
in lowercase hexadecimal. Measured on bundles `hdiutil` wrote: a band with no file
reads as zeros, a band file shorter than a band reads as zeros past its end (a
bundle that grew keeps its old last band short in the middle of the disk), and a band
size need not be a whole number of MiB. `hdiutil attach` reads only a band's first
band-size bytes and ignores band files numbered past the disk's end; ewfprobe does
the same, and `info` lists any such files and anything else in `bands/`. A sparse
bundle records no checksum, so `verify` prints the disk's hashes with nothing to
compare.

Reads Apple disk images encrypted with a password (`hdiutil -encryption`, AES-128 or
AES-256): a `.dmg` of any format above, a segmented one, a sparse image, a sparse
bundle, and an encrypted read-write image, which decrypts to the disk itself and is
reported as format `UDRW`, the name `hdiutil imageinfo` gives it. This needs the
optional `pycryptodome` package (or `pycryptodomex`); without it the image is refused,
naming the package. From Python, `open_ewf(path, password=...)` takes the password as
a string or as bytes, and raises `EwfPasswordRequiredError` without one and
`EwfWrongPasswordError` when it does not open the image; both are `EwfPasswordError`
and `EwfFormatError`. The password is used while the image is opened and not kept;
the keys it unwraps stay in memory while the image is open, since every read needs
them. `info` names the cipher, how the keys are wrapped and the PBKDF2 rounds.

The container (`encrcdsa`, version 2) is read from the layout two published readers
describe, credited below: a header at the start of the file, key items, and the data
in 512-byte blocks, each decrypted with AES-CBC under an IV made from the block's
number with HMAC-SHA1. Measured on images `hdiutil` wrote on macOS 26.6.2, where those
readers differ or say nothing: the keys are wrapped with AES-192, the stored 8-byte IV
padded with zeros, where both readers expect 3DES, so ewfprobe reads both (the 3DES
wrap only on files the test suite writes); each band of an encrypted sparse bundle is
encrypted on its own from its first byte, its block numbers starting again at zero,
and the bundle's `token` file holds only the header; each file of an encrypted
segmented image is a container of its own; and a password is used as its UTF-8 bytes
with no Unicode normalisation, as `hdiutil attach` refused the NFD spelling of a
password set in NFC. What decrypts is a UDIF image, a sparse image, or the disk. On
the Mac they were measured on, 512 MiB images read at about 100 MiB/s (UDRW) and
140 MiB/s (UDZO).

Reads acquisitions FTK Imager encrypted with AD encryption: E01, SMART and raw (dd)
sets, which are the formats FTK Imager 4.7.3.61 offers it for (for AFF it offers AFF's
own encryption, which is not read). Every file of the set is encrypted, and only the
first carries the header, so a set is opened from its first file, and a raw set from
any of its numbered files. What an E01 or SMART set decrypts to is read as it would
be unencrypted, stored hashes included; a raw set decrypts to the disk itself, in
numbered files, and is reported as format `RAW`. The layout (a 512-byte header, AES
in CTR mode with the file's index shifted left 64 bits as the IV and the counter
little endian) follows the EWF documentation's "AD encryption" section, credited
below. Measured on sets FTK Imager wrote, where that section says nothing: the key
made from the password is PBKDF2-HMAC-SHA1 of the header's hash (SHA-512 on every set
seen) of the password's UTF-8 bytes, over the header's salt and iteration count
(4,000); the header's HMAC of the encrypted file key, under that hash, checks the
password; and the file key is decrypted from the header with AES-CTR from counter 0.
`is_adcrypt()` tells whether a file begins with the header and `adcrypt_set()` lists
the files of the set a path belongs to. An AD1 (FTK's logical image) is recognised
inside and refused, as is an image protected by a certificate rather than a password.

A sparse image longer than about a gigabyte of written bands carries more than one
header. Measured on images `hdiutil` wrote, beyond what the format documentation
covers: the first header holds 1,008 band slots, and once they are used it names a
continuation header written after them, at offset 20; each continuation holds 1,010
slots from offset 56 and names the next one at offset 12. The disk's sector count is
64-bit at offset 28; the 32-bit field at offset 16 holds only its low half, which is
0 on a 2 TiB image.

`open_image()` is the same function as `open_ewf()`. `is_image()` is true for the
disk images ewfprobe reads (EWF, EWF2, AFF, an AFD directory, UDIF, sparse images and
sparse bundle folders), `is_logical_evidence()` for an L01, `is_ewf()` for EWF alone,
and `apple_image_kind()` names an Apple disk image as `UDIF`, `SPARSEIMAGE`,
`SPARSEBUNDLE` or `ENCRYPTED` (any encrypted one, which `is_image()` leaves out
because it opens only with its password). `is_image()` leaves out an AD-encrypted
acquisition for the same reason; `is_adcrypt()` and `adcrypt_set()` answer for it.

Refused with a message naming the reason rather than read wrongly:

- **Encrypted Ex01.** EnCase can encrypt an Ex01, and the encryption is not
  publicly documented.
- **Ex01 compressed with bzip2.** The format allows it, EnCase does not appear to
  offer it, and no sample exists to check a reader against.
- **Lx01**, the logical evidence EnCase 7 writes in the EWF2 format. No sample
  has been available.
- **An L01 whose ltree fails its own MD5, Adler-32 or size**, or lacks the total
  size or the entry list, and **an L01 entry** whose extents are shorter than its
  size, reach past the media data, carry an extent type, or give a duplicate
  offset without the sparse flag. None of those occur in the tested files.
- **Encrypted AFF**, and **AFF pages compressed with bzip2**, which AFFLIB itself
  never implemented.
- **An AFF file with no image size.** AFF records the size when the acquisition
  finishes, so its absence means the file may be incomplete.
- **An AFD with a gap in its file numbering**, or whose files disagree on a page,
  a hash, the page size, the sector size or the bad-sector marker.
- **AFM**, AFF metadata kept beside the image as split raw files (`.000`, `.001`
  and on).
- **An encrypted Apple disk image opened with a certificate or a keybag** rather than
  a password, and **one in the older version 1 format** (`cdsaencr`, with its header at
  the end of the file), which is recognised in order to be refused. No sample of either
  has been available. So is **a header that asks for more than 50 million PBKDF2
  rounds**; the images measured used 344,827 to 588,235.
- **An older `.dmg` whose block tables are only in a resource fork**, **a sparse image
  of a version other than 3**, and **a sparse bundle of a backing-store version other
  than 1**.
- **A `.dmg` whose block tables leave a gap or overlap, name a chunk type other
  than the ones above, or point outside the stored data**, and **a `.dmg` or sparse
  image cut short**.
- **A segmented `.dmg` with a segment missing**, two files claiming the same segment,
  or segments that disagree about the set, and **a `.dmgpart` opened on its own**,
  which names the `.dmg` to open instead. **A sparse bundle without its `bands`
  folder**, which would otherwise read as an empty disk.

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

L01 was checked against five L01s EnCase wrote of an iPhone for Digital Corpora's
2012 National Gallery DC scenario (`corpora/scenarios/2012-ngdc/extra/tracy-phone-encase/`),
four from EnCase 7.2.4.2 and one from 7.4.1.10, holding 9,951 to 14,803 entries
each. libewf 20260924's `ewfexport` was the oracle. On all five the media data is
identical to `ewfexport -f raw`, and every one of the 55,599 files `ewfexport -f
files` writes is byte-identical to ewfprobe's read of the same entry (`ewfexport`
writes `$` in a name as `\x24`, which the comparison maps). Every entry with data
and no children appears in that export, and all 646 MD5s EnCase stored for entries
match. A check that does not depend on libewf: the logical zip taken of the same
phone a minute after the last L01 holds 30 photos, and all 30 are byte-identical to
entries ewfprobe reads from that L01. The smallest of the five,
`tracy-phone-2012-07-05-1640.L01` (EnCase 7.2.4.2, 9,951 entries), is committed
under `tests/fixtures` with known answers taken from `ewfexport`: its media data,
and one digest over the 9,219 files `ewfexport -f files` writes. Digital Corpora
publishes its scenario data under CC0, excluding any material inside an image that
claims its own copyright. No L01 from another writer has been available; a writer
in the suite built from the specification and from the layout of these files
covers the behaviours that file does not exercise.

**Apple disk images, against Apple's own tools.** `hdiutil` wrote every format in
the table above from the 3 MiB source the other fixtures use, and those images are
committed under `tests/fixtures`: each reproduces the source byte for byte and
verifies every checksum it records. ADC was written from its documentation, and the
UDCO image's own checksums confirm the decode. A 2.5 GB sparse image `hdiutil` wrote
with 2,433 bands across three headers, too large to commit, reads byte-identical to
the same image attached with `hdiutil attach -readonly -nomount` and read from its
raw device. A private sample written by Fuji 1.2.0 (UDZO) verified every checksum it
records, 512 sampled windows across the disk matched its raw device the same way, and
a walk of its APFS container through qnxprobe listed the same paths and file sizes as
macOS's own read-only mount of the image.

**Encrypted Apple disk images, against `hdiutil attach`.** Eighteen encrypted images
`hdiutil` wrote on macOS 26.6.2, AES-128 and AES-256, some made by `hdiutil create` and
some by `hdiutil convert`, as UDZO (two of them segmented into two files each), ULFO,
UDRW, sparse images and sparse bundles, read byte for byte the same as the same image
attached with its password (`hdiutil attach -readonly -nomount -stdinpass`) and read
from its raw device, and so did 512 MiB UDRW and UDZO images of random and zero
stretches, whose decrypted disk also matched the file they were made from. The seven
committed encrypted fixtures are each kept by `tools/make_fixtures.py` only after
`hdiutil attach` gives back the disk they were made from. One uses a password outside
ASCII. In the sparse bundle, after `hdiutil` wrote it, its all-zero first band file was
removed and its second cut after its data, which `hdiutil` reads as zeros as it does
for the bands it never writes; `hdiutil attach` read the same disk. The 3DES key wrap,
an image opened with a certificate or a keybag, the version 1 container and damaged
files are tested on files the test suite writes from the published layout, with the
cipher library's own CBC mode rather than ewfprobe's.

**AD encryption, against FTK Imager.** FTK Imager 4.7.3.61 wrote an E01 (no
compression), a SMART and a raw set, each AD-encrypted with a test password in 1 MB
fragments, from a 1,257,984-byte disk of SHA-256 output that
`tools/make_fixtures.py` regenerates. All three decrypt to that disk, the E01 and
SMART sets match the MD5 and SHA-1 stored in them, and both files of every set read.
The E01 and raw sets are committed (the SMART set reads through the same code as the
E01). An E01 FTK Imager 4.7.3.81 wrote, from the test images of
[fox-it/dissect.evidence](https://github.com/fox-it/dissect.evidence) at `b2d1ac2`,
read as data, matched the hashes stored in it, and the 13 files of an encrypted AD1
from the same place each decrypted to the AD1 segment signature under its own
counter; those files are AGPL and are not committed. Other ciphers and hashes, a
later numbered file, damaged headers, an AD1 inside, and the wrapped EWF, SMART and
Ex01 fixtures are tested on sets the test suite writes, with the cipher library's CTR
mode rather than ewfprobe's.

**Segmented images and sparse bundles, against `hdiutil attach`.** 36 images `hdiutil`
wrote from HFS+ and APFS test disks read byte for byte the same as the same image
attached read-only and read from its raw device: each of UDZO, UDBZ, ULMO, ULFO, UDCO
and UDRO split by `hdiutil segment` at 700k and 3m (9 to 58 files) and left in one file
with the base offsets `segment` writes, the plain conversions, and nine sparse bundles,
among them bands of 1,536,000 bytes, a bundle grown after it was written, an APFS one
shrunk, and one given both a band file longer than a band and a band file numbered past
the disk's end. Every checksum the `.dmg` images record verified. The
committed fixtures cover a segmented UDZO image and a sparse bundle of the shared
source, and segmented images of a small GPT disk whose block tables carry base
offsets. The private sample above, converted by `hdiutil` into a sparse bundle and
split by `hdiutil segment` into 2 GB parts, read to the same SHA-256 across the whole
disk in both forms as the original `.dmg` does.

## Standalone executables

Each release carries `ewfprobe` built as a single executable with PyInstaller on
Python 3.14, for Windows x64 and arm64, macOS on Apple silicon and Intel, and Linux x64
and arm64, beside `ewfprobe.py` itself. The workflow that builds them
(`.github/workflows/build-executables.yml`) runs each executable on the reference images
in `tests/fixtures`. It requires `info`, `verify` and `export` to write the same bytes as
`python ewfprobe.py`, the export to match the source disk's SHA-256, and a set missing a
segment to be refused, before it is packaged with `SHA256SUMS.txt` and a README. On the
L01 it also requires `files` and `export --entry` to match, and the exports to match the
known answers taken from libewf. The executables do not include `pyliblzfse`, so they
refuse an LZFSE-compressed `.dmg`, naming the package, and the workflow checks that. They
do include `pycryptodome`, and on every encrypted fixture the workflow requires the
executable's output to match the source's, the export to match the disk `hdiutil`
read back, and a wrong password to be refused the same way. The
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

The Apple disk image variants (`dmg-*`) are written by `hdiutil`, so on macOS only.
`--add dmg-gpt` rebuilds the segmented images of a small GPT disk, which carry the
block-table base offsets the unpartitioned source cannot.
`--add dmg-encrypted` rebuilds the encrypted images, attaching each with `hdiutil`
before keeping it. The LZFSE one is skipped where `pyliblzfse` is not installed; set
`EWFPROBE_REQUIRE_LZFSE=1` to make that a failure instead, as the CI jobs that
install it do. The encrypted ones are skipped where neither `pycryptodome` nor
`pycryptodomex` is installed; `EWFPROBE_REQUIRE_CRYPTO=1` makes that a failure. CI runs
most jobs with `pycryptodome`, one with `pycryptodomex`, and one with neither, where
the refusal that names the package is what runs.

That tool shells out to `ewfacquire`, `affconvert` and `hdiutil` and is for development only.
libewf and AFFLIB are used there solely to produce test data. Nothing from them
ships and `ewfprobe` imports nothing.

## Format reference

Joachim Metz, *Expert Witness Compression Format (EWF)* and *Expert Witness
Compression Format 2 (EWF2)*, in the
[libyal/libewf](https://github.com/libyal/libewf) repository under
`documentation/`. The format is publicly documented, which is what makes an
independent implementation possible. L01 support follows the EWF-L01 parts of the
first document (the ltree section and its categories, the file entry flags and the
binary extents), read at commit
[`d76fd0b`](https://github.com/libyal/libewf/blob/d76fd0bb21601e2969bc88ffdaeb861023f6a5b2/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc).

For AFF: AFFLIB's own documentation (`doc/affdoc.doc`) and the segment names and
flag values in its public header, `include/afflib/afflib.h`, in the
[sshock/AFFLIBv3](https://github.com/sshock/AFFLIBv3) repository, and for AFD how
AFFLIB finds, names and joins the files of one, in `lib/vnode_afd.cpp` at commit
[`f35df6c`](https://github.com/sshock/AFFLIBv3/blob/f35df6c1d2610e3233c30d50054c00e29d7d5a23/lib/vnode_afd.cpp).
No AFFLIB code is copied.

For Apple disk images: Joachim Metz, *Mac OS disk image types*, in the
[libyal/libmodi](https://github.com/libyal/libmodi) repository under `documentation/`,
and the block-table rules libmodi's own code applies (contiguous tables and entries,
compressed chunks of at most 2048 sectors, unknown chunk types refused), in
`libmodi/libmodi_handle.c`, both at commit
[`8fc5088`](https://github.com/libyal/libmodi/blob/8fc5088e51cd606d9f2b8ce000bfdf5a78042f84/libmodi/libmodi_handle.c).
libmodi reads a block table's data offset only to print it. The chunk position, that
offset plus the entry's, follows libdmg-hfsplus, which seeks to `dataStart + compOffset`
([`dmg/io.c`, line 166 at `7ac55ec`](https://github.com/planetbeing/libdmg-hfsplus/blob/7ac55ec64c96f7800d9818ce64c79670e7f02b67/dmg/io.c#L166)),
and 7-Zip, which reads the same offset as `StartPackPos`
([`DmgHandler.cpp`, line 658 at `0766b73`](https://github.com/ip7z/7zip/blob/0766b733fe3e06dd2a7f9a3cfbf2108ac73abd17/CPP/7zip/Archive/DmgHandler.cpp#L658))
and adds it at
[line 1909](https://github.com/ip7z/7zip/blob/0766b733fe3e06dd2a7f9a3cfbf2108ac73abd17/CPP/7zip/Archive/DmgHandler.cpp#L1909).
7-Zip also adds the trailer's data fork offset, and `hdiutil attach` does too, measured
on an image moved into its file as described above. No code from either is copied.
ADC follows Joachim Metz, *ADC compressed data format*, in
[libyal/libfmos](https://github.com/libyal/libfmos) at commit
[`3396edf`](https://github.com/libyal/libfmos/blob/3396edfc19d172795971c00a2e848d8146cf7523/documentation/ADC%20compressed%20data%20format.asciidoc).
The sparse bundle layout follows the same libmodi documentation. The checksum rules,
the sparse image's continuation headers and 64-bit sector count, the layout of a
segmented image, and how `hdiutil attach` treats short, long and extra band files were
measured on images `hdiutil` wrote, as described above. No libmodi code is copied.

For encrypted Apple disk images: the `encrcdsa` layout and its key unwrapping in
nlitsme/encrypteddmg, `readencrcdsa.py` (`PassphraseWrappedKey` and `EncrCdsaFile`,
[lines 125 to 198](https://github.com/nlitsme/encrypteddmg/blob/626dac30710140ac488ea199cd14b5c450f2760b/readencrcdsa.py#L125-L198)
and [283 to 417](https://github.com/nlitsme/encrypteddmg/blob/626dac30710140ac488ea199cd14b5c450f2760b/readencrcdsa.py#L283-L417)
at `626dac3`, where
[lines 465 to 472](https://github.com/nlitsme/encrypteddmg/blob/626dac30710140ac488ea199cd14b5c450f2760b/readencrcdsa.py#L465-L472)
also give the version 1 signature), and kev365/xways-imageio-dmg, `encrypted_source.cpp`
([lines 30 to 98](https://github.com/kev365/xways-imageio-dmg/blob/406e738d1a43dfcb9d8f421d33a31d43078fb4b5/encrypted_source.cpp#L30-L98)
at `406e738`), both MIT. No code from either is copied. What current macOS writes
differently was measured, as described above.

For FTK Imager's AD encryption: the "AD encryption" section of the EWF documentation
above ([lines 3376 to 3465 at `d76fd0b`](https://github.com/libyal/libewf/blob/d76fd0bb21601e2969bc88ffdaeb861023f6a5b2/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc?plain=1#L3376-L3465)),
which it takes from AccessData's white paper. What that section leaves open was
measured on sets FTK Imager wrote, as described above.

## License

MIT. See `LICENSE`.

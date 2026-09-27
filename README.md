# ewfprobe

A read-only reader for EnCase/EWF (`.E01`, `.Ex01`), SMART (`.s01`), AFF (`.aff`, `.afd`) and AFF4 (`.aff4`) forensic images, Apple disk images (`.dmg`, including one split into `.dmgpart` files, `.sparseimage`, `.sparsebundle`), virtual machine disks (`.vhd`, `.vhdx`, `.vmdk`, `.qcow2`), and logical evidence, EnCase's (`.L01`) and FTK Imager's (`.ad1`). One file, pure
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
ewfprobe verify  image.aff4       # and the hashes an AFF4 records about its streams
ewfprobe files   evidence.L01     # an L01's entries: kind, size, stored MD5, path
ewfprobe export  evidence.L01 --entry "Folder/photo.jpg" -o photo.jpg
ewfprobe files   evidence.ad1     # an AD1's entries, with their item types
ewfprobe verify  evidence.ad1     # FTK Imager's image hash, and every entry's
ewfprobe info    --password-file pw.txt encrypted.dmg
ewfprobe verify  --password-env CASE_PW evidence.E01   # FTK Imager AD encryption
ewfprobe verify  --private-key examiner.pem sealed.aff  # AFF sealed to a certificate
```

`verify` exits non-zero when the recomputed hash does not match the one the
acquisition recorded.

An encrypted image (an Apple disk image, an acquisition FTK Imager wrote with AD
encryption, or an encrypted AFF) needs its password. `--password-file FILE` reads it
from the first line of a file and `--password-env NAME` from an environment
variable; without either, ewfprobe asks for it at a terminal. It is never taken as
an argument's value, which would put it in the process list and the shell history.
An AFF sealed to a certificate opens instead with that certificate's RSA private key,
given unencrypted, as PEM or DER, with `--private-key FILE`.

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

Reads encrypted AFF, as AFFLIB encrypts it (`lib/crypto.cpp`): every segment stored
AES-256-CBC but a few (on the files AFFLIB 3.7.22 wrote, the bad-sector marker and
count, the AFFLIB version, the creator, the file type and the key segments), opened
with the passphrase (which AFFLIB
hashes with SHA-256 to unwrap the file's key) or with the private key of a
certificate the image is sealed to (an RSA envelope). Both need the optional
pycryptodome package, which the release executables carry. `info` says which one
opened it. AFFLIB 3.7.22's `affcrypto -e`, which encrypts an existing AFF in place,
wrote its first re-encrypted segment over the file's header, with Homebrew's build on
macOS and with Ubuntu 26.04's package alike; AFFLIB could not open those files
afterwards, and every segment in them was intact.
ewfprobe reads such a file from its segments and `info` says the header was lost.

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

Reads AFF4, the Advanced Forensic Format 4, as the AFF4 Standard v1.0 defines it and
as the pre-standard images Evimetry 2.0 and 2.1 wrote (`.aff4`, `.af4`): a ZIP file
whose `information.turtle` describes the image, the map that places its bytes, and the
image streams that hold them in segments ("bevies") of chunks. A chunk is stored when
its length is the chunk size and compressed otherwise, with Snappy, LZ4 or deflate,
and the decoders for all three are in this file, so no package is needed. On an Apple
M2 Max they decode about 110 MB/s (Snappy), 160 MB/s (LZ4) and 1.9 GB/s (deflate) on a
mix of text, mostly empty and random 32 KiB chunks, and `verify` read and hashed an
uncompressed AFF4 at about 470 MB/s. What no range of the map covers reads from the map's gap stream,
zeros unless the map names another; `aff4:UnknownData` and `aff4:UnreadableData` read
as the repeated strings the standard defines. `info` lists how many bytes of the image
come from each stream, so a range the acquisition could not read shows there.

A striped image, one image kept across several files, opens from any of them. A
stream that is not in the file opened is looked for in the other `.aff4` and `.af4`
files in the same folder, and one that is in none of them is refused as a missing
file. A file in that folder joins the image only when it holds a segment the image
needs, so an unrelated container beside it is never read as part of it.

`verify` checks what an AFF4 records about itself: each image stream's linear hashes,
each chunk's block hash and the hash of each stream's block hashes, each map's
segment hashes, the block map hash of each map with its stream, and the image's hash
over those, one level up for a striped image. The orderings are the ones pyaff4's
validator uses, and the reference images agree with them. An AFF4 that records no hash
of the whole disk is not hashed end to end. BlackBag's Digital Collector, for one,
records the MD5 and SHA-1 of the image stream, the extents it captured, rather than
of the disk, and that is what `verify` compares.

Two writer differences, measured: c-aff4 writes an LZ4 chunk as a raw block, while
pyaff4 writes python-lz4's default, the block after a four-byte length, which pyaff4
then cannot read back itself; both are read. And c-aff4 writes a zlib stream, header
included, under both its zlib and its deflate settings, with spare bytes after a
deflate one; a chunk is read as zlib when it starts with a zlib header and as raw
deflate otherwise, and bytes after the end of the stream are ignored. `info` also
shows the image's properties outside the AFF4 vocabulary, such as BlackBag's
`bbt:APFSContainerType`.

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

Reads AD1, FTK Imager's logical image, in files named `.ad1`, `.ad2` and on, from any
of them, and an AD-encrypted set with its password. Entries come through the same
interface as an L01's: `logical_entries` in the order the items lie in the image (each
folder's children before its next sibling), `find_entry()`, `open_entry()`,
`read_entry()`, and `ewfprobe files` and `export --entry`. The image's stream is its
logical space, every file's data with its 512-byte margin left out, back to back,
which is what the image's addresses point into.

```python
with ewfprobe.open_ewf("evidence.ad1") as img:
    for entry in img.logical_entries:
        print(entry.path, entry.size, entry.md5, entry.times.get("modified"))
```

Each entry carries its names, its size, its item type (`item_type`), and from its
metadata records its stored MD5 and SHA-1, `type_code` (the text of record 2/0x2),
`is_folder`, `is_deleted` and `times`. `metadata` reads every record as stored, keyed
by category and key; an entry imaged from NTFS carries dozens (owner, security
descriptor, NTFS times and flags), so they are read from the image when asked for
rather than kept. In an image of several sources the top entries are named
for their sources, such as `U:\:AD1LEAN [NTFS]`. Paths can repeat.

Measured on images FTK Imager 4.7.3.61 wrote from folders of known content in a
Windows VM set to UTC-4, and checked against FTK Imager's own directory listing of
each image (the `.csv` it writes beside it):

- **The three time records hold UTC, to the microsecond.** Record 5/0x08 is the time
  created and 5/0x09 the time last modified, as Windows reported them for every file
  before imaging and as FTK's listing names them on all 55 rows of four images; 5/0x07
  is the time accessed. pyad1's notes call 0x08 the modification time and 0x09 the
  creation time, and AD1-tools calls them modified and change.
  `times` holds them as POSIX seconds under "created", "modified" and "accessed".
  Imaging a folder through Windows set the files' access times, so "accessed" is the
  time FTK read the file, not what the file carried before.
- **Item type 5 is a folder and 2 an entry FTK's listing marks deleted.** Imaged from an
  NTFS volume, a file deleted before imaging came back as an item of type 2 holding the
  file's 37 bytes, and on one of the two images also as a second, empty item of type 2
  whose `type_code` is `61`, listed as deleted with no size; a file with an alternate
  data stream as type 1, with the stream as a child item whose `type_code` is `D`; and
  folders with data of their own (160 bytes for one) beside their children. Imaged from
  a folder, every file was type 0 and folders held no data. A public AD1 of an NTFS
  volume (below) also carries `type_code` `6` on 27,206 items, each named after a file
  beside it with `.FileSlack` appended, and `F` on 5,732 items, each named `$I30`. Only
  types 5 and 2 are given a meaning here; the rest are reported as stored.
- **Records 4/0x1002, 4/0x1004 and 4/0x1005** were `true` on exactly the hidden, the
  read-only and the archive files, as AD1-tools names them.
- **The footer is two blocks**, `ATTRGUID` at the footer address the logical header
  gives and `LOCSGUID` at its second footer address, each an 8-byte tag, a zero and a
  count of 20-byte entries (a 4-byte number and a 16-byte GUID). Its length follows
  from the counts (372 bytes on one committed image, 1,492 on another, 2,012 on the
  public image below), and on all eight AD1s at hand (six from FTK Imager 4.7.3.61,
  pyad1's from 3.4.3.3, and the public image) the second block ends where the data
  ends. A last file whose footer runs past its end is refused as cut short, and one
  with bytes after its footer is refused too.
- **The recorded segment size is a whole number of MiB**, and every file but the last
  is exactly that long, its 512-byte margin included: 1,048,576 bytes on the set
  written in 1 MB fragments, 1,572,864,000 (1,500 MiB) on an image written as one file
  of 35,556 bytes, and 10,485,758,951,424 (9,999,999 MiB) on the public image (below),
  also one file. So a file shorter than that is refused as cut short unless it is the
  last of its set, whose end the footer gives instead.
- **Compression 0 still writes zlib streams**, of stored blocks.

`verify` computes FTK Imager's own image hash, the MD5 and SHA-1 its log records, and
checks every entry's stored MD5 and SHA-1 against its content. That hash is taken over
the logical header up to the first item, then the footer, then each item's header and
metadata records in the order they lie in the image, and last the digest of all the
items' content; chunk tables and compressed data are not in it. The order is pyad1's
reader, followed here through the image's own addresses. The image does not record the
hash itself, so it is compared with FTK Imager's log beside the image,
`<first file>.txt`, when that is there, and `info` names the log. An AD1 set encrypted
with AD encryption decrypts as the E01 and raw sets above do, only its first file
carrying the header, and FTK's log hash matches what it decrypts to.

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
the files of the set a path belongs to. An AD1 inside reads as described below, and
an image protected by a certificate rather than a password is refused.

A sparse image longer than about a gigabyte of written bands carries more than one
header. Measured on images `hdiutil` wrote, beyond what the format documentation
covers: the first header holds 1,008 band slots, and once they are used it names a
continuation header written after them, at offset 20; each continuation holds 1,010
slots from offset 56 and names the next one at offset 12. The disk's sector count is
64-bit at offset 28; the 32-bit field at offset 16 holds only its low half, which is
0 on a 2 TiB image.

Reads the disks virtual machines keep: VHD and VHDX (Microsoft's, which Windows,
Hyper-V and Virtual PC write), VMDK (VMware's) and QCOW (QEMU's). Each is opened from its
own file, a VMDK from its descriptor or from any of its sparse extents, and a disk that is a
difference over another (a differencing VHD or VHDX, a VMDK delta link, a QCOW overlay)
is read through its parent, which has to be in the same folder or where it names.

| Format | What is read | Parent found by, and checked against |
| --- | --- | --- |
| VHD | fixed, dynamic and differencing disks | its W2ru, W2ku or MacX locator or its recorded name; the parent's disk id |
| VHDX | fixed, dynamic and differencing disks, the log replayed in memory | its relative path, then its volume and absolute paths; the parent's DataWriteGuid |
| VMDK | descriptor files and extents: FLAT, VMFS, ZERO, SPARSE (including stream-optimized) and ESXi's VMFSSPARSE | parentFileNameHint; the parent's content id |
| QCOW | versions 1, 2 and 3: deflate or zstd compressed clusters, extended L2 entries, an external data file | the backing file's name; QCOW records no identity for it |

What each disk is made of is read from the formats' own documents, credited below, and
these were measured on disks the programs themselves wrote:

- **A VHD's size is the footer's Current Size, not its geometry.** Windows 11 recorded
  128 MiB disks with a geometry of 963 x 16 x 17 sectors, which is 134,111,232 bytes, a
  little short of the disk. qemu-img instead rounds the disk up to a whole geometry
  (16,781,312 bytes for 16 MiB), so its VHDs are read with zeros past the data they were
  made from.
- **A differencing VHD's sector bitmap is read most significant bit first, a VHDX's least
  significant bit first.** The VHD specification does not say; MS-VHDX does. On the
  children Windows 11 wrote, each order reproduces the disk Windows presented, and the
  other order does not.
- **Windows 11 writes a differencing VHD's parent locators as UTF-16 little-endian text**
  (the parent's name field is big-endian, like the rest of the format), and 0 in the
  parent's time stamp field, which is shown as not recorded. It writes a VHDX's
  parent_linkage2 as an all-zero GUID, which is taken to name no parent.
- **A VHDX whose log holds entries is read as it would be after replay**, with the
  replayed updates kept in memory; the file is not changed. A qemu-io killed after its
  writes had returned left the log empty, so the replay is tested on a file built to
  need one.
- **VMware's own tools and qemu-img both store stream-optimized grains as zlib streams**,
  although VMware's note names raw deflate; both are read. VMware's tools put the grain
  directory in a footer and name the extent `generated-stream.vmdk` in the embedded
  descriptor whatever the file is called, so a descriptor embedded in a sparse extent
  that lists one extent is read as describing that file. qemu-img keeps the directory in
  the header, and leaves the descriptor area of a twoGbMaxExtentSparse extent empty, so
  an extent opened on its own is read through the descriptor file beside it.
- **QCOW keeps no identity for its backing file**, so the file of that name is used and
  `info` says only the name ties them. Internal snapshots are listed with their names
  and times; the disk read is the active one.

A differencing disk is only as right as its parent, so a parent that is not the one
recorded is refused rather than read: a VHD whose disk id, a VHDX whose DataWriteGuid,
or a VMDK whose content id is not the one the child names. A zstd-compressed QCOW needs
Python 3.14's `compression.zstd`, or the optional `backports.zstd` or `zstandard` package;
without one it is refused, naming them.

`open_image()` is the same function as `open_ewf()`. `is_image()` is true for the
disk images ewfprobe reads (EWF, EWF2, AFF, an AFD directory, AFF4, UDIF, sparse images,
sparse bundle folders and the virtual disks above, which `virtual_disk_kind()` names as
`VHD`, `VHDX`, `VMDK` or `QCOW` from their bytes), `is_logical_evidence()` for an L01 or an AD1 (`is_ad1()` for
AD1 alone, `ad1_segments()` for the files of its set), `is_ewf()` for EWF alone,
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
- **AD1 other than version 4**, the version FTK Imager 3.4.3.3 and 4.7.3.61 write.
  pyad1's notes describe a version 3 with a different header; no sample has been
  available. Also **an AD1 set with a file missing, cut short or out of place**, whose
  files disagree about the set, whose margin is not 512 bytes, whose footer does not
  end where its data ends, whose item tree loops or places an item under a parent
  other than the one it names, or whose entry's chunk table does not fit its size. An
  entry whose chunk does not inflate fails when read, and `verify` reports it as a
  mismatch.
- **A VHD of a version other than 1.0**, a VHDX of a version other than 1, **a VHD split
  into `.v01` files** by Virtual PC 2004 or earlier (no sample has been available), a
  VHD or VHDX cut short, a VHDX with no header or region table whose checksum matches,
  a region or metadata item it marks required and this reader does not know, a log
  holding entries that form no complete sequence, and a block in a reserved state.
- **A VMDK extent of type SESPARSE**, which VMware has not documented, one marked
  NOACCESS, and **a VMDK backed by a physical device** (fullDevice, partitionedDevice
  and the raw device maps), which holds nothing to read.
- **An encrypted QCOW** (AES or LUKS) and a QCOW setting an incompatible feature this
  reader does not know.
- **A difference disk whose parent is missing, or is not the parent it records.**
- **AFF pages compressed with bzip2**, which AFFLIB itself never implemented, and
  **an encrypted AFF** without its passphrase or key, or with an RSA private key that
  is itself encrypted (give it unencrypted).
- **An AFF file with no image size.** AFF records the size when the acquisition
  finishes, so its absence means the file may be incomplete.
- **An AFD with a gap in its file numbering**, or whose files disagree on a page,
  a hash, the page size, the sector size or the bad-sector marker.
- **AFM**, AFF metadata kept beside the image as split raw files (`.000`, `.001`
  and on).
- **Encrypted AFF4** (`aff4:EncryptedStream`), **AFF4-L**, the logical form that holds
  files rather than a disk, **an AFF4 kept as a folder** rather than a ZIP, and **an
  AFF4 map whose ranges overlap**, which none of the eleven maps measured has. AFF4 written by
  pyaff4 or Rekall before the standard has not been available to test; its Snappy
  name, which marks every chunk compressed, is read as pyaff4 reads it.
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
  reader is working; there is simply nothing plain in there to find. What was
  acquired decrypted reads decrypted: on the Digital Collector AFF4 of an Apple
  silicon Mac described below, the tool read the FileVault Data volume through the
  Mac's own encryption, and 198 of 200 property lists on that volume parse, although
  the volume's own flags still say it is encrypted.

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
cases the fixtures cannot: a missing page, encrypted segments with no key, a
truncated file, the older `seg` page names, and an image size above 4 GiB.

Encrypted AFF is covered by six fixtures AFFLIB 3.7.22 wrote from the same source:
written encrypted by `affconvert` with a passphrase (deflate, LZMA, and an AFD over
five files), one sealed to a test certificate as well (`affcrypto -A`), and two
encrypted in place by `affcrypto -e`, one with a passphrase and one with a
certificate only. Every one reproduces the source with each key that opens it and
matches the MD5 and SHA-1 it recorded, which are encrypted segments themselves.
AFFLIB's `affconvert -r` read the first four back to the source before they were
kept and refused the two encrypted in place; the same `affcrypto -e` from Ubuntu
26.04's AFFLIB 3.7.22 package left a file of the same shape. A wrong passphrase, a
key that opens none of the sealed keys, a sealed key whose inner layer is damaged, a
key segment padded to 56 bytes and a clear copy of an encrypted segment are tested
by editing those files. Sixteen deliberate breaks of the encrypted AFF code are
each caught by the tests.

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

AD1 was checked against images FTK Imager wrote, with FTK Imager as the oracle. Three
were made with FTK Imager 4.7.3.61 from a folder of known content, recorded file by file
(size, MD5, SHA-1, times) before imaging: compression 0 in four 1 MB files, compression
6 with AD encryption, and two sources in one image, the folder on an NTFS volume with an
alternate data stream and a deleted file, and a second folder. On each, every file's
content, stored MD5 and SHA-1, and created and modified times match what Windows
recorded before imaging, the stream and the deleted file hold the bytes written to them,
every row of FTK's own listing matches its entry's times and deleted flag, and the image
hash matches the MD5 and SHA-1 in FTK's log; they are committed under
`tests/fixtures/ad1` with their logs and listings. Three larger ones made the same way
(the same kinds, with a 3 MiB file of incompressible bytes) also match their logs; they
are not committed. The four files FTK Imager 3.4.3.3 wrote for pyad1's tests
(Apache-2.0, fetched by CI from
[pcbje/pyad1](https://github.com/pcbje/pyad1/tree/74b21889410fb40b96e3f1f1f6ab369019d6984d/test_data)
at `74b2188`) match their log too, with all 8 files' stored hashes. A public AD1 of an
NTFS volume, `userbss.ad1` from Hexordia's 2025 Magnet Virtual Summit CTF dataset
([listed on NIST CFReDS](https://cfreds.nist.gov/all/Hexordia/2025MVSCTF);
51,678,663,221 bytes, SHA-256
`743e1e89e1d4fa9d6f75d91e820f6dd02d2d906e1bab70eb4731a2fdb4458e7c`), opens in about 23
seconds on an Apple M2 Max, using under 400 MB of memory, and lists 316,682 entries.
`verify` read all 132.4 GB of their content in 12 minutes, and the stored MD5 and SHA-1
of every one of the 299,729 entries that carry them match. Both counts are the ones
[ad1-forensic reports for the same
image](https://github.com/SecurityRonin/ad1-forensic/blob/afc3963659a13acf10082e7d76194d3ab789583e/docs/validation.md#L48-L53).
Its log is not published, so its image hash is computed with nothing to compare it with.
Twenty-one deliberate breaks of the AD1 code are each caught by the tests.

**Virtual disks, against the programs that write them.** Windows 11 (10.0.26200) made
fixed, expandable and differencing VHD and VHDX disks with diskpart, and each was read
through `\\.\PhysicalDriveN` after a read-only attach; every one reads byte for byte as
the disk Windows presented, and reading either child's sector bitmap in the other bit
order does not. qemu-img 10.2.1 wrote every VHD, VHDX, VMDK and QCOW form it offers from
a known 16 MiB disk, and each reads as that disk, or for its delta, overlay, snapshot and
zeroed samples (a VMDK with zeroed-grain entries, a QCOW2 with zero-flagged clusters) as
the disk plain file writes made. Three files were built from the formats' own documents
where no writer was at hand: a VHDX whose log holds an update not yet applied, which
qemu refuses to open read-only and whose replay by qemu reads as ewfprobe's does, an
ESXi sparse extent, and a QCOW version 1 image with compressed clusters, which qemu-img
10.2.1 refused to write; qemu reads the last two as ewfprobe does. The compact versions of
all of these are committed under `tests/fixtures/virtual` with a manifest of the answers.
A stream-optimized VMDK written by VMware's own tools, the one in VMware's Photon OS 2.0
OVA (SHA-1 `b8c183785bbf582bcd1be7cde7c22e5758fb3f16`, as its project publishes), reads
as the same 16 GiB disk qemu-img reads from it, SHA-256
`9d2c2ad3a3ee5922a7749da1dde4c830b3d577848f1074640792285737c70668`; CI fetches it. No ESXi
sparse extent, VMDK written by VMware Workstation or Fusion, or VHD from Virtual PC has
been available. Thirty-six deliberate breaks of the virtual disk code are each caught by
the tests.

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

**AFF4, against the reference images and two other writers.** The ten AFF4 reference
images ([aff4/ReferenceImages](https://github.com/aff4/ReferenceImages) at `84773b0`:
Evimetry 2.x and 3.x, standard and pre-standard, allocated blocks only, with a read
error, with all five block hash algorithms, striped across two files, and a sparse image
of 9 exabytes) are not committed, because that repository states no licence; the tests
read them from a folder named by `EWFPROBE_AFF4_REFERENCE`, and CI fetches them at that
commit. Eight read to the SHA-1 pyaff4's own tests record for them, the pre-standard
ones and both files of the striped pair included (pyaff4 0.34 read a different image
from each striped file alone, and its container API did not open the pre-standard
ones); the other two have no recorded image hash. Every hash all ten record
about themselves verifies. Four containers pyaff4 wrote over known content (stored,
Snappy, zlib, LZ4), and nine files `tools/make_aff4_fixtures.py` writes with chunks
compressed by the lz4, python-snappy and zlib libraries, cover c-aff4's LZ4 and deflate
forms, the always-compressed Snappy name, a gap stream other than zeros (a constructed
case: no sample has one), a striped pair and what is refused; all are committed. One
real acquisition stays outside the repository: a 926.4 GiB APFS container Digital
Collector 3.7 wrote as an uncompressed AFF4 (libaff4 2.0.0), whose 80,170 map ranges are
not in order and whose 38.4 GB image stream matches the MD5 and SHA-1 in the
acquisition log. Nineteen deliberate breaks of the AFF4 code are each caught by the
tests.

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

The AFF4 fixtures come from their own tool, which needs the lz4 and python-snappy
packages, and pyaff4 as well for the `pyaff4-*` set (the docstring says how it was
installed). The AFF4 reference images are read from a checkout of
[aff4/ReferenceImages](https://github.com/aff4/ReferenceImages); with
`EWFPROBE_REQUIRE_AFF4_REFERENCE=1` a missing one fails rather than skips:

```
python tools/make_aff4_fixtures.py tests/fixtures --pyaff4
EWFPROBE_AFF4_REFERENCE=/path/to/ReferenceImages python -m pytest tests/test_aff4.py -q
```

The AD1 fixtures in `tests/fixtures/ad1` were written by FTK Imager, as described under
validation, and are not regenerated. pyad1's test data is read from a folder holding it;
with `EWFPROBE_REQUIRE_AD1_REFERENCE=1` a missing one fails rather than skips:

```
EWFPROBE_AD1_REFERENCE=/path/to/pyad1/test_data python -m pytest tests/test_ad1.py -q
```

The virtual disks in `tests/fixtures/virtual` were written by Windows 11 and qemu-img,
or built from the formats' documents, as described under validation, and are not
regenerated; the scripts that made them sit with the full-size copies. VMware's Photon OS
2.0 OVA is read from where it is saved; with `EWFPROBE_REQUIRE_VMDK_REFERENCE=1` a
missing one fails rather than skips:

```
EWFPROBE_VMDK_REFERENCE=/path/to/photon-custom-hw11-2.0-304b817.ova python -m pytest tests/test_virtual_disks.py -q
```

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
For encrypted AFF, at tag v3.7.22
([`f6e51a8`](https://github.com/sshock/AFFLIBv3/tree/f6e51a8367cff73ea24c0adf09e533483c80ecd4)):
the key segments and their unwrapping in
[`lib/crypto.cpp`](https://github.com/sshock/AFFLIBv3/blob/f6e51a8367cff73ea24c0adf09e533483c80ecd4/lib/crypto.cpp#L154-L279)
(the passphrase) and
[lines 793 to 981](https://github.com/sshock/AFFLIBv3/blob/f6e51a8367cff73ea24c0adf09e533483c80ecd4/lib/crypto.cpp#L793-L981)
(a certificate), and the segment cipher in `af_aes_decrypt` and `af_update_segf`,
[`lib/afflib.cpp`](https://github.com/sshock/AFFLIBv3/blob/f6e51a8367cff73ea24c0adf09e533483c80ecd4/lib/afflib.cpp#L643-L834).
No AFFLIB code is copied.

For AFF4: the AFF4 Standard v1.0a (Bradley Schatz and Michael Cohen),
[`inprogress/AFF4StandardSpecification-v1.0a.md`](https://github.com/aff4/Standard/blob/da883fe48b15dec933a373f40e85e48b7b6c9214/inprogress/AFF4StandardSpecification-v1.0a.md)
at `da883fe`, for the container, the image stream and its index, the map and its gap
stream, the symbolic streams and the block map hash. What the standard leaves to the
implementations comes from pyaff4 at `6a91158` (Apache-2.0): the pre-standard index,
32-bit offsets where each chunk ends
([`aff4_image.py`, lines 461 to 503](https://github.com/aff4/pyaff4/blob/6a91158661edec6ed8a865a09e28dbf30d487e38/pyaff4/aff4_image.py#L461-L503)),
Scudette's always-compressed Snappy
([lines 689 to 691](https://github.com/aff4/pyaff4/blob/6a91158661edec6ed8a865a09e28dbf30d487e38/pyaff4/aff4_image.py#L689-L691)),
the 1 MiB tiles of the repeated-string streams
([`stream_factory.py`, lines 148 to 173](https://github.com/aff4/pyaff4/blob/6a91158661edec6ed8a865a09e28dbf30d487e38/pyaff4/stream_factory.py#L148-L173)),
and the order of the block map hash and of a striped image's hash
([`block_hasher.py`, lines 53 and 156 to 175](https://github.com/aff4/pyaff4/blob/6a91158661edec6ed8a865a09e28dbf30d487e38/pyaff4/block_hasher.py#L156-L175),
[lines 475 to 488](https://github.com/aff4/pyaff4/blob/6a91158661edec6ed8a865a09e28dbf30d487e38/pyaff4/block_hasher.py#L475-L488)),
and from c-aff4 at `63c9b2c` (Apache-2.0): how it compresses zlib, deflate and LZ4
chunks ([`aff4/aff4_image.cc`, lines 28 to 160](https://github.com/Velocidex/c-aff4/blob/63c9b2c352f9f74fc14c874063c03b06c4d1065c/aff4/aff4_image.cc#L28-L160))
and the method names it writes
([`aff4/lexicon.inc`, lines 155 to 163](https://github.com/Velocidex/c-aff4/blob/63c9b2c352f9f74fc14c874063c03b06c4d1065c/aff4/lexicon.inc#L155-L163)).
The Snappy decoder follows Google's
[`format_description.txt`](https://github.com/google/snappy/blob/9c28114a38866f6deeaa826db918293bc28ae410/format_description.txt)
at `9c28114` and the LZ4 decoder
[`doc/lz4_Block_format.md`](https://github.com/lz4/lz4/blob/0774d05537f9762f838f7ab541b7765f1a729cb5/doc/lz4_Block_format.md)
at `0774d05`. No code from any of them is copied.

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

For AD1: Petter Chr. Bjelland's *AccessData Format (AD1)* notes, in
[pcbje/pyad1](https://github.com/pcbje/pyad1/blob/74b21889410fb40b96e3f1f1f6ab369019d6984d/documentation/AccessData%20Format%20(AD1).asciidoc)
at `74b2188` (Apache-2.0), for the margin, the logical header, items, chunk tables and
metadata records, and the structures in al3ks1s/AD1-tools,
[`libad1/libad1_definitions.h`, lines 11 to 83](https://github.com/al3ks1s/AD1-tools/blob/2b4eec5d56cacd71717cf239d40de9a8d70fc6f4/AD1Tools/libad1/libad1_definitions.h#L11-L83)
at `2b4eec5`, for the addresses in the version 4 header and the metadata categories and
keys ([lines 133 to 160](https://github.com/al3ks1s/AD1-tools/blob/2b4eec5d56cacd71717cf239d40de9a8d70fc6f4/AD1Tools/libad1/libad1_definitions.h#L133-L160)).
The image hash follows pyad1's reader,
[`pyad1/reader.py`, lines 100 to 183](https://github.com/pcbje/pyad1/blob/74b21889410fb40b96e3f1f1f6ab369019d6984d/pyad1/reader.py#L100-L183):
the content hash's raw digest, not its hex form as the notes say, goes last
([line 183](https://github.com/pcbje/pyad1/blob/74b21889410fb40b96e3f1f1f6ab369019d6984d/pyad1/reader.py#L183)).
No code from either is copied. What the time records and item types mean was measured,
as described above.

For FTK Imager's AD encryption: the "AD encryption" section of the EWF documentation
above ([lines 3376 to 3465 at `d76fd0b`](https://github.com/libyal/libewf/blob/d76fd0bb21601e2969bc88ffdaeb861023f6a5b2/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc?plain=1#L3376-L3465)),
which it takes from AccessData's white paper. What that section leaves open was
measured on sets FTK Imager wrote, as described above.

For VHD: Microsoft's *Virtual Hard Disk Image Format Specification*, version 1.0 of
October 2006 ([download](https://www.microsoft.com/en-us/download/details.aspx?id=23850)),
for the footer and its checksum, the dynamic disk header, the block allocation table,
the sector bitmap and the parent locators. It does not give the bitmap's bit order or the
locators' byte order, which were measured on disks Windows 11 wrote, as described above.

For VHDX: Microsoft's *[MS-VHDX]: Virtual Hard Disk v2 (VHDX) File Format*, revision 8.0
of April 23, 2024
([Open Specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/83e061f8-f6e2-4de1-91bd-5d518a43d477)),
for the headers, region table, log and its replay, BAT, sector bitmap blocks, metadata
items and parent locator.

For VMDK: VMware's technical note *Virtual Disk Format 5.0* (2011), no longer on
vmware.com; the copy read is the Internet Archive's of its former address
([`vmdk_50_technote.pdf`, 1 January 2014](https://web.archive.org/web/20140101163557/https://www.vmware.com/support/developer/vddk/vmdk_50_technote.pdf)),
for the descriptor, the hosted and ESXi sparse extents and the stream-optimized form.

For QCOW: QEMU's own documents at commit `81ce3a8`,
[`docs/interop/qcow2.rst`](https://github.com/qemu/qemu/blob/81ce3a87737aa50716c42db8886082d12783e0a1/docs/interop/qcow2.rst)
for versions 2 and 3 (the header and its extensions, the L1 and L2 tables, compressed
clusters, which have no zlib header, extended L2 entries and snapshots), and, as version
1 has no document of its own, its driver
[`block/qcow.c`, lines 48 to 70 and 599 to 611](https://github.com/qemu/qemu/blob/81ce3a87737aa50716c42db8886082d12783e0a1/block/qcow.c#L48-L70)
for its header and how a compressed cluster records its size. No QEMU code is copied.

## License

MIT. See `LICENSE`.

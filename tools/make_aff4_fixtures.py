"""Write the small AFF4 containers tests/test_aff4.py reads.

Two sets, both generated content, none of it evidence:

* pyaff4-<method>.aff4: written by pyaff4 (Apache-2.0, github.com/aff4/pyaff4) with
  its own AFF4 Standard classes, AFF4SImage for the image stream and AFF4Map2 for the
  map, one per compression it writes: stored, Snappy, zlib and LZ4. These are another
  program's bytes. pyaff4 pins old dependencies; what installing it into a scratch
  folder took on Python 3.14 is `pip install --target DIR --no-deps pyaff4`, then
  rdflib intervaltree python-snappy lz4 future python-dateutil tzlocal pyyaml
  cryptography expiringdict pycryptoplus "setuptools<81" pynacl aes-keywrap passlib
  hexdump html5lib fastchunking, and PYTHONPATH=DIR.

* aff4-<case>.aff4: written here, for what no reference image and no pyaff4 image
  carries: LZ4 as c-aff4 writes it (a raw block, where pyaff4 prefixes the length),
  deflate as c-aff4 writes it (a zlib stream with spare bytes after it), raw deflate,
  Scudette's always-compressed Snappy, a map whose gaps read from
  aff4:UnknownData, a striped pair, and three containers ewfprobe must refuse. The
  chunks are compressed by the lz4, python-snappy and zlib libraries, not by
  ewfprobe's decoders, so the decoders are tested against those libraries' output;
  the container layout follows the AFF4 Standard v1.0a.

    python tools/make_aff4_fixtures.py tests/fixtures [--pyaff4]

It needs the lz4 and python-snappy packages, and --pyaff4 needs pyaff4 as well.

Every container's content is deterministic, and KNOWN below records the MD5 of what
each image must read back as, computed from the plain bytes before they are written.
"""

import hashlib
import io
import os
import random
import struct
import sys
import zipfile
import zlib

CHUNK = 4096
PER_BEVY = 8
NS = "http://aff4.org/Schema#"


def content():
    """The stream: incompressible chunks, text, zeros and a partial last chunk."""
    rng = random.Random(20260927)
    return (bytes(rng.getrandbits(8) for _ in range(3 * CHUNK))
            + b"".join(b"known AFF4 content, line %05d\n" % i for i in range(700))
            + bytes(2 * CHUNK)
            + bytes(rng.getrandbits(8) for _ in range(1234)))


def compressors():
    import lz4.block                            # noqa: PLC0415 (generator-only)
    import snappy                               # noqa: PLC0415

    def zlib_padded(chunk):
        # c-aff4's CompressDeflate_ writes a zlib stream into deflateBound's buffer
        # and never trims it, so spare bytes follow the stream
        return zlib.compress(chunk) + bytes(17)

    def raw_deflate(chunk):
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        return c.compress(chunk) + c.flush()

    return {
        "lz4-raw": ("https://code.google.com/p/lz4/",
                    lambda c: lz4.block.compress(c, store_size=False)),
        "deflate-zlibstream": ("https://tools.ietf.org/html/rfc1951", zlib_padded),
        "deflate-raw": ("https://tools.ietf.org/html/rfc1951", raw_deflate),
        "snappy-always": ("https://github.com/google/snappy", snappy.compress),
    }


def bevies(data, compress, always=False):
    """[(bevy bytes, index bytes)], each chunk stored when compressing does not save
    16 bytes (AFF4 Standard 3.2), except in always mode."""
    out = []
    chunks = [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)]
    chunks[-1] = chunks[-1].ljust(CHUNK, b"\0")          # the last chunk is padded
    for b in range(0, len(chunks), PER_BEVY):
        body, index = bytearray(), bytearray()
        for chunk in chunks[b:b + PER_BEVY]:
            packed = compress(chunk)
            if not always and len(packed) >= CHUNK - 16:
                packed = chunk
            if always and chunk[:1] == b"\xa5":         # one deliberately stored chunk
                packed = chunk
            index += struct.pack("<QI", len(body), len(packed))
            body += packed
        out.append((bytes(body), bytes(index)))
    return out


def turtle(volume, statements):
    lines = [f"@prefix : <{volume}> .", "@prefix aff4: <http://aff4.org/Schema#> .",
             "@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .", ""]
    for subject, props in statements:
        body = " ;\n    ".join(f"{p} {o}" for p, o in props)
        lines.append(f"<{subject}>\n    {body} .\n")
    return "\n".join(lines).encode()


def write_container(path, volume, members, statements):
    def put(z, name, data):
        # a fixed date, so the same content writes the same bytes every time
        z.writestr(zipfile.ZipInfo(name, date_time=(2026, 9, 27, 0, 0, 0)), data)

    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as z:
        put(z, "container.description", volume)
        put(z, "version.txt", "major=1\nminor=0\ntool=ewfprobe fixture\n")
        for name, data in members:
            put(z, name.replace("aff4://", "aff4%3A%2F%2F"), data)
        put(z, "information.turtle", turtle(volume, statements))
        z.comment = volume.encode()


def image_container(path, tag, method, compress, *, always=False, gap=None,
                    extra_map=(), stream_type="aff4:ImageStream", reverse_map=False):
    data = content()
    volume = f"aff4://f1{tag}00000-0000-4000-8000-000000000001"
    stream = f"aff4://5e{tag}00000-0000-4000-8000-000000000002"
    amap = f"aff4://3a{tag}00000-0000-4000-8000-000000000003"
    image = f"aff4://1a{tag}00000-0000-4000-8000-000000000004"
    if always:
        data = data[:5 * CHUNK] + b"\xa5" + bytes(CHUNK - 1) + data[6 * CHUNK:]
    split = 5 * CHUNK + 100
    hole = 3 * CHUNK
    ranges = [(0, split, 0, 0), (split + hole, len(data) - split, split, 0),
              (split + hole + len(data) - split, 2 * CHUNK,
               split + hole + len(data) - split, 1)] + list(extra_map)
    if reverse_map:                                   # BlackBag's libaff4 writes them unsorted
        ranges.reverse()
    targets = [stream, NS + "SymbolicStreamFF"]
    members = []
    for n, (body, index) in enumerate(bevies(data, compress, always)):
        members += [(f"{stream}/{n:08d}", body), (f"{stream}/{n:08d}.index", index)]
    members += [(f"{amap}/map", b"".join(struct.pack("<QQQI", *r) for r in ranges)),
                (f"{amap}/idx", ("\n".join(targets) + "\n").encode())]
    size = split + hole + len(data) - split + 2 * CHUNK
    map_props = [("a", "aff4:Map"), ("aff4:size", f'"{size}"^^xsd:long'),
                 ("aff4:dependentStream", f"<{stream}>")]
    if gap:
        map_props.append(("aff4:mapGapDefaultStream", gap))
    statements = [
        (image, [("a", "aff4:DiskImage, aff4:ContiguousImage, aff4:Image"),
                 ("aff4:dataStream", f"<{amap}>"), ("aff4:size", f'"{size}"^^xsd:long'),
                 ("aff4:blockSize", '"512"^^xsd:int')]),
        (amap, map_props),
        (stream, [("a", stream_type), ("aff4:chunkSize", f'"{CHUNK}"^^xsd:int'),
                  ("aff4:chunksInSegment", f'"{PER_BEVY}"^^xsd:int'),
                  ("aff4:compressionMethod", f"<{method}>"),
                  ("aff4:size", f'"{len(data)}"^^xsd:long')]),
    ]
    write_container(path, volume, members, statements)
    fill = b"UNKNOWN" if gap == "aff4:UnknownData" else None
    whole = bytearray(data[:split])
    for off in range(split, split + hole):
        whole.append(0 if fill is None else fill[(off % (1 << 20)) % 7])
    whole += data[split:] + b"\xff" * 2 * CHUNK
    return hashlib.md5(bytes(whole)).hexdigest()


def striped(folder):
    """Two files, each holding one of the image's two streams and a map of both."""
    data = content()
    half = 6 * CHUNK
    parts = (data[:half], data[half:])
    urns = [f"aff4://5e{t}00000-0000-4000-8000-00000000000{t}" for t in "ab"]
    image = "aff4://1aab0000-0000-4000-8000-00000000000c"
    names = []
    for k, t in enumerate("ab"):
        volume = f"aff4://f1{t}00000-0000-4000-8000-00000000000{t}"
        amap = f"aff4://3a{t}00000-0000-4000-8000-00000000000{t}"
        members = []
        for n, (body, index) in enumerate(bevies(parts[k], lambda c: c)):
            members += [(f"{urns[k]}/{n:08d}", body),
                        (f"{urns[k]}/{n:08d}.index", index)]
        ranges = [(0, half, 0, 0), (half, len(data) - half, 0, 1)]
        members += [(f"{amap}/map", b"".join(struct.pack("<QQQI", *r) for r in ranges)),
                    (f"{amap}/idx", ("\n".join(urns) + "\n").encode())]
        statements = [
            (image, [("a", "aff4:DiskImage, aff4:ContiguousImage, aff4:Image"),
                     ("aff4:dataStream", f"<{amap}>")]),
            (amap, [("a", "aff4:Map"), ("aff4:size", f'"{len(data)}"^^xsd:long'),
                    ("aff4:dependentStream", f"<{urns[0]}>, <{urns[1]}>")]),
            (urns[k], [("a", "aff4:ImageStream"), ("aff4:chunkSize", f'"{CHUNK}"^^xsd:int'),
                       ("aff4:chunksInSegment", f'"{PER_BEVY}"^^xsd:int'),
                       ("aff4:compressionMethod", "aff4:NullCompressor"),
                       ("aff4:size", f'"{len(parts[k])}"^^xsd:long')]),
        ]
        name = f"aff4-striped_{k + 1}.aff4"
        write_container(os.path.join(folder, name), volume, members, statements)
        names.append(name)
    return hashlib.md5(data).hexdigest()


def pyaff4_containers(folder):
    """The pyaff4-written set: pyaff4's AFF4SImage and AFF4Map2 over content(), the
    same stream the others hold, mapped with a gap and a range of SymbolicStreamFF."""
    import warnings                              # noqa: PLC0415 (generator-only)
    warnings.filterwarnings("ignore")
    from pyaff4 import aff4_image, aff4_map, container, data_store, lexicon, rdfvalue, zip  # noqa: PLC0415,A004

    data = content()
    split, hole = 5 * CHUNK + 100, 3 * CHUNK
    known = {}
    methods = {"stored": lexicon.AFF4_IMAGE_COMPRESSION_STORED,
               "snappy": lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY,
               "zlib": lexicon.AFF4_IMAGE_COMPRESSION_ZLIB,
               "lz4": lexicon.AFF4_IMAGE_COMPRESSION_LZ4}
    for name, method in methods.items():
        path = os.path.join(folder, f"pyaff4-{name}.aff4")
        if os.path.exists(path):
            os.remove(path)
        urn = rdfvalue.URN.FromFileName(path)
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))
            with zip.ZipFile.NewZipFile(resolver, container.Version(1, 0, "pyaff4"),
                                        urn) as zf:
                vol = zf.urn
                s_urn = rdfvalue.URN("aff4://5e1f0000-0000-4000-8000-%012d" % len(name))
                with aff4_image.AFF4SImage.NewAFF4Image(resolver, s_urn, vol) as img:
                    img.setCompressionMethod(method)
                    img.chunk_size = CHUNK
                    img.chunks_per_segment = PER_BEVY
                    img.Write(data)
                m_urn = rdfvalue.URN("aff4://3a900000-0000-4000-8000-%012d" % len(name))
                with aff4_map.AFF4Map2.NewAFF4Map(resolver, m_urn, vol) as m:
                    m.AddRange(0, 0, split, s_urn)
                    m.AddRange(split + hole, split, len(data) - split, s_urn)
                    m.AddRange(hole + len(data), hole + len(data), 2 * CHUNK,
                               rdfvalue.URN(lexicon.AFF4_NAMESPACE + "SymbolicStreamFF"))
                i_urn = rdfvalue.URN("aff4://1a6e0000-0000-4000-8000-%012d" % len(name))
                resolver.Add(vol, i_urn, lexicon.AFF4_TYPE,
                             rdfvalue.URN(lexicon.AFF4_NAMESPACE + "Image"))
                resolver.Add(vol, i_urn, rdfvalue.URN(lexicon.AFF4_NAMESPACE + "dataStream"),
                             m_urn)
        known[f"pyaff4-{name}.aff4"] = hashlib.md5(
            data[:split] + bytes(hole) + data[split:] + b"\xff" * 2 * CHUNK).hexdigest()
    return known


def main(argv):
    folder = argv[1]
    known = {}
    for tag, (name, (method, compress)) in zip("0123", compressors().items()):
        known[f"aff4-{name}.aff4"] = image_container(
            os.path.join(folder, f"aff4-{name}.aff4"), tag, method, compress,
            always=name == "snappy-always", reverse_map=name == "deflate-raw")
    known["aff4-gap-unknown.aff4"] = image_container(
        os.path.join(folder, "aff4-gap-unknown.aff4"), "4", NS + "NullCompressor",
        lambda c: c, gap="aff4:UnknownData")
    image_container(os.path.join(folder, "aff4-overlapping-map.aff4"), "5",
                    NS + "NullCompressor", lambda c: c,
                    extra_map=[(100, 50, 0, 0)])
    image_container(os.path.join(folder, "aff4-encrypted-stream.aff4"), "6",
                    NS + "NullCompressor", lambda c: c,
                    stream_type="aff4:EncryptedStream")
    known["aff4-striped_1.aff4"] = striped(folder)
    if "--pyaff4" in argv:
        known.update(pyaff4_containers(folder))
    for name, md5 in sorted(known.items()):
        print(f"{md5}  {name}")


if __name__ == "__main__":
    main(sys.argv)

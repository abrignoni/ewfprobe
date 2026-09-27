"""Tests for FTK Imager's AD encryption, on sets this module writes.

The layout is from Joachim Metz's EWF documentation ("AD encryption", from
AccessData's white paper); the details it leaves open (the PBKDF2 hash, how the
file key is encrypted, the password's bytes) were measured on sets FTK Imager
wrote, and those sets are tested in test_reference_fixtures.py against the hashes
FTK Imager recorded. The writer here wraps the committed EWF, SMART and Ex01
fixtures and constructed raw sets, for what FTK Imager would not write: other
ciphers and hashes, damaged headers, and what is inside that ewfprobe refuses.

The writer encrypts with the cipher library's CTR mode and its little-endian
counter; ewfprobe decrypts through ECB and its own XOR, so the two share no code.
"""

import hashlib
import hmac
import json
import os
import random
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ewfprobe  # noqa: E402

try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
except ImportError:
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Util import Counter
    except ImportError:
        AES = Counter = None

# A job that installs pycryptodome sets this, so these tests run there rather than
# skip unseen.
_CRYPTO_REQUIRED = bool(os.environ.get("EWFPROBE_REQUIRE_CRYPTO"))
pytestmark = pytest.mark.skipif(
    AES is None and not _CRYPTO_REQUIRED,
    reason="AD-encrypted images need the optional pycryptodome package")

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
PASSWORD = "constructed-ad-password"
HEADER = struct.Struct("<8sIIhhh2sIIIIII")
HASHES = {1: "sha256", 2: "sha512"}


def _ctr(key, data, first_block):
    ctr = Counter.new(128, initial_value=first_block, little_endian=True)
    return AES.new(key, AES.MODE_CTR, counter=ctr).encrypt(data)


def write_adcrypt(plain_files, out_files, password=PASSWORD, *, cipher=3, hash_id=2,
                  iterations=4000, version=1, header_size=512, seed=7, mutate=None):
    """Encrypt each of ``plain_files`` into ``out_files`` as FTK Imager does: one key
    for the set, the header in the first file only, file i under counter i << 64.
    ``mutate(header)`` may edit the header (a bytearray) before it is written."""
    r = random.Random(seed)
    key_bytes = {1: 16, 2: 24, 3: 32}.get(cipher, 32)
    file_key, salt = r.randbytes(key_bytes), r.randbytes(16)
    digest = hashlib.new(HASHES.get(hash_id, "sha512"), password.encode("utf-8")).digest()
    made = hashlib.pbkdf2_hmac("sha1", digest, salt, iterations, key_bytes)
    wrapped = _ctr(made, file_key, 0)
    mac = hmac.new(made, wrapped, HASHES.get(hash_id, "sha512")).digest()
    header = bytearray(HEADER.pack(b"ADCRYPT\x00", version, header_size, -1, -1, -1,
                                   b"\x00\x00", cipher, hash_id, iterations, len(salt),
                                   len(wrapped), len(mac)) + salt + wrapped + mac)
    header += bytes(header_size - len(header))
    if mutate:
        mutate(header)
    for index, (src, dst) in enumerate(zip(plain_files, out_files)):
        with open(src, "rb") as fh:
            data = fh.read()
        body = _ctr(file_key, data, index << 64)
        with open(dst, "wb") as fh:
            fh.write((bytes(header) if index == 0 else b"") + body)
    return out_files


def _manifest():
    with open(os.path.join(FIXTURES, "manifest.json"), encoding="utf-8") as fh:
        return json.load(fh)


def _wrap_fixture(tmp_path, variant, **kwargs):
    files = _manifest()["variants"][variant]["files"]
    out = [str(tmp_path / f) for f in files]
    write_adcrypt([os.path.join(FIXTURES, f) for f in files], out, **kwargs)
    return out


def _sha(img):
    h = hashlib.sha256()
    img.seek(0)
    while True:
        block = img.read(1 << 20)
        if not block:
            return h.hexdigest()
        h.update(block)


def _raw_set(tmp_path, sizes=(4096, 4096, 1536), seed=11, stem="disk", width=3):
    r = random.Random(seed)
    disk = r.randbytes(sum(sizes))
    plain, at = [], 0
    for n, size in enumerate(sizes, 1):
        p = tmp_path / f"plain.{n:0{width}d}"
        p.write_bytes(disk[at:at + size])
        plain.append(str(p))
        at += size
    out = [str(tmp_path / f"{stem}.{n:0{width}d}") for n in range(1, len(sizes) + 1)]
    return disk, plain, out


@pytest.mark.parametrize("variant,fmt", [("encase6-split", ewfprobe.FORMAT_E01),
                                         ("smart-split", ewfprobe.FORMAT_S01),
                                         ("ex01-fast", ewfprobe.FORMAT_EX01)])
def test_an_encrypted_ewf_set_reads_as_the_plain_one(tmp_path, variant, fmt):
    """Every file of the set is encrypted under its own counter, and only the first
    carries the header, so a four-segment set exercises the counter per file."""
    paths = _wrap_fixture(tmp_path, variant)
    assert ewfprobe.is_adcrypt(paths[0])
    assert not any(ewfprobe.is_adcrypt(p) for p in paths[1:])
    assert ewfprobe.adcrypt_set(paths[0]) == paths
    with ewfprobe.open_ewf(paths[0], password=PASSWORD) as img:
        assert img.format == fmt
        assert img.paths == paths
        assert _sha(img) == _manifest()["sha256"]
        assert img.encryption == {"container": "AD encryption (FTK Imager)",
                                  "cipher": "AES-256-CTR", "key_wrap": "AES-256-CTR",
                                  "kdf": "PBKDF2-HMAC-SHA1 of SHA512", "kdf_rounds": 4000}
        assert img.verify()["match"] is True        # the set's own stored hash


def test_a_segment_encrypted_under_the_wrong_counter_does_not_read(tmp_path):
    """The control for the test above: the same set with its second file encrypted as
    if it were the first must not read back, so the counter is doing the work."""
    paths = _wrap_fixture(tmp_path, "encase6-split")
    files = _manifest()["variants"]["encase6-split"]["files"]
    tmp = tmp_path / "second-as-first"
    tmp.mkdir()
    write_adcrypt([os.path.join(FIXTURES, files[1])], [str(tmp / "x")], header_size=512)
    with open(tmp / "x", "rb") as fh:
        with open(paths[1], "wb") as out:
            out.write(fh.read()[512:])
    with pytest.raises(ewfprobe.EwfError):
        with ewfprobe.open_ewf(paths[0], password=PASSWORD) as img:
            _sha(img)


@pytest.mark.parametrize("cipher,hash_id,bits,name", [(1, 1, 128, "SHA256"),
                                                      (2, 2, 192, "SHA512"),
                                                      (3, 1, 256, "SHA256")])
def test_a_raw_set_reads_whatever_cipher_and_hash_the_header_names(tmp_path, cipher,
                                                                   hash_id, bits, name):
    disk, plain, out = _raw_set(tmp_path)
    write_adcrypt(plain, out, cipher=cipher, hash_id=hash_id, iterations=1000)
    with ewfprobe.open_ewf(out[0], password=PASSWORD) as img:
        assert img.format == ewfprobe.FORMAT_RAW
        assert img.paths == out
        assert img.media_size == len(disk)
        assert _sha(img) == hashlib.sha256(disk).hexdigest()
        assert img.encryption["cipher"] == f"AES-{bits}-CTR"
        assert img.encryption["kdf"] == f"PBKDF2-HMAC-SHA1 of {name}"
        img.seek(4096 - 7)
        assert img.read(14) == disk[4096 - 7:4096 + 7]      # across two files


def test_a_raw_set_opens_from_a_later_segment_and_from_a_lone_file(tmp_path):
    """Only the first file carries the header, so a later numbered segment is
    recognised by its first sibling; a set of one file is read as it is."""
    disk, plain, out = _raw_set(tmp_path)
    write_adcrypt(plain, out)
    assert not ewfprobe.is_adcrypt(out[2])
    assert ewfprobe.adcrypt_set(out[2]) == out
    with ewfprobe.open_ewf(out[2], password=PASSWORD) as img:
        assert _sha(img) == hashlib.sha256(disk).hexdigest()
    lone = tmp_path / "lone"
    lone.mkdir()
    write_adcrypt([plain[0]], [str(lone / "disk.dd")])
    with ewfprobe.open_ewf(str(lone / "disk.dd"), password=PASSWORD) as img:
        assert img.format == ewfprobe.FORMAT_RAW and img.media_size == 4096


def test_an_unencrypted_numbered_set_is_not_an_ad_set(tmp_path):
    _disk_bytes, plain, _out = _raw_set(tmp_path)
    assert ewfprobe.adcrypt_set(plain[1]) is None
    assert ewfprobe.adcrypt_set(str(tmp_path)) is None


def test_no_password_and_a_wrong_one_are_told_apart(tmp_path):
    _disk_bytes, plain, out = _raw_set(tmp_path)
    write_adcrypt(plain, out)
    with pytest.raises(ewfprobe.EwfPasswordRequiredError, match="AD encryption"):
        ewfprobe.open_ewf(out[0])
    with pytest.raises(ewfprobe.EwfWrongPasswordError):
        ewfprobe.open_ewf(out[0], password=PASSWORD + "x")
    with ewfprobe.open_ewf(out[0], password=PASSWORD.encode("utf-8")) as img:
        assert img.format == ewfprobe.FORMAT_RAW


def test_the_password_is_its_utf8_bytes(tmp_path):
    _disk_bytes, plain, out = _raw_set(tmp_path)
    write_adcrypt(plain, out, password="pässwörd")
    with ewfprobe.open_ewf(out[0], password="pässwörd") as img:
        assert img.format == ewfprobe.FORMAT_RAW
    with pytest.raises(ewfprobe.EwfWrongPasswordError):
        ewfprobe.open_ewf(out[0], password="pässwörd".encode("latin-1"))


def _poke(fmt, at, value):
    def mutate(header):
        struct.pack_into(fmt, header, at, value)
    return mutate


@pytest.mark.parametrize("mutate,match", [
    (_poke("<I", 8, 2), "version 2"),
    (_poke("<I", 24, 9), "cipher 9"),
    (_poke("<I", 28, 3), "hash 3"),
    (_poke("<I", 40, 16), "key or HMAC length"),
    (_poke("<I", 32, 0), "0 PBKDF2 iterations"),
    (_poke("<I", 32, 60_000_000), "60,000,000 PBKDF2 iterations"),
    (_poke("<I", 12, 64), "lengths do not fit"),
])
def test_a_damaged_header_is_refused_by_what_is_wrong(tmp_path, mutate, match):
    _disk_bytes, plain, out = _raw_set(tmp_path)
    write_adcrypt(plain, out, mutate=mutate)
    with pytest.raises(ewfprobe.EwfFormatError, match=match):
        ewfprobe.open_ewf(out[0], password=PASSWORD)


def test_a_header_cut_short_is_refused(tmp_path):
    _disk_bytes, plain, out = _raw_set(tmp_path)
    write_adcrypt(plain[:1], out[:1])
    with open(out[0], "rb") as fh:
        head = fh.read(60)
    lone = tmp_path / "cut.dd"
    lone.write_bytes(head)
    with pytest.raises(ewfprobe.EwfIncompleteSetError, match="inside its AD encryption"):
        ewfprobe.open_ewf(str(lone), password=PASSWORD)


def test_an_encrypted_ad1_set_reads_as_the_plain_one(tmp_path):
    plain = [os.path.join(FIXTURES, "ad1", f"lean-src-c0-1mb.ad{n}") for n in range(1, 5)]
    out = [str(tmp_path / f"evidence.ad{n}") for n in range(1, 5)]
    write_adcrypt(plain, out)
    with ewfprobe.open_ewf(plain[0]) as want, \
            ewfprobe.open_ewf(out[2], password=PASSWORD) as img:
        assert img.format == ewfprobe.FORMAT_AD1 and len(img.paths) == 4
        entries = [(e.path, e.size, e.md5) for e in img.logical_entries]
        assert entries == [(e.path, e.size, e.md5) for e in want.logical_entries]
        result = img.verify()
    assert result["entry_md5_checked"] == 8 and not result["entry_md5_mismatched"]


def test_an_ad1_name_that_decrypts_to_something_else_is_refused(tmp_path):
    plain = tmp_path / "plain"
    plain.write_bytes(bytes(4096))
    out = str(tmp_path / "evidence.ad1")
    write_adcrypt([str(plain)], [out])
    with pytest.raises(ewfprobe.EwfFormatError, match="not AD1"):
        ewfprobe.open_ewf(out, password=PASSWORD)


def test_an_ewf_name_that_decrypts_to_something_else_is_refused(tmp_path):
    plain = tmp_path / "plain"
    plain.write_bytes(bytes(4096))
    out = str(tmp_path / "evidence.E01")
    write_adcrypt([str(plain)], [out])
    with pytest.raises(ewfprobe.EwfFormatError, match="not EWF"):
        ewfprobe.open_ewf(out, password=PASSWORD)


def test_a_raw_set_that_is_not_whole_sectors_is_refused(tmp_path):
    _disk_bytes, plain, out = _raw_set(tmp_path, sizes=(4096, 1000))
    write_adcrypt(plain, out)
    with pytest.raises(ewfprobe.EwfFormatError, match="not a whole number"):
        ewfprobe.open_ewf(out[0], password=PASSWORD)


def test_without_the_cipher_package_the_image_is_refused_by_name(tmp_path, monkeypatch):
    _disk_bytes, plain, out = _raw_set(tmp_path)
    write_adcrypt(plain, out)
    monkeypatch.setattr(ewfprobe, "_AES", None)
    with pytest.raises(ewfprobe.EwfFormatError, match="needs the pycryptodome package"):
        ewfprobe.open_ewf(out[0], password=PASSWORD)


def test_the_cli_describes_an_ad_encrypted_raw_set(tmp_path, capsys, monkeypatch):
    disk, plain, out = _raw_set(tmp_path)
    write_adcrypt(plain, out)
    monkeypatch.setenv("AD_TEST_PASSWORD", PASSWORD)
    assert ewfprobe.main(["info", out[0], "--password-env", "AD_TEST_PASSWORD"]) == 0
    text = capsys.readouterr().out
    assert "format          RAW" in text
    assert "segments        3 (disk.001 .. disk.003)" in text
    assert f"media size      {len(disk):,} bytes" in text
    assert "AD encryption (FTK Imager)" in text
    assert PASSWORD not in text

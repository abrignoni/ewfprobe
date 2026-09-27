"""Tests for encrypted Apple disk images (encrcdsa version 2), on files this module
writes from the layout nlitsme/encrypteddmg and kev365/xways-imageio-dmg publish.

hdiutil on current macOS wraps the keys with AES-192; images from older macOS wrap
them with 3DES, which hdiutil no longer writes, so that path, the certificate and
version 1 refusals and the damaged files are only tested here, on constructed
files. The images hdiutil did write are tested in test_reference_fixtures.py, where
every one was checked against hdiutil's own reading of it.

The writer encrypts with the cipher library's CBC mode; ewfprobe decrypts through
ECB and its own XOR, so the two do not share that code.
"""

import hashlib
import hmac
import io
import os
import random
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ewfprobe  # noqa: E402
from test_apple_images import write_udif, write_bundle, _disk  # noqa: E402

try:
    from Crypto.Cipher import AES, DES3
except ImportError:
    try:
        from Cryptodome.Cipher import AES, DES3
    except ImportError:
        AES = DES3 = None

# A job that installs pycryptodome sets this, so these tests run there rather than
# skip unseen.
_CRYPTO_REQUIRED = bool(os.environ.get("EWFPROBE_REQUIRE_CRYPTO"))
needs_crypto = pytest.mark.skipif(
    AES is None and not _CRYPTO_REQUIRED,
    reason="encrypted images need the optional pycryptodome package")

PASSWORD = "constructed-test-password"
HEADER = struct.Struct(">8s7L16sLQQL")
ITEM = struct.Struct(">LQQ")
PASSWORD_ITEM = struct.Struct(">LQL32sL32s5L")


def _keys(key_bits, seed):
    r = random.Random(seed)
    return r.randbytes(key_bits // 8), r.randbytes(20), r


def _password_item(aes_key, hmac_key, password, *, wrap, rounds, r, mark=b"CKIE\x00"):
    keydata = aes_key + hmac_key + mark
    unit = 16 if wrap == "aes" else 8
    pad = unit - len(keydata) % unit
    keydata += bytes([pad]) * pad
    salt, iv = r.randbytes(20), r.randbytes(8)
    secret = password.encode("utf-8") if isinstance(password, str) else password
    derived = hashlib.pbkdf2_hmac("sha1", secret, salt, rounds, 32)
    if wrap == "aes":
        blob = AES.new(derived[:24], AES.MODE_CBC, iv=iv + bytes(8)).encrypt(keydata)
        algorithm = 0x80000001
    else:
        blob = DES3.new(derived[:24], DES3.MODE_CBC, iv=iv).encrypt(keydata)
        algorithm = 0x11
    return PASSWORD_ITEM.pack(0x67, rounds, 20, salt, 8, iv, 192, algorithm, 7, 6,
                              len(blob)) + blob


def _encrypt_blocks(aes_key, hmac_key, plain, block=512):
    plain = plain + bytes(-len(plain) % block)
    out = bytearray()
    for n in range(len(plain) // block):
        iv = hmac.new(hmac_key, struct.pack(">L", n), "sha1").digest()[:16]
        out += AES.new(aes_key, AES.MODE_CBC, iv=iv).encrypt(plain[n * block:(n + 1) * block])
    return bytes(out)


def encrcdsa(plain, password=PASSWORD, *, key_bits=128, wrap="aes", rounds=1000,
             items=None, data_length=None, seed=1, version=2):
    """An encrcdsa file holding ``plain``: its header, one password item (or the
    ``items`` given, as (type, bytes) pairs), then ``plain`` encrypted in 512-byte
    blocks from offset 4096."""
    aes_key, hmac_key, r = _keys(key_bits, seed)
    if items is None:
        items = [(1, _password_item(aes_key, hmac_key, password, wrap=wrap,
                                    rounds=rounds, r=r))]
    start = 4096
    table = b""
    body = b""
    at = HEADER.size + ITEM.size * len(items)
    for kind, blob in items:
        table += ITEM.pack(kind, at + len(body), len(blob))
        body += blob
    head = HEADER.pack(b"encrcdsa", version, 16, 5, 0x80000001, key_bits, 0x5B, 160,
                       r.randbytes(16), 512,
                       len(plain) if data_length is None else data_length, start,
                       len(items)) + table + body
    return head.ljust(start, b"\0") + _encrypt_blocks(aes_key, hmac_key, plain)


def _write(path, data):
    with open(path, "wb") as fh:
        fh.write(data)
    return str(path)


def _read_all(img):
    img.seek(0)
    return img.read(img.media_size)


@needs_crypto
@pytest.mark.parametrize("key_bits,wrap", [(128, "aes"), (256, "aes"), (128, "3des"),
                                            (256, "3des")])
def test_a_constructed_image_decrypts_under_either_key_wrap(tmp_path, key_bits, wrap):
    disk = _disk(40)
    path = _write(tmp_path / "rw.dmg", encrcdsa(disk, key_bits=key_bits, wrap=wrap))
    assert ewfprobe.apple_image_kind(path) == "ENCRYPTED"
    with ewfprobe.open_ewf(path, password=PASSWORD) as img:
        assert img.format == ewfprobe.FORMAT_UDRW
        assert img.media_size == len(disk)
        assert _read_all(img) == disk
        for start, length in ((0, 1), (511, 2), (1000, 3000), (len(disk) - 7, 7)):
            img.seek(start)
            assert img.read(length) == disk[start:start + length]
        info = img.info()["encryption"]
    assert info["cipher"] == f"AES-{key_bits}"
    assert info["key_wrap"] == ("AES-192" if wrap == "aes" else "3DES")
    assert info["kdf_rounds"] == 1000


@needs_crypto
def test_a_udif_image_inside_the_container_reads_as_udif(tmp_path):
    disk = _disk(48, seed=9)
    inner = write_udif(tmp_path / "inner.dmg", disk)
    with open(inner, "rb") as fh:
        plain = fh.read()
    path = _write(tmp_path / "enc.dmg", encrcdsa(plain))
    with ewfprobe.open_ewf(path, password=PASSWORD) as img:
        assert img.format == ewfprobe.FORMAT_UDIF
        assert _read_all(img) == disk
        assert all(c["match"] for c in img.verify()["container_checks"])


@needs_crypto
def test_the_password_may_be_bytes_and_any_password_item_may_open_it(tmp_path):
    disk = _disk(8)
    aes_key, hmac_key, r = _keys(128, 1)
    items = [(1, _password_item(aes_key, hmac_key, "first", wrap="aes", rounds=500, r=r)),
             (1, _password_item(aes_key, hmac_key, b"\xffsecond", wrap="3des",
                                rounds=700, r=r))]
    path = _write(tmp_path / "two.dmg", encrcdsa(disk, items=items))
    for password in ("first", b"first", b"\xffsecond"):
        with ewfprobe.open_ewf(path, password=password) as img:
            assert _read_all(img) == disk
    with pytest.raises(ewfprobe.EwfWrongPasswordError, match="does not open two.dmg"):
        ewfprobe.open_ewf(path, password="second")


@needs_crypto
def test_a_missing_or_wrong_password_is_refused_as_such(tmp_path):
    path = _write(tmp_path / "locked.dmg", encrcdsa(_disk(8)))
    with pytest.raises(ewfprobe.EwfPasswordRequiredError, match="opens only with its"):
        ewfprobe.open_ewf(path)
    with pytest.raises(ewfprobe.EwfWrongPasswordError) as caught:
        ewfprobe.open_ewf(path, password="not it")
    assert "not it" not in str(caught.value)
    # both are format errors, so callers that refuse on EwfFormatError still do
    assert issubclass(ewfprobe.EwfPasswordError, ewfprobe.EwfFormatError)


@needs_crypto
def test_keys_that_unwrap_without_their_end_mark_are_a_wrong_password(tmp_path):
    aes_key, hmac_key, r = _keys(128, 1)
    item = _password_item(aes_key, hmac_key, PASSWORD, wrap="aes", rounds=500, r=r,
                          mark=b"XXXX\x00")
    path = _write(tmp_path / "nomark.dmg", encrcdsa(_disk(8), items=[(1, item)]))
    with pytest.raises(ewfprobe.EwfWrongPasswordError):
        ewfprobe.open_ewf(path, password=PASSWORD)


def test_a_keybag_image_is_refused_and_a_certificate_one_asks_for_its_key(tmp_path):
    for kind in (2, 3):
        path = tmp_path / f"k{kind}.dmg"
        head = HEADER.pack(b"encrcdsa", 2, 16, 5, 0x80000001, 128, 0x5B, 160, bytes(16),
                           512, 512, 4096, 1) + ITEM.pack(kind, 96, 564) + bytes(564)
        path.write_bytes(head.ljust(4096, b"\0") + bytes(512))
        if kind == 3:
            with pytest.raises(ewfprobe.EwfFormatError,
                               match="keybag, not a password or a certificate"):
                ewfprobe.open_ewf(str(path), password=PASSWORD)
            continue
        # a password does not open an image sealed only to a certificate: it asks for
        # the certificate's private key instead of another password
        with pytest.raises(ewfprobe.EwfPasswordRequiredError) as caught:
            ewfprobe.open_ewf(str(path), password=PASSWORD)
        assert caught.value.needs == "private key"


def test_a_header_ewfprobe_does_not_read_is_refused(tmp_path):
    cases = [
        ({"version": 1}, "encrcdsa version 1"),
        ({"algorithm": 0x11}, "only AES-CBC"),
        ({"key_bits": 192}, "only AES-CBC with a 128 or 256-bit key"),
        ({"iv_algorithm": 0x5A}, "only HMAC-SHA1"),
        ({"block": 500}, "not a whole number of AES blocks"),
        ({"count": 0}, "lists 0 key items"),
    ]
    for change, match in cases:
        f = {"version": 2, "algorithm": 0x80000001, "key_bits": 128, "iv_algorithm": 0x5B,
             "block": 512, "count": 1}
        f.update(change)
        head = HEADER.pack(b"encrcdsa", f["version"], 16, 5, f["algorithm"], f["key_bits"],
                           f["iv_algorithm"], 160, bytes(16), f["block"], 512, 4096,
                           f["count"]) + ITEM.pack(1, 96, 200) + bytes(200)
        path = tmp_path / "bad.dmg"
        path.write_bytes(head.ljust(4096, b"\0") + bytes(512))
        with pytest.raises(ewfprobe.EwfFormatError, match=match):
            ewfprobe.open_ewf(str(path), password=PASSWORD)


@needs_crypto
def test_a_hostile_round_count_is_refused_without_running_it(tmp_path):
    aes_key, hmac_key, r = _keys(128, 1)
    item = bytearray(_password_item(aes_key, hmac_key, PASSWORD, wrap="aes", rounds=500,
                                    r=r))
    struct.pack_into(">Q", item, 4, (1 << 31) - 1)   # runs for many minutes if allowed
    path = _write(tmp_path / "slow.dmg", encrcdsa(_disk(8), items=[(1, bytes(item))]))
    with pytest.raises(ewfprobe.EwfFormatError, match="PBKDF2 rounds"):
        ewfprobe.open_ewf(path, password=PASSWORD)


@needs_crypto
def test_an_image_cut_short_inside_its_encrypted_data_is_refused(tmp_path):
    blob = encrcdsa(_disk(16))
    path = _write(tmp_path / "short.dmg", blob[:-1000])
    with pytest.raises(ewfprobe.EwfIncompleteSetError, match="cut short"):
        ewfprobe.open_ewf(path, password=PASSWORD)


def test_a_version_1_image_is_recognised_and_refused(tmp_path):
    path = tmp_path / "old.dmg"
    path.write_bytes(bytes(8192) + b"\x00\x00\x00\x00\x00\x00\x10\x00"
                     + b"\x00\x00\x00\x01cdsaencr")
    assert ewfprobe.apple_image_kind(str(path)) == "ENCRYPTED"
    assert not ewfprobe.is_image(str(path))
    with pytest.raises(ewfprobe.EwfFormatError, match="version 1 format"):
        ewfprobe.open_ewf(str(path), password=PASSWORD)


def test_without_the_cipher_package_it_is_refused_by_name(tmp_path, monkeypatch):
    head = HEADER.pack(b"encrcdsa", 2, 16, 5, 0x80000001, 128, 0x5B, 160, bytes(16),
                       512, 512, 4096, 1) + ITEM.pack(1, 96, 200) + bytes(200)
    path = tmp_path / "nolib.dmg"
    path.write_bytes(head.ljust(4096, b"\0") + bytes(512))
    monkeypatch.setattr(ewfprobe, "_AES", None)
    with pytest.raises(ewfprobe.EwfFormatError, match="pycryptodome") as caught:
        ewfprobe.open_ewf(str(path), password=PASSWORD)
    assert not isinstance(caught.value, ewfprobe.EwfPasswordError)


def _encrypted_bundle(tmp_path, disk, band, *, seed=3, cut=None):
    """A sparse bundle whose bands are each encrypted on their own, block numbers
    from 0, and whose token holds only the header, as hdiutil writes one."""
    aes_key, hmac_key, r = _keys(256, seed)
    item = _password_item(aes_key, hmac_key, PASSWORD, wrap="aes", rounds=600, r=r)
    token = (HEADER.pack(b"encrcdsa", 2, 16, 5, 0x80000001, 256, 0x5B, 160, bytes(16),
                         512, 0, 4096, 1) + ITEM.pack(1, 96, len(item)) + item)
    token = token.ljust(4096, b"\0")
    bands = {}
    for number in range(-(-len(disk) // band)):
        piece = disk[number * band:(number + 1) * band]
        if any(piece):
            bands[format(number, "x")] = _encrypt_blocks(aes_key, hmac_key, piece)
    if cut:
        name, length = cut
        bands[name] = bands[name][:length]
    folder = write_bundle(tmp_path / "enc.sparsebundle", b"", band, size=len(disk),
                          bands=bands, token=token)
    return folder


@needs_crypto
def test_an_encrypted_sparse_bundle_decrypts_each_band_from_block_zero(tmp_path):
    disk = bytes(8192) + _disk(40, seed=11) + bytes(4096)    # band 0 is all zeros
    band = 8192
    path = _encrypted_bundle(tmp_path, disk, band)
    assert "0" not in os.listdir(os.path.join(path, "bands"))
    with ewfprobe.open_ewf(path, password=PASSWORD) as img:
        assert img.format == ewfprobe.FORMAT_SPARSEBUNDLE
        assert _read_all(img) == disk
        assert img.info()["encryption"]["cipher"] == "AES-256"
    with pytest.raises(ewfprobe.EwfWrongPasswordError, match="enc.sparsebundle"):
        ewfprobe.open_ewf(path, password="wrong")


@needs_crypto
def test_an_encrypted_band_cut_inside_a_block_is_refused(tmp_path):
    disk = _disk(48, seed=12)
    path = _encrypted_bundle(tmp_path, disk, 8192, cut=("1", 700))
    with pytest.raises(ewfprobe.EwfIncompleteSetError, match="band file 1 ends inside"):
        ewfprobe.open_ewf(path, password=PASSWORD)


@needs_crypto
def test_a_short_encrypted_band_reads_as_zeros_past_its_end(tmp_path):
    disk = _disk(32, seed=13)[:8192] + _disk(2, seed=14) + bytes(8192 - 1024)
    path = _encrypted_bundle(tmp_path, disk, 8192, cut=("1", 1024))
    with ewfprobe.open_ewf(path, password=PASSWORD) as img:
        assert _read_all(img) == disk


def test_a_malformed_token_is_refused(tmp_path):
    path = write_bundle(tmp_path / "enc.sparsebundle", _disk(8), 2048,
                        token=b"encrcdsa" + bytes(1000))
    assert ewfprobe.apple_image_kind(path) == "ENCRYPTED"
    with pytest.raises(ewfprobe.EwfFormatError, match="encrcdsa version 0"):
        ewfprobe.open_ewf(path, password=PASSWORD)


# -- the command line ------------------------------------------------------------

@pytest.fixture
def locked(tmp_path):
    disk = _disk(24, seed=21)
    return _write(tmp_path / "cli.dmg", encrcdsa(disk)), disk


@needs_crypto
def test_the_cli_takes_the_password_from_an_environment_variable(locked, monkeypatch,
                                                                  capsys):
    path, _disk_bytes = locked
    monkeypatch.setenv("EWFPROBE_TEST_PW", PASSWORD)
    assert ewfprobe.main(["info", "--password-env", "EWFPROBE_TEST_PW", path]) == 0
    out = capsys.readouterr().out
    assert "format          UDRW" in out
    assert "encryption      AES-128, encrcdsa version 2" in out
    assert PASSWORD not in out
    assert ewfprobe.main(["info", "--password-env", "NOT_SET_ANYWHERE_42", path]) == 2
    assert "NOT_SET_ANYWHERE_42 is not set" in capsys.readouterr().err


@needs_crypto
def test_the_cli_takes_the_password_from_the_first_line_of_a_file(locked, tmp_path):
    path, disk = locked
    pw = tmp_path / "pw.txt"
    pw.write_bytes(PASSWORD.encode() + b"\r\nsecond line\n")
    out = tmp_path / "disk.raw"
    assert ewfprobe.main(["export", "-q", "--password-file", str(pw), path,
                          "-o", str(out)]) == 0
    assert out.read_bytes() == disk


@needs_crypto
def test_the_cli_names_the_ways_to_give_a_password_when_it_cannot_ask(locked,
                                                                      monkeypatch, capsys):
    path, _disk_bytes = locked
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))       # not a terminal
    assert ewfprobe.main(["info", path]) == 2
    err = capsys.readouterr().err
    assert "--password-file or --password-env" in err


@needs_crypto
def test_the_cli_asks_at_a_terminal_and_asks_again_after_a_wrong_one(locked,
                                                                    monkeypatch, capsys):
    path, _disk_bytes = locked

    class Terminal(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(sys, "stdin", Terminal(""))
    answers = iter(["wrong", PASSWORD])
    monkeypatch.setattr(ewfprobe.getpass, "getpass", lambda prompt: next(answers))
    assert ewfprobe.main(["info", path]) == 0
    captured = capsys.readouterr()
    assert "that password does not open the image" in captured.err
    assert PASSWORD not in captured.out + captured.err

    monkeypatch.setattr(ewfprobe.getpass, "getpass", lambda prompt: "never")
    assert ewfprobe.main(["verify", "-q", path]) == 2
    assert "does not open cli.dmg" in capsys.readouterr().err


def test_the_cipher_package_a_job_installs_is_the_one_imported():
    """CI installs pycryptodome (module Crypto) in most jobs and pycryptodomex
    (module Cryptodome) in one, and names which in EWFPROBE_CRYPTO_PACKAGE."""
    expected = os.environ.get("EWFPROBE_CRYPTO_PACKAGE")
    if not expected:
        pytest.skip("EWFPROBE_CRYPTO_PACKAGE is not set")
    assert ewfprobe._AES is not None     # pylint: disable=protected-access
    assert ewfprobe._AES.__name__.split(".")[0] == expected  # pylint: disable=protected-access


@needs_crypto
def test_the_password_is_not_kept_once_the_image_is_open(tmp_path):
    secret = "keep-me-out-of-the-object"
    path = _write(tmp_path / "kept.dmg", encrcdsa(_disk(8), secret))
    with ewfprobe.open_ewf(path, password=secret) as img:
        seen = repr(vars(img)) + repr(img.info())
        assert secret not in seen and secret.encode() not in seen.encode()
        assert all(v is None or "AES-" in repr(v) for v in img._keys.values())  # pylint: disable=protected-access


@needs_crypto
def test_a_disk_that_is_not_whole_sectors_is_refused(tmp_path):
    path = _write(tmp_path / "odd.dmg", encrcdsa(_disk(4) + b"x" * 100))
    with pytest.raises(ewfprobe.EwfFormatError, match="not a whole number of 512-byte"):
        ewfprobe.open_ewf(path, password=PASSWORD)


def test_data_past_a_32_bit_block_number_is_refused(tmp_path):
    path = _write(tmp_path / "huge.dmg",
                  encrcdsa(_disk(4), data_length=(1 << 32) * 512 + 512) if AES else
                  HEADER.pack(b"encrcdsa", 2, 16, 5, 0x80000001, 128, 0x5B, 160,
                              bytes(16), 512, (1 << 32) * 512 + 512, 4096, 1)
                  + ITEM.pack(1, 96, 200) + bytes(4096))
    with pytest.raises(ewfprobe.EwfFormatError, match="32-bit block number"):
        ewfprobe.open_ewf(path, password=PASSWORD)

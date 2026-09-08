"""Tests against EWF files written by the reference implementation.

The fixtures under ``tests/fixtures`` were produced by ``ewfacquire`` from
libewf, driven by ``tools/make_fixtures.py``. They are bytes neither this
reader nor the test writer in ``test_ewfprobe.py`` produced, which is what makes
them worth having: they check the reader against the format as a different
program actually writes it, not against a second reading of the specification.

``manifest.json`` records the source image's own SHA-256 and the offset, length
and SHA-256 of every synthetic media file placed in it. Those are the known
answers, and they are also the known answers a carver will be measured against.

The content is generated, not evidence.
"""

import hashlib
import json
import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ewfprobe  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
MANIFEST_PATH = os.path.join(FIXTURES, "manifest.json")

pytestmark = pytest.mark.skipif(
    not os.path.exists(MANIFEST_PATH),
    reason="reference fixtures absent; run tools/make_fixtures.py tests/fixtures --small")


def _manifest():
    with open(MANIFEST_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _variants():
    man = _manifest()
    return [(name, v) for name, v in sorted(man["variants"].items())]


def _first(variant):
    return os.path.join(FIXTURES, variant["files"][0])


def _media_sha(img):
    h = hashlib.sha256()
    img.seek(0)
    while True:
        block = img.read(1 << 20)
        if not block:
            break
        h.update(block)
    return h.hexdigest()


@pytest.mark.parametrize("name,variant", _variants())
def test_every_variant_reproduces_the_source_exactly(name, variant):
    man = _manifest()
    with ewfprobe.open_ewf(_first(variant)) as img:
        assert img.media_size == man["size"], name
        assert img.sector_size == man["sector_size"], name
        assert _media_sha(img) == man["sha256"], name


@pytest.mark.parametrize("name,variant", _variants())
def test_every_variant_matches_its_own_stored_hash(name, variant):
    with ewfprobe.open_ewf(_first(variant)) as img:
        result = img.verify()
    assert result["stored"], f"{name} recorded no hash"
    assert result["match"] is True, name
    assert result["checksum_errors"] == [], name


@pytest.mark.parametrize("name,variant", _variants())
def test_the_known_media_is_where_the_manifest_says(name, variant):
    """Also the known-answer set a carver will be measured against."""
    man = _manifest()
    with ewfprobe.open_ewf(_first(variant)) as img:
        for item in man["media"]:
            img.seek(item["offset"])
            data = img.read(item["length"])
            assert hashlib.sha256(data).hexdigest() == item["sha256"], \
                f"{name}: {item['kind']} at {item['offset']}"


def test_the_older_encase5_table_layout_reads():
    """encase5 predates the 64-bit table base offset, so it exercises base 0."""
    variants = dict(_variants())
    assert "encase5-fast" in variants, "the encase5 fixture is missing"
    with ewfprobe.open_ewf(_first(variants["encase5-fast"])) as img:
        assert _media_sha(img) == _manifest()["sha256"]
        assert {t.base for t in img._tables} == {0}, \
            "encase5 should carry no table base offset"


def test_the_split_fixture_is_genuinely_multi_segment():
    variants = dict(_variants())
    split = variants["encase6-split"]
    assert len(split["files"]) >= 3, "the split fixture did not actually split"
    with ewfprobe.open_ewf(_first(split)) as img:
        assert len(img.paths) == len(split["files"])
        # a read that crosses from one segment file into the next
        boundary = next(t.first_chunk * img.chunk_size
                        for t in img._tables if t.segment == 1)
        img.seek(boundary - 4096)
        spanning = img.read(8192)
    with ewfprobe.open_ewf(_first(variants["encase6-fast"])) as whole:
        whole.seek(boundary - 4096)
        assert spanning == whole.read(8192)


def test_a_missing_segment_of_a_real_set_is_refused(tmp_path):
    variants = dict(_variants())
    split = variants["encase6-split"]
    for name in split["files"]:
        shutil.copy(os.path.join(FIXTURES, name), tmp_path / name)
    os.remove(tmp_path / split["files"][-1])
    with pytest.raises(ewfprobe.EwfIncompleteSetError):
        ewfprobe.open_ewf(str(tmp_path / split["files"][0]))


def test_metadata_written_by_ewfacquire_is_read_back():
    variants = dict(_variants())
    with ewfprobe.open_ewf(_first(variants["encase6-fast"])) as img:
        meta = img.metadata
    assert meta.get("case_number") == "FIXTURE"
    assert "ewfprobe fixture" in meta.get("description", "")

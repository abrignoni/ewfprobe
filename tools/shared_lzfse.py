"""The LZFSE and LZVN decoder ewfprobe.py and qnxprobe.py share, kept byte-identical.

qnxprobe.py is where the decoder is maintained: it was written there, from Apple's
reference implementation (github.com/lzfse/lzfse at commit
e634ca58b4821d9f3d560cdc6df5dec02ffc93fd), for macOS file compression (decmpfs), and
ewfprobe.py carries a copy for LZFSE-compressed Apple disk images (ULFO), taken from
qnxprobe v1.74 (tag v1.74, commit dffd27ab242c16100b40114f248e816fb302cc52). A fix lands
in qnxprobe.py first and is then copied here, so this file names the two pieces of
source that must match and checks them:

    python tools/shared_lzfse.py digest ewfprobe.py
    python tools/shared_lzfse.py check ewfprobe.py /path/to/qnxprobe.py
    python tools/shared_lzfse.py sync /path/to/qnxprobe.py ewfprobe.py

The pieces are found by name, not by line number: the DecompressError class through
the end of _copy_match, and the "# LZVN opcode kinds" comment through the end of
lzfse_decompress. ``check`` exits 1 when they differ, ``sync`` replaces the pieces in
the second file with those of the first, and ``digest`` prints the SHA-256 that
tests/test_lzfse.py pins, so an edit made to ewfprobe.py's copy alone fails the tests.
Standard library only.
"""

import ast
import hashlib
import sys

FIRST = ("class DecompressError(Exception):", "_copy_match")
SECOND = ("# LZVN opcode kinds,", "lzfse_decompress")


def _piece(text, start_marker, last_def):
    """(start, end) character offsets of the piece of ``text`` that begins at the
    line starting with ``start_marker`` and ends with the top-level definition
    ``last_def``, both of which must appear exactly once."""
    lines = text.split("\n")
    starts = [i for i, line in enumerate(lines) if line.startswith(start_marker)]
    if len(starts) != 1:
        raise ValueError(f"{start_marker!r} begins {len(starts)} lines, not one")
    defs = [node for node in ast.parse(text).body
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == last_def]
    if len(defs) != 1:
        raise ValueError(f"{last_def} is defined {len(defs)} times at the top level, not once")
    first, last = starts[0], defs[0].end_lineno - 1
    if last < first:
        raise ValueError(f"{last_def} ends before {start_marker!r}")
    begin = sum(len(line) + 1 for line in lines[:first])
    end = sum(len(line) + 1 for line in lines[:last + 1]) - 1
    return begin, end


def pieces(text):
    """The two shared pieces of ``text``, as strings."""
    return [text[slice(*_piece(text, *spec))] for spec in (FIRST, SECOND)]


def digest(text):
    """SHA-256 of the two pieces, each followed by a newline."""
    h = hashlib.sha256()
    for piece in pieces(text):
        h.update(piece.encode("utf-8") + b"\n")
    return h.hexdigest()


def _read(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


def main(argv):
    if len(argv) == 2 and argv[0] == "digest":
        print(digest(_read(argv[1])))
        return 0
    if len(argv) == 3 and argv[0] == "check":
        a, b = _read(argv[1]), _read(argv[2])
        if pieces(a) == pieces(b):
            print(f"identical: {digest(a)}")
            return 0
        print(f"the shared LZFSE decoder differs: {argv[1]} {digest(a)}, "
              f"{argv[2]} {digest(b)}")
        return 1
    if len(argv) == 3 and argv[0] == "sync":
        source, target = _read(argv[1]), _read(argv[2])
        new = pieces(source)
        # Replace the later piece first so the earlier piece's offsets still hold.
        spans = sorted(((_piece(target, *spec), text) for spec, text in
                        zip((FIRST, SECOND), new)), reverse=True)
        for (begin, end), text in spans:
            target = target[:begin] + text + target[end:]
        with open(argv[2], "w", encoding="utf-8", newline="") as fh:
            fh.write(target)
        print(f"copied: {digest(target)}")
        return 0
    print(__doc__.strip().split("\n\n")[1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

# ewfprobe

A read-only reader for EnCase/EWF (`.E01`) forensic images. One file, pure
Python, standard library only. No compiler, no network, nothing to install.

It presents the acquired disk as an ordinary seekable file object, so anything
that can read a raw image can read an E01 without changing how it reads.

MIT licensed and written from the public format documentation.

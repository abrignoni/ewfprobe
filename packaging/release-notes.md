ewfprobe {{VERSION}}: standalone executables of `ewfprobe.py`, built by this repository's own GitHub Actions workflow from the tagged commit.

- `ewfprobe-{{VERSION}}-windows-x64.zip` runs on Intel and AMD PCs, and on Windows on ARM through its x64 emulation.
- `ewfprobe-{{VERSION}}-windows-arm64.zip` is native for Windows on ARM.
- `ewfprobe-{{VERSION}}-macos-arm64.zip` for Apple silicon Macs, `ewfprobe-{{VERSION}}-macos-x64.zip` for Intel Macs.
- `ewfprobe-{{VERSION}}-linux-x64.tar.gz` and `ewfprobe-{{VERSION}}-linux-arm64.tar.gz`, built on Ubuntu 22.04 so they run on distributions with a glibc at least that old.
- `ewfprobe.py`, the tagged source file itself.

It reads EnCase/EWF `.E01`, SMART `.s01`, EnCase 7 `.Ex01`, AFF, as an `.aff` file or an `.afd` folder, AFF4 `.aff4`, and Apple `.dmg` (including one split into `.dmgpart` files), `.sparseimage` and `.sparsebundle` images as a disk image, and lists and reads the files in an EnCase `.L01` and an FTK Imager `.ad1`. An Apple disk image encrypted with a password (AES-128 or AES-256), and an E01, SMART, raw or AD1 set FTK Imager encrypted with AD encryption, opens with that password, which the executables ask for or take from `--password-file` or `--password-env`. An LZFSE-compressed `.dmg` needs the optional `pyliblzfse` package, which the executables do not include.

Each archive holds the command line tool, `README.txt`, `LICENSE` and `SHA256SUMS.txt`. `SHA256SUMS.txt` beside the archives covers the archives and `ewfprobe.py`. Before it was attached, each executable was run on the repository's reference images: E01, SMART and Ex01 images written by libewf's `ewfacquire`, E01 and SMART images written by FTK Imager, AFF files and AFD folders written by AFFLIB's `affconvert` and by FTK Imager, Apple disk images written by `hdiutil`, encrypted ones among them, an L01 written by EnCase, AFF4 containers written by pyaff4 and by the repository's fixture tool, and AD1s written by FTK Imager, one of them AD-encrypted. It printed the same output as `python ewfprobe.py`, verified the stored hashes where an image records them, exported a disk matching the source disk's SHA-256, listed and exported the L01's entries matching answers taken from libewf, matched the hashes FTK Imager logged for each AD1 and the content written to an entry of it, decrypted each encrypted image to the disk `hdiutil attach` read from it and refused a wrong password, and refused a set with a segment missing and an LZFSE `.dmg` it cannot decompress.

None of the executables is code signed: Windows SmartScreen and macOS Gatekeeper will each ask once, and the README inside says what to do. Unzip to a local folder rather than running from a network share.

`ewfprobe.py` needs nothing built: `python3 ewfprobe.py` works on macOS, Linux and Windows with the standard library alone, and reads encrypted Apple disk images once `pycryptodome` is installed. See the README for what it reads.

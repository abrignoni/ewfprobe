ewfprobe, built as a standalone executable
==========================================

  ewfprobe            the command line tool (ewfprobe.exe on Windows). Open a
                      terminal in this folder and run, for example:
                          ewfprobe info   image.E01
                          ewfprobe verify image.E01
                          ewfprobe export image.E01 -o image.raw
                          ewfprobe files  evidence.L01
                          ewfprobe export evidence.L01 --entry "Folder/a.jpg" -o a.jpg
                          ewfprobe --help
                      On Windows write ewfprobe.exe; on macOS and Linux write
                      ./ewfprobe from this folder. It reads .E01, .s01, .Ex01,
                      .aff and .afd disk images, and the files in an .L01. For
                      a split set, keep every segment (.E01, .E02, ...) in one
                      folder and name the first.

  SHA256SUMS.txt      the hash of the executable as built. Check it with
                          certutil -hashfile ewfprobe.exe SHA256     (Windows)
                          shasum -a 256 -c SHA256SUMS.txt            (macOS)
                          sha256sum -c SHA256SUMS.txt                (Linux)

It opens the image read-only and never writes to it. It installs nothing and
needs no administrator rights. It is built from ewfprobe.py in
https://github.com/abrignoni/ewfprobe by the repository's own GitHub Actions
workflow, and is not code signed:

  Windows   SmartScreen may ask once before running it. Unzip to a local
            folder rather than running from a network share.
  macOS     Gatekeeper will refuse a downloaded, unsigned program on first
            run. Right-click (Control-click) ewfprobe in Finder and choose
            Open, once, or remove the quarantine mark from this folder:
                xattr -dr com.apple.quarantine .
  Linux     mark the file executable if the archive did not keep the bit:
                chmod +x ewfprobe

Builds: windows-x64, windows-arm64 (native for Windows on ARM; the x64 build
also runs there through emulation), macos-arm64 (Apple silicon), macos-x64
(Intel), linux-x64, linux-arm64.

# Third-party distribution notices

EvidenceMesh's original source files retain their MIT license. Bundled components
retain their own licenses; the installer as a whole is not described as MIT-only.
Full notices are installed under `resources/third-party-licenses` and TShark's
GPL text is also under `resources/tshark/COPYING.txt`.

Each release includes `EvidenceMesh.CorrespondingSource.0.4.0.zip`, available next
to the installer at <https://github.com/Kowntaewook/evidence-mesh/releases/tag/v0.4.0>.
It contains EvidenceMesh source, Python dependency source distributions, upstream
TShark source, library sources, MSYS2 source packages with patches/PKGBUILDs, and
the Wireshark/vcpkg build recipes. `SOURCES.json` records exact URLs, versions and
SHA-256 values; `packaging/tshark.lock.json` pins the native inputs. A release job
must upload this archive successfully before publishing the release.

| Component | Terms / distribution notes |
|---|---|
| Wireshark/TShark 4.6.8 and its three libraries | GPL-2.0-or-later; unmodified upstream Windows binaries, corresponding source supplied |
| GLib 2.86.3, GNU libiconv, GNU gettext runtime, libgcrypt 1.12.2, libgpg-error, GnuTLS 3.8.13, libtasn1 | LGPL; exact versions/build patches are in the source inventory |
| GMP / Nettle | LGPL/GPL alternatives in their upstream notices; shared libraries remain replaceable |
| Brotli, c-ares, Kerberos, Lua, libffi, libxml2, PCRE2/SLJIT, p11-kit, libsmi, LZ4, nghttp2/3, Snappy, xxHash, zlib/zlib-ng, Zstandard | MIT/BSD/zlib or upstream notice terms; notices and source included |
| Dissect NTFS, REGF, cstruct and util | AGPL-3.0-or-later; complete dependency and application source supplied; retain AGPL notices and obligations when redistributing the combined backend |
| Volatility 3 | Volatility Software License; exact license text and source supplied, including its attribution requirements |
| python-evtx and other Python libraries | Their individual installed distribution notices and matching source distributions |
| Python | PSF license and included third-party notices |
| PyInstaller bootloader | GPL with PyInstaller's distribution exception; license and source included |
| Electron / Chromium / Node.js | Electron MIT and Chromium/Node third-party notices included |
| Microsoft VC runtime DLLs | Unmodified Microsoft redistributable runtime, not covered by the project's MIT license or by the corresponding-source offer |

The TShark bundle includes only its offline dependency closure and data files.
It excludes the Wireshark GUI, Npcap, live capture helpers and optional external
plugins. The dynamically linked LGPL DLLs are ordinary files, not embedded in an
encrypted container; users can replace compatible versions. EvidenceMesh imposes
no additional restriction on modification or reverse engineering for debugging
such modifications. Rebuilding the backend and installer is documented in
`WINDOWS_PACKAGING.md`; no signing key is needed for an unsigned local rebuild.

Microsoft's [redistribution list](https://learn.microsoft.com/en-us/visualstudio/releases/2026/redistribution)
and applicable Visual Studio terms govern the VC runtime. These files are kept
unmodified and no Microsoft compiler, SDK, debug runtime or capture driver is
redistributed. Distributors must retain the upstream component terms.

Authoritative license texts in the source archives and installed notices control
over the summary above. License acquisition failures are build failures, not a
reason to omit notices or publish a binary-only release.

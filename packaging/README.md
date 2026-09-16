# Windows distribution inputs

`backend.spec` collects the Python modules, plugin modules, metadata and data files
used by the installed application. `tshark.lock.json` pins upstream archives and
the minimal offline TShark dependency set. Acquisition verifies hashes before
unpacking and produces a binary inventory. No capture driver or Wireshark GUI is
installed. Corresponding sources and notices accompany the release.

The Windows workflow tests the installed executables with a restricted PATH;
development smoke tests do not establish Windows packaging success.

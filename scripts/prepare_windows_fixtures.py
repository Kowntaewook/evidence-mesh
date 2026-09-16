"""Generate inert packaged-E2E inputs and acquire hash-pinned public disk samples."""

import json
import runpy

from acquire_tshark import ROOT, acquire


def main():
    output = ROOT / "data/windows-fixtures"
    output.mkdir(parents=True, exist_ok=True)
    sources = json.loads((ROOT / "packaging/compatibility-fixtures.json").read_text())
    public = ROOT / "data/compatibility"
    for item in sources:
        acquire({**item, "name": item["file"]}, public)
    (public / "sources.json").write_text(json.dumps(sources, indent=2), encoding="utf-8")
    formats = runpy.run_path(str(ROOT / "tests/test_disk_formats_v04.py"))
    for version in [2, 3, 4]:
        (output / f"usn-v{version}.bin").write_bytes(formats["usn_record"](version))
    for version in [17, 23, 26, 30, 31]:
        (output / f"compressed-v{version}.pf").write_bytes(
            formats["mam_literals"](formats["prefetch_bytes"](version))
        )
    disk = runpy.run_path(str(ROOT / "tests/test_disk_images_v04.py"))
    (output / "inert-ntfs.img").write_bytes(disk["ntfs_volume"]())
    network = runpy.run_path(str(ROOT / "tests/test_network_v04.py"))
    body = network["tls_capture"](output / "encrypted.pcapng", output / "supplied-keys.log")
    (output / "body.bin").write_bytes(body)
    (output / "invalid-memory.raw").write_bytes(b"Inert invocation fixture. Not a memory image.\n" * 1024)
    print(f"Prepared inert fixtures and {len(sources)} public artifacts")


if __name__ == "__main__":
    main()

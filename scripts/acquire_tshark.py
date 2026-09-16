"""Acquire an immutable offline TShark runtime; no installer is executed."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def acquire(item, cache):
    path = cache / item["name"]
    cache.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        temporary = path.with_name(path.name + ".part")
        request = urllib.request.Request(item["url"], headers={"User-Agent": "EvidenceMesh-build/0.4"})
        with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as output:
            shutil.copyfileobj(response, output)
        temporary.replace(path)
    if sha256(path) != item["sha256"]:
        raise ValueError(f"Archive hash mismatch: {path.name}; delete the cache entry and retry")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / "data" / "vendor")
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "tshark")
    args = parser.parse_args()
    lock = json.loads((ROOT / "packaging" / "tshark.lock.json").read_text())
    archive = acquire(lock["binary"], args.cache)
    unpacked = args.cache / ("portable-" + lock["version"])
    sevenzip = shutil.which("7z") or str(
        Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "7-Zip/7z.exe"
    )
    if not (unpacked / "App/Wireshark/tshark.exe").is_file():
        subprocess.run(
            [sevenzip, "x", "-y", "-o" + str(unpacked), str(archive)], check=True, stdout=subprocess.DEVNULL
        )
    original = unpacked / "App/Wireshark"
    destination = args.output
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for filename in lock["files"] + lock["data_files"]:
        shutil.copy2(original / filename, destination / filename)
    for directory in lock["data_directories"]:
        shutil.copytree(original / directory, destination / directory)

    # Validate direct and delayed PE imports; fail rather than depending on a
    # developer's PATH or silently adding an unreviewed DLL to the distribution.
    import pefile

    allowed = set(lock["files"]) | set(lock["os_dlls"])
    for filename in lock["files"]:
        with pefile.PE(str(destination / filename)) as binary:
            imports = getattr(binary, "DIRECTORY_ENTRY_IMPORT", [])
            imports += getattr(binary, "DIRECTORY_ENTRY_DELAY_IMPORT", [])
            unknown = {entry.dll.decode().lower() for entry in imports} - allowed
            if unknown:
                raise ValueError(f"Unreviewed dependency in {filename}: {sorted(unknown)}")
    inventory = {
        "version": lock["version"],
        "upstream": lock["binary"],
        "files": {
            str(p.relative_to(destination)).replace("\\", "/"): sha256(p)
            for p in sorted(destination.rglob("*"))
            if p.is_file()
        },
        "live_capture": False,
        "external_plugins": False,
    }
    (destination / "BUNDLE.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    print(f"Verified TShark {lock['version']}: {len(lock['files'])} PE files, {destination}")


if __name__ == "__main__":
    main()

"""Bundle corresponding sources, build recipes, licenses and installed versions."""

import argparse
import importlib.metadata
import io
import json
import re
import shutil
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

from acquire_tshark import ROOT, acquire, sha256


def license_name(name):
    return bool(re.match(r"^(copying|copyright|licen[cs]e|notice|authors)([._-].*)?$", Path(name).name, re.I))


def collect_notices(archive, directory, depth=0):
    """Read archive entries without executing build scripts or extracting paths."""
    directory.mkdir(parents=True, exist_ok=True)
    seen = set()

    def save(name, content):
        if len(content) > 512_000 or b"\0" in content:
            return
        digest = __import__("hashlib").sha256(content).hexdigest()
        if digest in seen:
            return
        seen.add(digest)
        target = re.sub(r"[^A-Za-z0-9._-]", "_", name)[-150:]
        (directory / (digest[:12] + "-" + target)).write_bytes(content)

    if isinstance(archive, Path) and archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as bundle:
            for item in bundle.infolist():
                if license_name(item.filename) and item.file_size <= 512_000:
                    save(item.filename, bundle.read(item))
        return
    stream = None
    if isinstance(archive, Path) and archive.suffix == ".zst":
        import zstandard

        stream = zstandard.ZstdDecompressor().stream_reader(archive.open("rb"))
        bundle = tarfile.open(fileobj=stream, mode="r|")
    elif isinstance(archive, Path):
        bundle = tarfile.open(archive)
    else:
        bundle = tarfile.open(fileobj=io.BytesIO(archive))
    try:
        with bundle:
            for member in bundle:
                if not member.isfile():
                    continue
                if license_name(member.name) and member.size <= 512_000:
                    save(member.name, bundle.extractfile(member).read())
                elif (
                    depth < 1
                    and member.size < 80_000_000
                    and member.name.endswith((".tar.gz", ".tar.xz", ".tar.bz2"))
                ):
                    collect_notices(bundle.extractfile(member).read(), directory, depth + 1)
    finally:
        if stream:
            stream.close()


def python_distributions():
    from packaging.requirements import Requirement

    pending = [
        "fastapi",
        "pydantic",
        "uvicorn",
        "tzdata",
        "volatility3",
        "python-evtx",
        "dissect.ntfs",
        "dissect.regf",
        "pyinstaller",
    ]
    found = {}
    while pending:
        name = pending.pop()
        distribution = importlib.metadata.distribution(name)
        normalized = distribution.metadata["Name"].lower().replace("_", "-")
        if normalized in found:
            continue
        found[normalized] = distribution
        for value in distribution.requires or []:
            requirement = Requirement(value)
            if requirement.marker is None or requirement.marker.evaluate({"extra": ""}):
                pending.append(requirement.name)
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / "data/vendor/sources")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/corresponding-source")
    parser.add_argument("--licenses", type=Path, default=ROOT / "dist/third-party-licenses")
    parser.add_argument("--tshark-only", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    args.licenses.mkdir(parents=True, exist_ok=True)
    lock = json.loads((ROOT / "packaging/tshark.lock.json").read_text())
    assert len(lock["sources"]) >= 35, "Corresponding source inventory is incomplete"
    inventory = []
    for item in lock["sources"]:
        original = acquire(item, args.cache)
        shutil.copy2(original, args.output / original.name)
        collect_notices(original, args.licenses / original.name)
        inventory.append(item)
    if not args.tshark_only:
        for name, distribution in sorted(python_distributions().items()):
            with urllib.request.urlopen(
                f"https://pypi.org/pypi/{name}/{distribution.version}/json", timeout=60
            ) as response:
                metadata = json.load(response)
            source = next((item for item in metadata["urls"] if item["packagetype"] == "sdist"), None)
            if source is None:
                raise ValueError(f"Source distribution unavailable for {name} {distribution.version}")
            item = {
                "name": source["filename"],
                "url": source["url"],
                "sha256": source["digests"]["sha256"],
                "component": name,
                "version": distribution.version,
                "license": metadata["info"].get("license_expression") or metadata["info"].get("license"),
            }
            original = acquire(item, args.cache)
            shutil.copy2(original, args.output / original.name)
            notices = args.licenses / name
            collect_notices(original, notices)
            for file in distribution.files or []:
                if license_name(str(file)) and file.locate().is_file():
                    notices.mkdir(exist_ok=True)
                    shutil.copy2(file.locate(), notices / file.name)
            inventory.append(item)
        python_notice = Path(sys.base_prefix) / "LICENSE.txt"
        if python_notice.exists():
            shutil.copy2(python_notice, args.licenses / "Python-LICENSE.txt")
        for filename in ["LICENSE", "LICENSES.chromium.html"]:
            source = ROOT / "desktop/node_modules/electron/dist" / filename
            if not source.is_file():
                raise ValueError(f"Electron license missing: {source}")
            shutil.copy2(source, args.licenses / ("Electron-" + filename))
    shutil.copy2(ROOT / "LICENSE", args.licenses / "EvidenceMesh-MIT.txt")
    shutil.copy2(ROOT / "docs/THIRD_PARTY_LICENSES.md", args.licenses / "README.md")
    shutil.copy2(ROOT / "packaging/tshark.lock.json", args.output / "tshark.lock.json")
    (args.output / "SOURCES.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    shutil.copy2(args.output / "SOURCES.json", args.licenses / "SOURCES.json")
    (args.licenses / "SHA256SUMS.txt").write_text(
        "\n".join(
            f"{sha256(p)}  {p.relative_to(args.licenses).as_posix()}"
            for p in sorted(args.licenses.rglob("*"))
            if p.is_file() and p.name != "SHA256SUMS.txt"
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Verified {len(inventory)} source archives and collected notices in {args.licenses}")


if __name__ == "__main__":
    main()

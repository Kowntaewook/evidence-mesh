"""Only assemble release assets after the installed Windows E2E passes."""

import json
import shutil
import subprocess
import zipfile

from acquire_tshark import ROOT, sha256


def main():
    version = (ROOT / "VERSION").read_text().strip()
    report = ROOT / "data/windows-e2e/report.json"
    results = json.loads(report.read_text())
    assert results["platform"] == "win32" and results["status"] == "PASS", results
    destination = ROOT / "dist/release-assets"
    destination.mkdir(parents=True, exist_ok=True)
    installer = ROOT / f"desktop/release-installer/EvidenceMesh.Setup.{version}.exe"
    shutil.copy2(installer, destination / installer.name)
    shutil.copy2(report, destination / "Windows-E2E.json")
    source = ROOT / "dist/corresponding-source"
    project = source / f"EvidenceMesh-{version}-source.zip"
    subprocess.run(["git", "archive", "--format=zip", "--output", str(project), "HEAD"], cwd=ROOT, check=True)
    with zipfile.ZipFile(destination / f"EvidenceMesh.CorrespondingSource.{version}.zip", "w") as archive:
        for directory, prefix in [(source, "sources"), (ROOT / "dist/third-party-licenses", "licenses")]:
            for item in sorted(directory.rglob("*")):
                if item.is_file():
                    archive.write(item, prefix + "/" + item.relative_to(directory).as_posix())
    (destination / "SHA256SUMS.txt").write_text(
        "\n".join(
            f"{sha256(p)}  {p.name}" for p in sorted(destination.iterdir()) if p.name != "SHA256SUMS.txt"
        )
        + "\n",
        encoding="utf-8",
    )
    print((destination / "SHA256SUMS.txt").read_text())


if __name__ == "__main__":
    main()

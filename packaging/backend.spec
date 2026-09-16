# Run from the repository root: pyinstaller --noconfirm --clean packaging/backend.spec
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_data_files, copy_metadata

root = Path(SPECPATH).parent
datas = []
binaries = []
hiddenimports = []
for package in (
    "engine", "schemas", "samples", "uvicorn", "tzdata", "volatility3", "Evtx",
    "dissect.ntfs", "dissect.regf", "dissect.cstruct", "dissect.util",
):
    package_data, package_binaries, package_imports = collect_all(package)
    datas += package_data
    binaries += package_binaries
    hiddenimports += package_imports
for distribution in (
    "fastapi", "uvicorn", "tzdata", "volatility3", "python-evtx", "dissect.ntfs",
    "dissect.regf", "dissect.cstruct", "dissect.util",
):
    datas += copy_metadata(distribution)
datas += collect_data_files("samples") + collect_data_files("schemas")
a = Analysis(
    [str(root / "api" / "launcher.py")], pathex=[str(root)], binaries=binaries,
    datas=datas, hiddenimports=hiddenimports, hookspath=[], hooksconfig={},
    runtime_hooks=[], excludes=["tkinter", "pytest", "IPython"], noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [], exclude_binaries=True, name="evidencemesh-backend",
    debug=False, bootloader_ignore_signals=False, strip=False, upx=False, console=True,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="evidencemesh-backend")

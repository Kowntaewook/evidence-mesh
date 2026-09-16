"""Canonical export contracts and installed CLI discovery; no Volatility imports."""

import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path


@dataclass(frozen=True)
class PluginSpec:
    name: str
    class_name: str
    aliases: tuple[str, ...] = ()

    def matches(self, value: str) -> bool:
        names = (self.name, *self.aliases)
        return value.casefold() in {
            item.casefold() for name in names for item in (name, f"{name}.{self.class_name}")
        }


SPECS = (
    PluginSpec("windows.pslist", "PsList"),
    PluginSpec("windows.pstree", "PsTree"),
    PluginSpec("windows.cmdline", "CmdLine"),
    PluginSpec("windows.netscan", "NetScan"),
    PluginSpec("windows.dlllist", "DllList"),
    PluginSpec("windows.psscan", "PsScan"),
    PluginSpec("windows.envars", "Envars"),
    PluginSpec("windows.handles", "Handles"),
    PluginSpec("windows.filescan", "FileScan"),
    PluginSpec("windows.vadinfo", "VadInfo"),
    PluginSpec("windows.malware.malfind", "Malfind", ("windows.malfind",)),
    PluginSpec("windows.svcscan", "SvcScan"),
    PluginSpec("windows.svclist", "SvcList"),
    PluginSpec("windows.registry.amcache", "Amcache", ("windows.amcache",)),
    PluginSpec("windows.registry.userassist", "UserAssist", ("windows.userassist",)),
    PluginSpec("windows.shimcachemem", "ShimcacheMem", ("windows.registry.shimcache",)),
    PluginSpec("windows.modules", "Modules"),
    PluginSpec("windows.modscan", "ModScan"),
    PluginSpec("windows.driverscan", "DriverScan"),
    PluginSpec("windows.callbacks", "Callbacks"),
    PluginSpec("windows.dumpfiles", "DumpFiles"),
)


def canonical_plugin(value: str) -> str:
    for spec in SPECS:
        if spec.matches(value):
            return spec.name
    raise ValueError(f"Unsupported Volatility export plugin: {value}")


def filename_plugin(stem: str) -> str:
    if stem.startswith("windows."):
        return canonical_plugin(stem)
    for spec in SPECS:
        if stem.casefold() in {spec.name.rsplit(".", 1)[-1], spec.class_name.casefold()}:
            return spec.name
    return canonical_plugin(f"windows.{stem}")


def discover_plugins(
    executable: str | None = None, timeout: float = 30, command: list[str] | None = None
) -> dict:
    binary = executable or shutil.which("vol") or shutil.which("volatility3")
    if not binary and (Path(sys.executable).parent / "vol").is_file():
        binary = str(Path(sys.executable).parent / "vol")
    if command:
        binary = command[0]
        command = [*command, "--help"]
    else:
        command = [binary, "--help"] if binary else []
    error, stderr, output = None, "", ""
    if not binary:
        error = "Volatility executable not installed; export parsing remains available"
    else:
        try:
            process = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
            stderr, output = process.stderr, process.stdout
            if process.returncode:
                error = f"Volatility discovery exited {process.returncode}"
        except (OSError, subprocess.TimeoutExpired) as exc:
            error = str(exc)
    found = set(re.findall(r"\bwindows\.[A-Za-z0-9_.]+", output)) if not error else set()
    plugins = []
    for spec in SPECS:
        names = sorted(name for name in found if spec.matches(name))
        plugins.append(
            {
                "plugin": spec.name,
                "supported": True,
                "available": bool(names),
                "installed_names": names,
                "status": "SUCCESS" if names else "UNAVAILABLE",
            }
        )
    version = re.search(r"Volatility(?: 3)? Framework\s+([\d.]+)", output + stderr)
    found_version = version.group(1) if version else None
    if not found_version and binary and Path(binary).resolve().parent == Path(sys.executable).parent:
        try:
            found_version = package_version("volatility3")
        except PackageNotFoundError:
            pass
    return {
        "executable": binary,
        "version": found_version,
        "plugins": plugins,
        "error": error,
        "stderr": stderr,
        "command": command,
    }

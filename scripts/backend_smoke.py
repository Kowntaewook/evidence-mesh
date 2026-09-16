"""Exercise the actual frozen backend before putting it into an installer."""

import argparse
import json
import os
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--tshark", type=Path, required=True)
    args = parser.parse_args()
    executable, tshark = args.executable.resolve(), args.tshark.resolve()
    with tempfile.TemporaryDirectory(prefix="evidencemesh-frozen-") as directory:
        env = {
            **os.environ,
            "EVIDENCEMESH_WORKSPACE": directory,
            "EVIDENCEMESH_DB": str(Path(directory) / "smoke.sqlite3"),
            "EVIDENCEMESH_TSHARK": str(tshark),
            "PATH": str(Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32"),
        }
        result = subprocess.run(
            [str(executable), "--self-test"], env=env, check=True, capture_output=True, text=True, timeout=90
        )
        status = json.loads(result.stdout)
        assert status["backend"]["embedded"] and status["tshark"]["embedded"], status
        assert all(value["status"] == "OK" for value in status["components"].values()), status
        assert status["tshark"]["status"] == "OK" and all(v == "OK" for v in status["data"].values()), status
        discovery = subprocess.run(
            [str(executable), "--volatility", "--help"], env=env, capture_output=True, text=True, timeout=120
        )
        assert discovery.returncode == 0, discovery.stderr
        for plugin in ["windows.pslist", "windows.netscan", "windows.callbacks", "windows.modules"]:
            assert plugin in discovery.stdout, plugin + " not discoverable"
        process = subprocess.Popen(
            [str(executable), "--parent-pipe"],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            # The outer CI step has a timeout as a final guard for startup before
            # stdout; installed application E2E also has a bounded launch wait.
            address = json.loads(process.stdout.readline())
            assert address["host"] == "127.0.0.1" and address["type"] == "backend-address"
            url = f"http://127.0.0.1:{address['port']}/health"
            for _attempt in range(100):
                try:
                    with urllib.request.urlopen(url, timeout=1) as response:
                        health = json.load(response)
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("Frozen backend health timeout")
            assert health["version"] == status["version"]
            assert (Path(directory) / "smoke.sqlite3").is_file()
            process.stdin.write("quit\n")
            process.stdin.flush()
            assert process.wait(timeout=15) == 0
            print(
                json.dumps(
                    {
                        "health": health,
                        "dependencies": status,
                        "plugin_discovery": "PASS",
                        "shutdown": "PASS",
                    },
                    indent=2,
                )
            )
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()

"""Packaged entry point and isolated Volatility worker entry point."""

import argparse
import json
import logging
import multiprocessing
import os
import socket
import sys
import threading


def main():
    multiprocessing.freeze_support()
    if len(sys.argv) > 1 and sys.argv[1] == "--volatility":
        from volatility3.cli import main as volatility_main

        sys.argv = [sys.argv[0], *sys.argv[2:]]
        volatility_main()
        return

    from engine.runtime import configure_logging, dependency_status, workspace_root
    from engine.version import VERSION

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--parent-pipe", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps(dependency_status()), flush=True)
        return
    from engine.processes import contain_windows_children

    contain_windows_children()
    if not 0 <= args.port <= 65535:
        parser.error("port must be between 0 and 65535")
    root = workspace_root()
    root.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("EVIDENCEMESH_DB", str(root / "evidencemesh.sqlite3"))
    logfile = configure_logging()
    logger = logging.getLogger("evidencemesh")
    import uvicorn

    from api.main import create_app

    # Keep the reserved socket open through Uvicorn startup: no free-port race.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", args.port))
        listener.listen(128)
        server = uvicorn.Server(uvicorn.Config(create_app(), log_level="warning", access_log=False))
        if args.parent_pipe:

            def watch_parent():
                try:
                    sys.stdin.buffer.readline()
                finally:
                    server.should_exit = True

            threading.Thread(target=watch_parent, daemon=True).start()
        port = listener.getsockname()[1]
        print(
            json.dumps(
                {
                    "type": "backend-address",
                    "host": "127.0.0.1",
                    "port": port,
                    "pid": os.getpid(),
                    "version": VERSION,
                }
            ),
            flush=True,
        )
        logger.info("backend startup version=%s port=%s log=%s", VERSION, port, logfile)
        try:
            server.run(sockets=[listener])
        finally:
            logger.info("backend shutdown")


if __name__ == "__main__":
    main()

from engine.correlation.base import reason
from engine.normalization.windows import basename, command_tokens, path_key
from schemas.events import Event
from schemas.results import Reason


class FileRule:
    def evaluate(self, left: Event, right: Event) -> list[Reason]:
        results = []
        a, b = left.file, right.file
        if a and b:
            ah = a.sha256 or (left.hash.sha256 if left.hash else None)
            bh = b.sha256 or (right.hash.sha256 if right.hash else None)
            if ah and bh and ah != bh:
                return []
            if ah and bh and ah == bh:
                results.append(reason("same_sha256", 60, ah, "file.sha256", "hash.sha256"))
            if a.path and b.path and path_key(a.path) == path_key(b.path):
                results.append(reason("same_file_path", 45, a.path, "file.path"))
            elif basename(a.path or a.name) and basename(a.path or a.name) == basename(b.path or b.name):
                results.append(reason("same_filename", 10, basename(a.path or a.name), "file.name"))
        for origin, target in ((left, right), (right, left)):
            if not target.file:
                continue
            path = path_key(target.file.path)
            name = basename(target.file.path or target.file.name)
            tokens = command_tokens(origin.process.command_line if origin.process else None)
            if path and path in tokens:
                results.append(
                    reason(
                        "command_line_file_path",
                        50,
                        target.file.path or path,
                        "process.command_line",
                        "file.path",
                    )
                )
            elif name and name in tokens:
                # The launcher basename cannot override a known different executable path.
                known_launcher = (
                    origin.process and origin.process.path and basename(origin.process.path) == name
                )
                if not (known_launcher and path and path_key(origin.process.path) != path):
                    results.append(
                        reason("command_line_filename", 25, name, "process.command_line", "file.name")
                    )
            if origin.file and path and path in {path_key(ref) for ref in origin.file.references}:
                results.append(
                    reason("prefetch_reference", 45, target.file.path or path, "file.references", "file.path")
                )
        if any(r.score >= 25 for r in results):
            for event in (left, right):
                if event.source_artifact and event.source_artifact.kind in {"$MFT", "$UsnJrnl"}:
                    results.append(
                        reason("ntfs_artifact_support", 5, event.source_artifact.kind, "source_artifact.kind")
                    )
                    break
        return results

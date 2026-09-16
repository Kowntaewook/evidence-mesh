from engine.correlation.base import reason, same_host
from engine.normalization.windows import path_key
from schemas.events import Event
from schemas.results import Reason


class ProcessRule:
    def evaluate(self, left: Event, right: Event) -> list[Reason]:
        a, b = left.process, right.process
        if not a or not b:
            return []
        scoped_same = bool(a.instance_id and a.instance_id == b.instance_id and a.pid == b.pid)
        scoped_parent = bool(
            a.instance_id
            and a.instance_id == b.parent_instance_id
            or b.instance_id
            and b.instance_id == a.parent_instance_id
        )
        if a.instance_id or b.instance_id:
            if not (scoped_same or scoped_parent):
                # Bridge a memory-scoped identity to independent process-creation evidence.
                if not (
                    left.source != right.source
                    and same_host(left, right)
                    and a.pid == b.pid
                    and a.creation_time
                    and a.creation_time == b.creation_time
                ):
                    return []
        elif not same_host(left, right):
            return []
        if scoped_parent:
            return [
                reason(
                    "parent_process_instance",
                    55,
                    "Recorded parent/child process instances in one evidence scope",
                    "process.instance_id",
                    "process.parent_instance_id",
                )
            ]
        results = []
        if a.pid == b.pid:
            if a.creation_time and b.creation_time and a.creation_time != b.creation_time:
                return []
            # PID equality without lifetime evidence has only a short observation window.
            if not scoped_same and not (a.creation_time and b.creation_time):
                if abs((left.timestamp - right.timestamp).total_seconds()) > 60:
                    return []
            if a.path and b.path and path_key(a.path) != path_key(b.path):
                return []
            if a.name and b.name and a.name.casefold() != b.name.casefold():
                return []
            if scoped_same:
                results.append(
                    reason(
                        "same_process_instance", 55, f"PID {a.pid}: {a.instance_id}", "process.instance_id"
                    )
                )
            else:
                results.append(
                    reason(
                        "same_process_id", 35, f"PID {a.pid} on {left.hostname}", "process.pid", "hostname"
                    )
                )
            if a.creation_time and b.creation_time:
                results.append(
                    reason("same_process_creation", 20, a.creation_time.isoformat(), "process.creation_time")
                )
            if a.name and b.name and a.name.casefold() == b.name.casefold():
                results.append(reason("same_process_name", 5, a.name, "process.name"))
            if a.path and b.path and path_key(a.path) == path_key(b.path):
                results.append(reason("same_executable_path", 10, a.path, "process.path"))
            if a.command_line and b.command_line and a.command_line == b.command_line:
                results.append(reason("same_command_line", 10, a.command_line, "process.command_line"))
        else:
            for parent, child, parent_event, child_event in ((a, b, left, right), (b, a, right, left)):
                if child.ppid != parent.pid:
                    continue
                parent_start = parent.creation_time or parent_event.timestamp
                child_start = child.creation_time or child_event.timestamp
                if parent_start > child_start:
                    continue
                if not (parent.creation_time and child.creation_time):
                    if abs((left.timestamp - right.timestamp).total_seconds()) > 60:
                        continue
                results.append(
                    reason(
                        "parent_process",
                        40,
                        f"PID {parent.pid} is recorded PPID of {child.pid}",
                        "process.ppid",
                    )
                )
                break
        return results

from engine.correlation.base import reason, same_host
from engine.correlation.index import domains
from engine.normalization.windows import basename, path_key


class ArtifactRule:
    """Add signals for typed v0.3 observations without changing legacy sample weights."""

    def evaluate(self, left, right):
        results = []
        a, b = left.file, right.file
        if a and b:
            same_path = bool(a.path and b.path and path_key(a.path) == path_key(b.path))
            if a.sha256 and b.sha256 and a.sha256 != b.sha256:
                return []
            if (
                a.volume_id
                and a.volume_id == b.volume_id
                and same_host(left, right)
                and a.record_number is not None
                and a.record_number == b.record_number
                and a.sequence_number is not None
                and a.sequence_number == b.sequence_number
            ):
                results.append(
                    reason(
                        "same_mft_reference",
                        55,
                        f"{a.volume_id}:{a.record_number}:{a.sequence_number}",
                        "file.volume_id",
                        "file.record_number",
                        "file.sequence_number",
                    )
                )
            if (
                a.file_object
                and a.file_object == b.file_object
                and left.metadata.get("acquisition_id")
                and left.metadata.get("acquisition_id") == right.metadata.get("acquisition_id")
            ):
                results.append(
                    reason(
                        "same_file_object", 55, a.file_object, "file.file_object", "metadata.acquisition_id"
                    )
                )
            if same_path and (left.handle or right.handle):
                results.append(reason("handle_file_reference", 10, a.path, "handle", "file.path"))
            if same_path and (left.module or right.module):
                results.append(reason("dll_file_reference", 10, a.path, "module", "file.path"))
            if same_path and (left.registry or right.registry):
                results.append(reason("registry_file_reference", 10, a.path, "registry", "file.path"))
        for origin, target in ((left, right), (right, left)):
            if not origin.process:
                continue
            process = origin.process
            if target.prefetch:
                prefetch = target.prefetch
                if basename(process.path or process.name) == basename(prefetch.executable):
                    if process.path and prefetch.executable_path:
                        if path_key(process.path) != path_key(prefetch.executable_path):
                            continue
                        results.append(
                            reason(
                                "prefetch_executable_path",
                                50,
                                process.path,
                                "process.path",
                                "prefetch.executable_path",
                            )
                        )
                    elif abs((origin.timestamp - target.timestamp).total_seconds()) <= 5:
                        results.append(
                            reason(
                                "prefetch_executable_name",
                                25,
                                prefetch.executable,
                                "process.name",
                                "prefetch.executable",
                            )
                        )
            if target.registry and target.file and process.path and target.file.path:
                if path_key(process.path) == path_key(target.file.path):
                    results.append(
                        reason(
                            "amcache_executable_path",
                            50,
                            process.path,
                            "process.path",
                            "file.path",
                            "registry.artifact",
                        )
                    )
        if left.network and right.network:
            common = domains(left) & domains(right)
            if common and (left.network.tls or right.network.tls):
                # Domain equality alone on different clients is insufficient.
                def client(event):
                    net = event.network
                    return net.dst_ip if net.dns_response else net.src_ip

                if client(left) and client(left) == client(right):
                    if abs((left.timestamp - right.timestamp).total_seconds()) <= 60:
                        results.append(
                            reason(
                                "tls_sni_domain",
                                40,
                                ", ".join(sorted(common)),
                                "network.tls.sni",
                                "network.dns_query",
                                "network.src_ip",
                            )
                        )
        return results


def negative_reasons(left, right):
    results = []
    if left.hostname and right.hostname and left.hostname != right.hostname:
        results.append(reason("hostname_conflict", -100, "Known hostnames differ", "hostname"))
    if left.process and right.process and left.process.pid == right.process.pid:
        for owner, observation in ((left, right), (right, left)):
            process = owner.process
            if observation.timestamp_semantics == "extraction_time":
                continue
            if process.exit_time and observation.timestamp > process.exit_time:
                results.append(
                    reason(
                        "process_lifetime_conflict",
                        -100,
                        "Observation follows recorded exit time",
                        "process.exit_time",
                        "timestamp",
                    )
                )
                break
            if process.creation_time and observation.timestamp < process.creation_time:
                results.append(
                    reason(
                        "process_lifetime_conflict",
                        -100,
                        "Observation precedes recorded creation",
                        "process.creation_time",
                        "timestamp",
                    )
                )
                break
    if "extraction_time" not in {left.timestamp_semantics, right.timestamp_semantics}:
        precision = max(
            left.timestamp_precision or 0,
            right.timestamp_precision or 0,
            left.timestamp_uncertainty,
            right.timestamp_uncertainty,
        )
        if precision >= 1:
            results.append(
                reason(
                    "timestamp_precision_penalty",
                    -10,
                    f"Timestamp precision/uncertainty is {precision:g} seconds",
                    "timestamp_precision",
                    "timestamp_uncertainty",
                )
            )
        a_hash = (left.file.sha256 if left.file else None) or (left.hash.sha256 if left.hash else None)
        b_hash = (right.file.sha256 if right.file else None) or (right.hash.sha256 if right.hash else None)
        gap = max(
            0,
            (
                left.timestamp
                - (right.network.end_time if right.network and right.network.end_time else right.timestamp)
            ).total_seconds(),
            (
                right.timestamp
                - (left.network.end_time if left.network and left.network.end_time else left.timestamp)
            ).total_seconds(),
        )
        if gap > 60 and not (a_hash and a_hash == b_hash):
            results.append(
                reason(
                    "temporal_distance", -30, "Event timestamps differ by more than 60 seconds", "timestamp"
                )
            )
    return results

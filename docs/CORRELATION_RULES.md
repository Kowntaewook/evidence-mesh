# Deterministic correlation rules v0.3.0

Rules consume normalized observations, not parser-specific files. A substantive identity/reference anchor is mandatory; temporal proximity, filename equality or a process name alone cannot create an edge. The default threshold is 50. Signed reasons sum to raw_score; displayed Correlation Score is clamped to 0–100. Scores are not probabilities, independence estimates or maliciousness verdicts.

## Weights

| Signal / rule | Weight |
|---|---:|
| Same scoped process instance / recorded parent instance | +55 |
| Same known-host PID | +35 |
| Same process creation | +20 |
| Same process name / executable path / command line | +5 / +10 / +10 |
| Legacy recorded PPID with valid ordering | +40 |
| Exact content SHA-256 | +60 |
| Same full file path / filename | +45 / +10 |
| Exact command-line path / filename token | +50 / +25 |
| Prefetch referenced full path | +45 |
| NTFS artifact support after a substantive file match | +5 |
| Same volume/host/MFT record/sequence | +55 |
| Same FILE_OBJECT within acquisition | +55 |
| Handle / DLL / registry matching file path | +10 each |
| Prefetch executable full path / name within 5s | +50 / +25 |
| Registry-derived executable path matching process | +50 |
| Exact bidirectional socket five-tuple | +60 |
| Recorded flow interval overlap | +10 |
| DNS answer resolves destination / preceding response | +40 / +10 |
| TLS SNI/domain with same known client within 60s | +40 |
| Typed cross-source corroboration with strong anchor | +10 |
| Timestamp precision/uncertainty ≥1 second | −10 |
| Event interval separation >60s without equal SHA-256 | −30 |

The original temporal boundaries are preserved: ≤2s +30, ≤5s +25, ≤30s +15, ≤60s +5. Extraction-time fallbacks earn no temporal score. See [network.py](../engine/correlation/network.py) for the legacy incomplete-tuple endpoint and same-client DNS rules; these retain their original gates and are weaker than a complete tuple.

## Conflict handling

Known different hosts are rejected. Same PID with different known creation times is rejected. Recorded observations before process creation or after exit are rejected, rather than merely reducing a high positive score. An executable basename cannot override a conflicting known full executable path. Incompatible content hashes cannot create a file match. Conflicting known DNS client IPs do not become equivalent just because host metadata matches.

A >60-second time gap rejects weak associations. Strong identities (exact hash, scoped process/parent, matching creation, MFT reference, FILE_OBJECT) can retain an association with the documented penalty. Exact hash is exempt from temporal-distance penalties; content can persist long after an observation.

Not every rejected pair is stored as a negative edge. Only accepted edges retain signed contributing reasons. Unknown facts do not count as contradictions.

## Candidate indexes

EventIndex indexes scoped PID/instance/parent, process name, executable/file paths, filenames, hashes, IP/domain/port, MFT reference, FILE_OBJECT, five-tuples and time buckets. Complete network tuples use tuple postings rather than broad shared-server postings. DNS resolution candidates include client context. Common process executable paths are separate from generic file paths.

Deterministic sorting and pair deduplication precede rule evaluation. A test compares indexed output with brute-force default-rule evaluation on the cross-source case and checks input-order invariance. A 2,000-query shared-DNS-server test produces zero unrelated candidates. Explicit custom rule lists retain the legacy all-pairs extension behavior.

100k synthetic Events evaluated 210,000 candidates instead of 4,999,950,000 possible pairs. This is workload-specific: a dense group of genuinely matching identities can still produce quadratic output. See [verification](VERIFICATION.md).

## Process identities and graph semantics

Memory process merge retains original scoped identities and conservative unknown-owner handling. Cross-source process creation requires known equal host/PID/creation time. FILE_OBJECT comparison never crosses acquisition scope; MFT comparison includes sequence to avoid record reuse.

The selected process view follows Event correlation edges, not shared graph entity membership. An indirect path does not receive a fabricated direct score.

Graph PARENT_OF, OPENED, LOADED, CONNECTED_TO, RESOLVED_TO, USES_BINARY and other typed relations project recorded fields. EXECUTED represents a recorded command-line file reference and does not prove that a script completed. Observed graph-edge score 100 denotes a direct recorded relationship, not certainty about causation. Same entity/relation edges coalesce with support_count and all source-event/provenance records.

## Verified examples

The original sample remains: 15 Events, 9 related Events and 16 links. PowerShell→MFT = 85, socket→PCAP = 90 and DNS→connection = 80.

The new case has 67 Events: 34 in the PID 4120 component and 29 explicitly labeled noise observations, plus four unrelated kernel observations. The component has 259 accepted correlations. It connects command-line/handle/file-object/recovered SHA-256 to MFT/USN/Prefetch/Amcache, and memory socket to DNS/TCP/TLS. Different-path filenames, different clients/hosts, reused PID lifetimes and unrelated flows remain outside the component.

Driver/callback observations are normalized and visible as graph evidence, but dedicated scored cross-source driver/callback ownership rules are not implemented. Clock skew, NAT, DNS TTL lifetime and volume alias inference are not automatic.

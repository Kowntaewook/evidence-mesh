# PCAP / PCAPNG adapter

`PcapAdapter` in [pcap.py](../engine/collectors/network/pcap.py) uses **tshark** offline. Both PCAP and PCAPNG are decoded as actual binary captures. No capture interface is opened.

The Windows packaging definition includes TShark **4.6.8** and its required DLLs/data. Electron supplies its absolute path through `EVIDENCEMESH_TSHARK`; discovery checks this bundled path before system PATH. An explicitly configured executable takes precedence. Missing both produces UNAVAILABLE. Development Linux tests use TShark **4.6.6**. Actual installed Windows execution is still pending; binary acquisition alone is not an execution result.

## Decoder execution and errors

The subprocess is an argument array using `-n -r PATH -T fields` and explicit field names. It has a 180-second default timeout, checks exit code, captures stderr (up to 64 KiB), and writes decoded intermediate output to temporary files. No shell interpolation or network name resolution is used.

Missing tool = UNAVAILABLE. Missing capture, invalid capture, timeout, nonzero decoder exit, malformed output and invalid normalized fields = FAILED. Empty captures fail; captures with packets but no supported TCP/UDP IP traffic can succeed with an explicit warning and zero supported Events. ParserRun preserves command, status, exit code, error, input hash and counts.

## Observations

| Protocol | Normalized fields |
|---|---|
| DNS | Query/response flag, name/type/ID, A/AAAA answers, wire src/dst, timestamp/frame |
| TCP / UDP | Bidirectional flow, IP/ports/protocol, first/last time, packet and wire-byte counts, stream ID |
| TCP flags | Observed flags; FIN/RST-observed descriptions, not invented application state |
| HTTP | Visible request method/host/URI/user-agent and response status/content-type |
| TLS | ClientHello SNI/version/client/server endpoint where observed; other TLS record version |

Flows group protocol, tshark stream ID and unordered endpoints. Display direction is the first observed wire direction, which need not be the initiator. Original packet frame numbers are retained for every flow. DNS responses keep their real wire direction, not a fabricated client-first packet. Multiple DNS A/AAAA answers are retained; the first query-name/type occurrence is normalized while all decoder values remain raw.

Timestamps normalize to microseconds; original decimal epoch text remains in provenance. Frame byte_count is the sum of observed frame lengths, not application payload size. TLS record version is an observed field, not a claim about negotiated protocol version. Client/server roles are populated from SNI-bearing ClientHello only.

## Correlation

An exact complete memory socket/flow five-tuple matches in either direction, with recorded temporal interval overlap as an additional reason. DNS-to-destination associations require the same known client (or compatible host only when IP context is unavailable), a recorded resolved IP and a preceding DNS observation within 60 seconds. TLS SNI/domain matching includes client and time context.

Shared public server or DNS resolver addresses alone do not merge clients. Full tuples use indexed tuple candidates so thousands of clients using one resolver do not force broad all-pairs comparisons.

## Usage and provenance

```bash
python -m engine.cli import pcap samples/cross_source/network/traffic.pcapng \
  --db data/case.sqlite3 --case-id CASE_ID --acquisition-id network-01 \
  --extracted-at 2026-09-16T09:35:00Z --tool-version 4.6.6
```

Tool version is supplied context and stays unknown if not supplied; no version is inferred from a fixture. A sensor hostname must not be supplied as the client host unless that attribution is established.

Capture SHA-256/size/path/import time, decoder fields, frame/stream references, timestamp and acquisition context survive normalization. The UI exposes them through Provenance and Raw.

## Validation and limits

Actual generated 13-packet PCAP and PCAPNG each produce 17 Events. Normal/malformed/optional protocol cases, absent tshark, timeout/nonzero exit, malformed decoder output and literal metacharacter paths are tested.

Two pre-existing workspace captures were read separately: 20,000 packets → 39,929 Events, and 2,826 packets → 7 flow Events. Their collection history is unknown; this validates decode compatibility, not case interpretation. The first capture's index built 40,691 candidates versus 797,142,556 possible pairs.

## HTTP bodies and supplied TLS secrets

TCP and HTTP reassembly/dechunking are enabled. Complete supported request/response
bodies are written under `derived/network/<capture-sha256>/bodies/<body-sha256>.bin`.
The existing HTTP event is enriched with the content SHA-256, size, recovered path
and a File identity. This enables the existing `same_sha256` correlation with an
independently imported disk file; matching bytes alone do not prove causation.
Content encoding is preserved rather than silently decompressed. Recovery is
bounded at 32 MiB per body; ambiguous multiple bodies or incomplete length checks
produce warnings rather than invented complete files. Raw capture provenance
retains capture hash/frame references and excludes bulky duplicate body hex.

The optional `ArtifactContext.tls_keylog_file` supplies an existing key log (up to
64 MiB) to TShark's `tls.keylog_file` option. The UI has a native key-file picker.
Without keys, TLS stays `Encrypted - metadata only`. It is labeled
`Decrypted using supplied key log` only after actual decoded application data is
observed. Supplying a wrong or unrelated key does not itself prove decryption.

Nine new tests use actual TShark: split Content-Length/chunked request and response
bodies in PCAP/PCAPNG, content hashes, and a real TLS 1.2 handshake created offline
with SSL MemoryBIO. The encrypted capture yields no HTTP body without its key and
the expected bytes with its supplied key. No network service is contacted.

Live acquisition, QUIC-specific normalization, NAT reconstruction and clock-skew
correction remain outside support. See the [tshark manual](https://www.wireshark.org/docs/man-pages/tshark)
and [TLS fields](https://www.wireshark.org/docs/dfref/t/tls.html) for the decoder contract.

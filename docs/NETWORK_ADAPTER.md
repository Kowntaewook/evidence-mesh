# PCAP / PCAPNG adapter

`PcapAdapter` in [pcap.py](../engine/collectors/network/pcap.py) uses installed **tshark** offline. Both PCAP and PCAPNG are decoded as actual binary captures. No capture interface is opened.

Install tshark separately (`apt-get install tshark` on Debian-family systems, or the appropriate Wireshark installation for the host). The adapter locates it on PATH or accepts an explicit executable. The validated environment used tshark **4.6.6**; other versions must expose the requested fields.

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

No TLS decryption, encrypted HTTP interpretation, HTTP body recovery/download-to-file causation, live acquisition, QUIC-specific normalization, NAT reconstruction or clock-skew correction is implemented. Non-IP and unsupported protocols remain outside normalized support. See the [tshark manual](https://www.wireshark.org/docs/man-pages/tshark) and [TLS fields](https://www.wireshark.org/docs/dfref/t/tls.html) for the external decoder contract.

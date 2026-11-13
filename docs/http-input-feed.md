# Read-only loopback HTTP input feed

Version 0.18 adds an opt-in HTTP input/status feed for the GUI and CLI. It binds only IPv4 `127.0.0.1`, starts serving after backend setup and closes at run completion. It has no output, configuration, OP or reconnect routes. It does not change native hardware authorization. Any local process can read an enabled feed; there is no authentication, TLS, remote binding or CORS support. Use it on a trusted local host and enable it deliberately.

```powershell
# Authored synthetic data, no NIC or Npcap needed.
.\ethercat-workbench-cli.exe run samples/http-input.json --seconds 20 --csv .local/http.csv --report .local/http-run.json
curl.exe http://127.0.0.1:8766/v1/status
curl.exe http://127.0.0.1:8766/v1/latest
curl.exe 'http://127.0.0.1:8766/v1/samples?after=0&limit=16'
curl.exe http://127.0.0.1:8766/v1/metadata
```

In the desktop, enable **read-only local HTTP input feed** in section **2 Bus and capture** and configure port, freshness, feed queue and history. The live snapshot shows the actual URL and independent interface counters. CLI `run --http-port PORT` enables or overrides the port. Port `0` requests an automatic port; the CLI prints the bound URL to stderr before setup, while stdout remains the final JSON report. A bound listener is not yet a ready backend: retry reads after setup, or use the GUI cycling state. A bind/configuration failure occurs before device setup. Other worker/client failures do not stop acquisition or CSV; inspect `report.http` even when `report.error` is null.

## Configuration and ownership

Profiles keep schema 1. The optional `http` object enables the feed; omitted/null means disabled. Disabled settings are omitted from canonical serialization so older profile hashes and saved reports remain usable.

```json
"http": {
  "port": 8766,
  "queue_capacity": 4096,
  "history_capacity": 1024,
  "freshness_ms": 100
}
```

Queue capacity is 1–8192 fixed records; history is 1–4096 records; freshness is 1–60000 ms. Input field names are bounded to 16 KiB combined for HTTP-enabled profiles. The cycle offers one fixed record per completed/failed cyclic attempt through a preallocated queue. It performs no socket I/O, JSON encoding, consumer wait or CSV file I/O. The separate HTTP worker drains that queue, keeps bounded history and serves one client at a time. Finishing cyclic I/O marks the feed inactive before INIT cleanup; final teardown drains pending records and closes the listener. Worker failure is reported independently and does not create a bus retry.

## Schema 1 and routes

Every JSON response has `schema`, `stream_id`, `stream_start_utc`, `connection_generation`, `response_elapsed_us`, `active`, `fresh` and route-specific `data`. The stream identifier includes UTC/process/run identity; reset cursors when it changes, even if the generation repeats in another process. The monotonic feed anchor is independent of the CSV anchor. UTC plus feed elapsed time is a host-clock estimate, not device/DC or wire timing.

| GET route | Data |
| --- | --- |
| `/v1/status` | Feed address/counters, history bounds/length, capacities, freshness threshold and the latest dispatched acquisition/CSV counter snapshot |
| `/v1/latest` | `latest` attempt and separately labeled `last_valid` historical input, either nullable |
| `/v1/samples?after=N&limit=L` | Records with `event_index > N`, in order; default limit 16, maximum 64; oldest/newest retained and producer indexes plus `next_after` |
| `/v1/metadata` | App/backend, canonical profile hash, requested host period, expected identity, TxPDO size/field definitions, device setup snapshot, PDO verification and synchronization readback |

Metadata is frozen after setup. Its device/port/counter/AL information is not a cyclic refresh. Current attempt AL/WKC status comes from the samples. Profile identity and field definitions remain expectations; fixture backend names and verification provenance must remain visible. Metadata does not expose staged RxPDO bytes or grant hardware permissions.

Each sample contains `event_index`, `cycle_index`, monotonic `elapsed_us`, `timestamp_kind`, `age_us`, exchange `valid`, expected/actual WKC, nullable AL status/code, input issue, acquisition/CSV counters, and nullable `payload_hex`/`values`. Valid frames export all named TxPDO fields as decoded strings, independently of CSV column selection or on-change mode. This preserves wide integers and non-finite float text without JSON-number rounding. Raw bytes are uppercase hex.

Invalid attempts have null payload and values. Timeouts/transport failures have no current WKC/AL readback and use `failed_attempt_observed` timing; replied frames use near-receive timing. `last_valid` is explicitly historical and carries an age. An exchange's `valid` records its original WKC/SAFEOP checks; it does not mean the payload is current at the client.

`fresh` describes the latest attempt at response construction: the feed is active, the latest dispatched attempt was valid, its event index equals the producer's offered index, and its age is within the configured threshold. Backlog, a dropped newer attempt, invalid input, inactivity or age makes it false. Transfer/processing delay after construction can age the result further. History records are historical regardless of the envelope's latest freshness; inspect their ages and indexes.

## Indexes, loss and lifecycle

HTTP event indexes start at 1 for every cyclic attempt, including invalid attempts and offers dropped by the feed queue. Cycle indexes also reflect skipped scheduling slots. CSV sample indexes count selected valid offers and can follow on-change filtering. These are different domains; correlate generation/cycle/profile identity and do not equate them.

Queue overflow drops the new HTTP offer and increments `queue_drops`. History rollover increments `history_evictions`; neither changes bus/CSV counters. Detect leading/interior gaps from returned event indexes and oldest retained index. An empty batch can mean no newer dispatched event yet; retain its cursor and check producer index/status. A cursor ahead of this stream returns 400, so reset after a stream change. Latest-only polling does not provide every-attempt delivery.

`http` report counters include offered/dispatched/pending, queue drops, history evictions, requests, rejected requests, I/O errors, worker-failed flag and final worker error. Incomplete/oversized/timed-out headers or failed writes count as I/O errors; complete malformed/unsupported requests count as rejections. Live counters are independent atomic observations and can briefly be in flight. At settled completion, offered equals dispatched plus queue drops plus pending; a failed worker can leave abandoned pending records. CSV written counts in live samples can lag the writer; use the final report/audit for clean-drain proof.

The listener closes when the run ends; unavailable HTTP is not proof of INIT success or zero loss. Use the saved report for final bus/cleanup/writer outcome. `compare-runs` retains each trial's HTTP counters and warns about interface losses/errors separately from bus quality and logger overruns. Enabled HTTP settings must match between compared trials; use separate compatible trial groups for enabled/disabled comparisons.

## Supported HTTP subset and bounds

The implementation uses a narrow HTTP/1.1 request/response subset following [RFC 9112 message syntax](https://www.rfc-editor.org/rfc/rfc9112.html). It accepts GET origin-form routes with one matching `Host` (`127.0.0.1:PORT` or `localhost:PORT`), ASCII headers and CRLF termination. Requests have at most 4096 header bytes/32 fields and a 25 ms header deadline. Bodies, transfer coding, upgrades, expectation handling, duplicate Host/length and pipelining are unsupported. Responses are JSON with content length, `Connection: close`, `Cache-Control: no-store`, a 2 MiB body cap and a 25 ms write deadline. Request a smaller history batch if encoding exceeds the response cap. Socket deadlines are checked cooperatively; Windows scheduling and bounded JSON work can add latency.

There is no subscription, long poll, durable history or acknowledgement that a caller processed a response. Deliberately slow clients can lose HTTP records without affecting acquisition/CSV ownership. Headless authored tests cover this boundary; native GUI operation and a physical GUI-plus-CSV-plus-consumer timing comparison remain pending the selected bench device/NIC. The [MQTT publisher](mqtt-input-feed.md) is a separate opt-in latest-value consumer; shared memory and C-compatible embedding remain [roadmap work](interfaces-roadmap.md).

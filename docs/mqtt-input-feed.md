# MQTT input publisher

Version 0.19 adds an opt-in publish-only MQTT input/status worker for the CLI and desktop. It connects only to a trusted broker on IPv4 `127.0.0.1`. It uses MQTT 3.1.1 TCP, QoS 0, non-retained publications and clean sessions. There are no subscriptions, command topics, device outputs or configuration routes. It grants no EtherCAT hardware authorization. Use a local broker's separately configured authenticated/TLS bridge for remote consumers; this client has no remote address, DNS, TLS, username or password support.

```powershell
# Start your trusted local broker separately on 127.0.0.1:1883.
# These are authored synthetic inputs; no NIC or Npcap is needed.
.\ethercat-workbench-cli.exe run samples/mqtt-input.json --seconds 20 --csv .local/mqtt.csv --report .local/mqtt-run.json
# Optional concurrent HTTP, with an automatically selected port:
.\ethercat-workbench-cli.exe run samples/mqtt-input.json --mqtt-port 1883 --http-port 0 --seconds 20
```

The desktop's **2 Bus and capture** section enables/configures the publisher and displays its connection, coalescing, queue loss, write/error counters and last error. CLI `run --mqtt-port PORT` enables the default configuration or overrides its port. Set a distinct topic for each app/device. A topic collision merges streams at the consumer; generated client IDs distinguish sessions but do not isolate topics.

## Profile and ownership

Profiles retain schema 1. Omitted/null `mqtt` disables the worker and is omitted from canonical serialization, preserving previous profile hashes. Enabled settings are part of the effective profile and scheduler-comparison fingerprint.

```json
"mqtt": {
  "port": 1883,
  "topic": "ethercat/workbench/input",
  "queue_capacity": 4096,
  "period_ms": 20,
  "freshness_ms": 100
}
```

Port is 1–65535. Topics are 1–512 printable ASCII bytes without whitespace, `+`, `#` or a leading `$`. Queue capacity is 1–8192 fixed records; period and freshness are 1–60000 ms. Enabled HTTP/MQTT profiles limit combined TxPDO field names to 16 KiB. Invalid configuration fails profile validation before device setup.

After backend setup, the acquisition thread offers each cyclic attempt to MQTT's preallocated bounded queue, separately from HTTP and CSV. The offer copies a fixed record and never performs networking, JSON encoding, allocation or consumer waits. The MQTT worker drains into a latest snapshot and a separately historical last-valid snapshot. Replaced, not-yet-attempted events count as `coalesced`; this is intentional latest-value sampling, not every-exchange delivery. Queue overflow drops the new offer and increments `queue_drops`. Slow/refusing/disconnected brokers cannot request bus retries or stop CSV/HTTP.

## Schema 1 payload

Every publication uses the configured topic and a bounded JSON object (maximum 2 MiB):

- `schema: 1`, `kind: "input"`, `stream_id`, `stream_start_utc`, `connection_generation`, `broker_attempt`, `publication_index`, `response_elapsed_us`, `active`, `fresh`.
- `latest` and `last_valid`, nullable, using the [HTTP sample contract](http-input-feed.md#schema-1-and-routes): event/cycle indexes, near-receive or failed-attempt monotonic timing and age, WKC/AL/input quality, acquisition/CSV counters, nullable raw hex/typed values. All TxPDO fields are decoded as strings independently of CSV selection. Invalid attempts have null raw/typed payloads. Last-valid input is explicitly historical.
- `metadata`: frozen application/backend, profile hash, requested period, expected identity, TxPDO size/field definitions, setup device snapshot, PDO verification and synchronization readback. No staged RxPDO bytes are included. Expected/profile values remain separate from discovered/verified setup information.
- `feed`: independently observed publisher counters. These can be briefly in flight; final saved reports provide settled accounting.

Metadata repeats so a late subscriber can interpret a newly received publication. Publication time and the stream UTC/monotonic anchor are host evidence, separate from CSV's anchor, device/DC synchronization or wire timestamps. HTTP and MQTT have independent stream IDs, clocks and event loss; correlate generation/cycle/profile identity, rather than equating stream timestamps or assuming delivery of each event.

`publication_index` counts JSON publication attempts, including failed writes and the final inactive message. It differs from event/cycle/CSV sample indexes. Repeated snapshots can carry the same event index. `broker_attempt` increases on each connection attempt; reconnects retain the stream/client ID and do not reconnect or reinitialize EtherCAT. New runs create new stream IDs/client IDs, even when a connection generation repeats. Reset consumer state on a new stream; ignore unavailable messages from older broker attempts.

At encoding, `fresh` requires an active publisher, a valid latest attempt, its event index equal to the producer's latest offered index and age within `freshness_ms`. A backlog or dropped newer offer makes it false. Transfer/broker/consumer delay can age the message further. Consumers must enforce their own receipt-age/timeout policy and inspect original sample ages. A message's historical `valid`, a once-true `fresh`, or a TCP connection is insufficient proof of current usable input.

## MQTT subset, delivery and shutdown

The implementation follows the [OASIS MQTT 3.1.1 specification](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html) for its publish-only subset: CONNECT/CONNACK, QoS 0 PUBLISH, PINGREQ/PINGRESP and DISCONNECT. CONNECT uses a generated 23-character alphanumeric client ID, clean session, keepalive 10 seconds and a QoS 0 non-retained last will on the same topic. The will is a small schema-1 `kind: "unavailable"` object with stream/generation/broker-attempt identity, `active: false`, `fresh: false` and reason `publisher_connection_lost`; it has no sample or metadata. Broker timing/delivery of the will is outside the client. A graceful disconnect suppresses it.

Connection and CONNACK deadlines are each 100 ms; nonblocking writes have a 25 ms deadline. Idle connections send a ping after two seconds without a send and require a valid response within 100 ms. Malformed/rejected acknowledgements, unexpected server packets, peer close and deadline failures close the connection. Reconnect waits increase from 100 ms to a five-second cap; successful handshakes reset the delay. There is no durable queue, acknowledgement, retransmission promise or subscription processing. Periodic publication uses the latest snapshot, including repeated/status-only snapshots, and skips elapsed periods. It is an upper rate target, not a timer guarantee. Bounded encoding and Windows scheduling can add latency.

QoS 0 has no broker acknowledgement. `write_completions`, `shutdown_written` and `disconnect_written` mean complete writes to the local TCP socket; they do not prove broker acceptance, delivery, processing or durable storage. Partially written/failed publications have unknown delivery and are not replayed as transactions. Subsequent latest snapshots may repeat an event. A subscriber can miss the final inactive message or last will and must time out stale input independently.

Cyclic stop marks the publisher inactive before approved INIT cleanup. Final teardown drains the record queue, makes one bounded inactive publication/DISCONNECT attempt on an existing connection, closes it and joins the worker. It does not connect/retry at shutdown. With no connection, the final latest event remains `unsent_events: 1`. Network/worker failures are independent of `report.error`; inspect `report.mqtt` even when acquisition succeeded.

Final accounting has two domains: `offered = drained + queue_drops + queue_pending`, and `drained = coalesced + attempted_events + unsent_events` (zero or one unsent latest event). `publish_attempts = write_completions + publish_errors`. Repeated/status-only publications add no attempted event. Connection attempts/successes/errors, last error, worker failure and clean-shutdown write flags remain separate. CSV losses and bus errors do not become MQTT losses. Saved-run comparisons retain these counters and warn on feed loss/errors; intentional coalescing remains visible. Compare identical enabled settings between schedulers, using separate compatible groups for enabled/disabled workloads.

## Verification boundaries

Rust tests cover wire vectors/configuration, bounded overflow/coalescing, null invalid versus historical data, malformed handshakes and bounded shutdown with a silent broker. The independent Python TCP fixture checks both schedulers with simultaneous HTTP/CSV, silent/rejected/malformed handshakes, reconnect identity, raw/typed values, fragmented replies, keepalive, stalled-reader write pressure, absent brokers and sustained invalid virtual input with INIT/write audits. It is not a production broker and does not qualify real broker forwarding/security or subscriber processing. The physical GUI-plus-CSV-plus-consumer timing comparison remains pending the selected device/NIC and agreed bench run. Windows shared memory and optional C ABI/C# embedding remain [roadmap work](interfaces-roadmap.md).

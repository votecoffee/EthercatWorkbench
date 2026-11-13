# Software interfaces and roadmap

**Status: read-only loopback HTTP implemented in 0.18, MQTT publishing in 0.19; other transports planned.** EtherCAT Workbench exports CSV, run reports, offline review/inspection JSON and an opt-in [HTTP input feed](http-input-feed.md). The [MQTT publisher](mqtt-input-feed.md) exports latest input/status to a trusted local broker. There is no shared-memory feed or C ABI. These items do not authorize hardware work or output/configuration writes.

The read-only reference is [EthernetIPWorkbench](https://github.com/votecoffee/EthernetIPWorkbench), locally `C:\~LocalWork\Repos\Programming\~Github\EthernetIPWorkbench`. Its [README at 5fec2f8](https://github.com/votecoffee/EthernetIPWorkbench/blob/5fec2f8937cd21ee4437de49a4f54733d5c97f86/README.md) describes loopback HTTP with bounded history, MQTT 3.1.1 TCP QoS 0 latest-value publishing and a Windows shared-memory latest raw snapshot. C-compatible FFI has been discussed there, not implemented. Use its consumer isolation patterns while defining EtherCAT-specific schemas and ownership.

## Shared acquisition contract

Keep acquisition, GUI, CSV and every external consumer independent. Offer fixed-capacity preallocated records or bounded latest snapshots without blocking, file/network I/O or per-consumer waits on the cycle/receive thread. A slow/disconnected consumer must not stall bus acquisition, CSV drain or another consumer. Opt-in configuration starts disabled; invalid consumer settings must not silently alter the requested bus period.

Define a versioned EtherCAT sample with run/stream identity, UTC capture anchor, monotonic near-receive elapsed time, sample/cycle indexes and connection generation. Retain position/configured station, identity verification, TxPDO layout/profile hash, raw bytes and typed values. WKC expected/actual, AL state/code, transport/input-health status, age of last valid input and mapping/synchronization provenance belong in explicit quality/status metadata. A stale last-good payload must not appear as fresh valid input. Keep host period/spacing, device/DC settings and imported capture clocks distinct.

Count bus timeouts/WKC/AL errors, skipped deadlines, CSV overruns, interface dispatch drops and each consumer's coalescing/failures separately. Document index domains, restart/generation resets, bounded history eviction, latest-value sampling, unknown delivery and whether invalid exchanges generate status-only records. Preserve wide numeric values without JSON floating-point precision loss. A dropped external sample does not imply a dropped EtherCAT reply, and a successful publish/copy does not prove a consumer processed it.

## Interface work items

| Interface / status | Scope and acceptance criteria |
| --- | --- |
| Read-only local API (implemented 0.18; physical impact unqualified) | See the [HTTP contract](http-input-feed.md) for loopback status/latest, bounded history, setup metadata, client limits and independent loss/freshness reporting. No output/configuration routes or remote binding. |
| MQTT publishing (implemented 0.19; physical impact unqualified) | See the [MQTT contract](mqtt-input-feed.md) for local-broker QoS 0/non-retained latest input/status, independent loss/coalescing, age, bounded reconnects and shutdown. No subscriptions or device writes; TCP writes do not prove consumer delivery. |
| Windows shared memory | Versioned, fixed-capacity latest raw snapshot plus coherent quality/identity/time header. Define mapping names, Windows access control, single writer, reader-copy consistency, restart/generation detection and writer-death/staleness behavior. Never expose Rust pointers or let a reader lock stall acquisition. Report skipped publications/contention independently. Document latest-value loss semantics and a stable C-readable byte layout if required. |
| Optional C-compatible FFI / C# embedding | First decide whether the C# host must own the hardware connection. If not, evaluate an out-of-process read-only interface. If embedding is needed, design opaque handles, fixed-width/versioned C structs, explicit allocation/free, UTF-8 strings, error codes, shutdown/cancellation and bounded polling/callback handoff. Catch panics at the ABI boundary and state thread/runtime ownership. One owner controls a NIC/session; the desktop and host must not open competing MainDevice sessions. Treat callback/host stalls as consumer failures. No output/configuration ABI is implied by read-only embedding. |

Only the linked HTTP/MQTT contracts define implemented routes/topics. Memory layout and ABI remain unimplemented. Define schemas and compatibility rules before implementation; keep EtherNet/IP sequence/assembly fields out of EtherCAT schemas.

## Qualification and maintenance

Before calling an interface implemented, add headless tests for bounded memory/overflow, stalled consumers, malformed input, worker/network failure, generation changes, stale/invalid input, shutdown and independence from CSV/other consumers. Exercise MQTT with a local fixture broker, shared memory with an independent reader and any ABI with a small C/C# host. Check Windows x64 packaging, notices and configuration migration. A software fixture does not qualify physical timing.

After selecting the bench device/NIC and agreeing the run, compare repeated 1 ms deadline/relative trials with GUI and CSV active, first without feeds and then with representative consumers and deliberate slow/failing consumers. Keep requested period, device/DC settings, host frame spacing and interface age/loss results separate. Physical SAFEOP validity, outputs/OP/configuration changes retain their original approval boundaries.

Maintain operational/developer instructions, AGENTS, skill routing, schemas/examples and package contents with each implemented interface. Mark roadmap items complete only after their concrete behavior, failure/loss semantics and verification receipts exist.

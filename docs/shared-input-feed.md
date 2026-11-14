# Windows shared-memory input

Version 0.20 adds an opt-in, fixed-layout latest raw input/status snapshot. A separate worker copies fixed acquisition records into a named page-file mapping. It tries the reader mutex with zero wait. Slow or crashed readers cannot make cyclic I/O, HTTP, MQTT or CSV wait. This is a read-only consumer interface with no device output/configuration path, and it does not grant hardware permission.

```powershell
# Authored synthetic inputs, no NIC/Npcap needed.
.\ethercat-workbench-cli.exe run samples/shared-input.json --seconds 20 --csv .local/shared.csv --report .local/shared-run.json
# Separate console; optional example requires Windows Python 3:
python -B examples/read_shared_memory.py --name bench --seconds 10
# CLI override enables the default settings or replaces the configured name:
.\ethercat-workbench-cli.exe run samples/synthetic.json --shared-memory another_bench --seconds 20
```

The desktop's **Integration** tab configures the name, period, freshness threshold and queue; **Diagnostics** displays independent publication/loss/contention counters. Profiles retain schema 1. Omitted/null `shared_memory` disables it and is omitted from canonical serialization, preserving older profile hashes. Enabled settings enter the scheduler-comparison fingerprint.

```json
"shared_memory": { "name": "bench", "queue_capacity": 4096, "period_ms": 10, "freshness_ms": 100 }
```

Names contain 1–64 ASCII letters/digits/underscore/hyphen. Queue is 1–8192 fixed records; period/freshness are 1–60000 ms. Period is an upper publication-rate target, separate from the host cycle request and observed frame spacing. The worker coalesces intermediate events; use CSV for every selected valid exchange or HTTP for bounded history. Shared-memory publication does not imply that any reader copied/processed it.

## Objects, permissions and lifecycle

Open existing `Local\EtherCATWorkbench.NAME.data` with `FILE_MAP_READ`, and `Local\EtherCATWorkbench.NAME.lock` with `SYNCHRONIZE | MUTEX_MODIFY_STATE`. Open the mutex, copy all 2560 bytes into private storage while owning it, then release it before decoding, printing or doing other work. Never create the objects from a reader. The [native CLI reader/inspector](shared-input-review.md) reads these bytes without Python and optionally decodes them with an exact matching effective profile. The [Python example](../examples/read_shared_memory.py) uses only those mapping/synchronization rights. The [C header](../include/ethercat_input_v1.h) defines the little-endian packed byte layout; it is not an embedding/function ABI or a Rust struct/pointer contract.

The producer reserves both names before backend setup, and refuses any existing object rather than overwrite another writer or a retained reader snapshot. The initially zero mapping means reserved/not ready. A worker starts after backend setup. A clean finish drains its queue, makes one zero-wait inactive publication attempt, closes its view/handles and joins. If a reader still holds the mutex, the attempt is skipped and `shutdown_written` is false; the retained bytes can still have `active` set. Process identity and heartbeat/sample age must therefore be checked independently. No cleanup wait or forced lock release is imposed on the reader.

Objects use the `Local` session namespace and a protected DACL granting full access to the object owner and LocalSystem (`OW`, `SY`), with no Everyone/authenticated-users ACE and no inherited handles. The owner is defined by the creating Windows token; administrator/group ownership and integrity levels follow Windows rules. Same-session readers need compatible access tokens. Cross-user/service/session access is not supported here. An owner/privileged process can alter objects; this is a trusted local interface, not a tamper-proof boundary. No Global-object privilege is requested. See [Windows synchronization security](https://learn.microsoft.com/en-us/windows/win32/sync/synchronization-object-security-and-access-rights).

On `WAIT_ABANDONED`, a reader owns the mutex but must release it and discard that copy; a dead writer may have left partial data. The example raises an explicit error. The live producer can recover an abandoned reader mutex by overwriting the entire snapshot from its own state, incrementing `abandoned_recoveries`. This differs from accepting unknown shared bytes. See [Windows wait semantics](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject).

After a run ends or crashes, close all reader handles and reopen for a new run. Retained mapping/mutex handles keep objects alive and deliberately prevent name reuse. A new stream ID resets event/publication cursors; a connection generation can repeat across processes. A writer crash does not publish an inactive marker. Check publisher PID **and process creation FILETIME**, plus heartbeat age; PID alone can be reused. A stuck worker can share a still-running GUI process, so process liveness alone is insufficient.

## Schema 1 byte layout

All integer fields are little endian. The mapping is exactly 2560 bytes: 512-byte header, 1024-byte latest payload slot and 1024-byte last-valid slot. Strings are UTF-8, zero-terminated/zero-padded to 64 bytes (backend label may be truncated at a UTF-8 boundary). Unused payload/padding bytes are zero, including the whole latest slot on invalid attempts. Raw lengths describe only valid payload bytes.

| Offset | Type / fields in consecutive order |
| --- | --- |
| 0 | 8 bytes `ECWBIN01` |
| 8 | 4 × u32: schema=1, size=2560, header=512, payload capacity=1024 |
| 24 | u64 publication attempt index; i64 UTC stream-start Unix microseconds |
| 40 | 3 × u64: connection generation, publication elapsed microseconds, producer offered event index |
| 64 | 3 × u64: latest event index, cycle index, elapsed microseconds; zero when absent |
| 88 | 3 × u64: historical last-valid event index, cycle index, elapsed microseconds |
| 112 | 7 × u64: queue drops, drained events, coalesced events, mutex misses, written events, queue pending, successful snapshot writes |
| 168 | 7 × u64: acquisition cycles, valid exchanges, timeouts, WKC mismatches, AL mismatches, transport errors, missed deadlines |
| 224 | 3 × u64: CSV selected, written, overruns (presence flag required) |
| 248 | 2 × u64: publication QPC, QPC frequency |
| 264 | 2 × u32: publisher PID, flags |
| 272 | 4 × u16: expected WKC, actual WKC, AL status, AL code (presence flags required) |
| 280 | 4 × u32: input issue, profile TxPDO bytes, latest payload length, last-valid payload length |
| 296 | 3 × u32: expected vendor/product/revision; separate presence flag |
| 308 | 3 × u32: setup-observed vendor/product/revision; separate presence flag |
| 320 | 3 × u32: requested host cycle us, freshness ms, publication period ms |
| 332 | 2 × u16: setup configured station address, bus position |
| 336 | u64 publisher process creation FILETIME |
| 344 | 64-byte stream ID |
| 408 | 32-byte canonical profile SHA-256; presence flag required |
| 440 | 64-byte backend label |
| 504 | u64 abandoned mutex recoveries |
| 512 | 1024-byte latest raw input slot |
| 1536 | 1024-byte explicitly historical last-valid raw input slot |

Flag bits: `0x001` active, `0x002` latest present, `0x004` latest exchange valid, `0x008` last-valid present, `0x010` reply received, `0x020` actual WKC present, `0x040` AL present, `0x080` expected identity present, `0x100` fresh at publication, `0x200` profile hash present, `0x400` setup-observed identity present, `0x800` CSV counters present. Issue codes: 0 none, 1 timeout, 2 WKC, 3 AL, 4 WKC+AL, 5 transport error. Absent fields are zero. Invalid attempts retain their quality/status but have no current raw payload. Historical last-valid bytes are separately labeled, not a substitute for current input.

Identity/station/backend are frozen setup evidence; fixture labels must stay visible. Expected identity and layout/hash originate in the profile, while setup-observed identity originates in that backend. They do not independently prove physical PDO meaning. Full mapping provenance, verification and synchronization details remain in the saved profile/report or HTTP metadata. No staged RxPDO bytes or typed output values are exported. Use the existing offline `decode` command with the matching profile for bit/type/endian/word transformations.

## Time, freshness and accounting

Event indexes count every completed/failed attempt, including feed offers dropped by the queue; cycle indexes also reflect skipped slots. Publication indexes count attempts to copy a snapshot, including mutex misses. Successful copies can repeat an event/heartbeat. These are separate from CSV sample indexes and other feed streams.

Receive/failed-attempt times use the feed's own monotonic anchor. UTC start is a host estimate and differs from CSV/HTTP/MQTT anchors. Publication QPC is a local Windows clock for reader age, not a device/DC or wire timestamp. [Windows QPC guidance](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps) describes this time basis. With a matching positive QPC frequency and nondecreasing reader counter, compute publication age as `(reader_qpc - publication_qpc) * 1_000_000 / frequency`; sample age adds `publication_elapsed_us - sample_elapsed_us`. Do not compare QPC values across machines/boots. The example also checks process creation/liveness, flags, lengths, quality and stream/profile identity fields, and exposes its age-qualified `current_usable` hint. Quality/freshness describes the copied snapshot; it cannot guarantee the bus remains unchanged after publication.

Fresh-at-publication requires active cyclic input, a valid latest record, its event index equal to the producer's offered index and age within the threshold. Backlog/dropped newer offers invalidate it. Readers must recompute age and liveness each time rather than trust a previously true bit. Enforce an application timeout after the last usable snapshot. A valid exchange's payload remains historical after stop, stall or crash.

Final report accounting: `offered = drained + queue_drops + queue_pending`; `drained = coalesced + written_events + unsent_events` (zero or one latest event awaiting a copy). Mutex misses are independent skipped publication attempts, not bus/CSV losses. Live diagnostic counters are independent atomic observations and can be briefly in flight. Final reports carry inactive-publication outcome, worker failure and recovery counts; comparison retains these independently and warns on losses/contention/recovery or incomplete shutdown publication. Compare matching enabled settings between schedulers and use separate compatible groups for enabled/disabled workloads.

## Verification boundaries

Rust tests cover byte/quality/padding layout, deterministic overflow/coalescing, names/configuration, exclusive creation before virtual setup, nonblocking mutex contention and abandoned-reader recovery. An independent Python reader checks real Windows named objects, DACL contents, simultaneous HTTP/MQTT/CSV, stale data while holding the reader mutex, retained-handle collision, restart identity, shutdown under a held lock, writer death and abandoned-reader rejection. Invalid virtual input retains null current bytes/WKC/AL and historical last-good data, with INIT and zero-output audits. The C header is compiled with layout assertions and checked against authored snapshot bytes. These results do not qualify native GUI operation, physical EtherCAT input/timing or another user's access token. The selected-device GUI-plus-logger-plus-consumer bench run remains pending. C ABI/C# embedding remains [planned](interfaces-roadmap.md).

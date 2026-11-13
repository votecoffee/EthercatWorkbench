# Operating EtherCAT Workbench

This guide is the starting point for the portable Windows app and headless CLI. Extract a verified ZIP beside its `samples` and `docs` folders. The GUI is `ethercat-workbench.exe`; commands below use `ethercat-workbench-cli.exe` from that folder. Offline workflows need no Npcap runtime. Native raw Ethernet uses a separately installed x64 Npcap driver/runtime and its access policy. See [installation/build prerequisites](../README.md#install) and the [source/backend review](ethercrab-review.md).

## Choose the evidence and target

Use `samples/synthetic.json` for generated inputs, the matching `samples/virtual*.json` for the selected in-memory ESC model, and `samples/synthetic-replay.json` for authored raw-frame replay. They provide no physical device evidence. Put vendor ESI files, selected-NIC profiles, raw captures and receipts in ignored `.local/`.

For a physical bench, first obtain the exact model/revision, licensed ESI location, isolated NIC identifier and input value plus an independent way to vary/observe it. The roadmap records the pending selection; a new chat should verify current user context. Do not assume that a matching byte count proves a matching device or PDO layout.

## Import a description or configure manually

```powershell
.\ethercat-workbench-cli.exe esi-list .local/device.xml
.\ethercat-workbench-cli.exe esi-import .local/device.xml --device 0 --out .local/imported.json
.\ethercat-workbench-cli.exe validate .local/imported.json
.\ethercat-workbench-cli.exe review-pdos .local/imported.json
```

Choose the exact ESI device/revision entry, not just its display name. The importer retains ESI filename/hash and identity, supported PDO candidates, defaults and timing annotations. [PDO selection](pdo-selection.md) describes offline alternatives, padding, SyncManager alignment and unsupported module/virtual annotations. [Sync review](esi-sync-review.md) covers staged DC modes and unresolved device-dependent timing. These operations do not download mappings or apply DC settings.

For manual setup, edit/save a profile through GUI sections **1** and **3**, or use a new JSON profile based on an appropriate sample. Configure exact expected identity, Tx/Rx lengths, bit offsets/widths, numeric/raw types and transformations. `Field.source` identifies the definition as manual, ESI or override. Live PDO verification is separate discovered evidence. Staged output values are manual offline entries even when their field definitions came from ESI.

Profiles use schema 1 with defaults for omitted settings and validation on load/save. Saves create new paths, use UTF-8 and flush. Preserve the source profile when preparing variants. Typed staging has its own preview/apply guard; [output staging](output-staging.md) explains ranges, overlaps, zero initialization and provenance.

## Decode and stage offline

```powershell
.\ethercat-workbench-cli.exe decode samples/synthetic.json '04 00 00 00 00 00 80 3F'
.\ethercat-workbench-cli.exe decode samples/synthetic.json 'FE FF' --rx
.\ethercat-workbench-cli.exe stage-rx samples/output-staging.json --set '2=-1234' --out .local/staged.json
```

In the GUI, inspect raw/typed payloads in section **3**. Typed staging prepares a frozen preview, shows overlapping views and updates only the offline staged image after Apply. Saving or loading staged bytes does not publish them. The native cycle remains input-only.

## Exercise the pipeline headlessly

```powershell
.\ethercat-workbench-cli.exe run samples/synthetic.json --seconds 3 --csv .local/synthetic.csv --report .local/synthetic-run.json
.\ethercat-workbench-cli.exe run samples/virtual-segmented.json --backend virtual --virtual-model coe-segmented --seconds 3 --csv .local/virtual.csv --report .local/virtual-run.json
.\ethercat-workbench-cli.exe run samples/synthetic.json --backend replay --replay samples/synthetic-replay.json --seconds 2 --csv .local/replay.csv --report .local/replay-run.json
.\ethercat-workbench-cli.exe verify-capture .local/virtual-run.json .local/virtual.csv
```

Use fresh paths. Runs reserve new report paths before starting; CSV rotation preserves existing parts and reports failures/losses. Replay must finish its fixture; playback timestamps are host execution timestamps. Virtual models exercise the shared EtherCrab setup/cleanup using authored memory transport. Their normal/segmented upload policy changes after private initialization and does not resolve the earlier expedited-only initializer gap for arbitrary devices.

For saved PCAPNG containing several capture interfaces, use `inspect-pcap .local/bench.json .local/capture.pcapng --interface 1 --out .local/interface-1.json`, or select **PCAPNG interface** in desktop saved-file review. Choose the actual Ethernet interface ID from the file, not a Windows adapter index. A sole interface can be selected automatically; multiple descriptors require an explicit choice. The [capture guide](pcap-inspection.md) defines schema-3 inventory/excluded counts, original packet indexes and timing isolation. Malformed excluded records still fail validation.

## Interpret timing, quality and losses

The requested host period (1,000 us is a bench target), configured/discovered synchronization/DC settings, host send/receive spacing and saved capture timestamps are different evidence. Deadline scheduling skips elapsed slots; stock relative scheduling rebases its next dispatch. Neither gives Windows hard real-time guarantees.

The logger can record every valid exchange, including unchanged values, or selected-bit changes. Its bounded preallocated queue and batched writer are separate from cyclic I/O. Rows retain UTC capture start, near-receive monotonic elapsed microseconds, sample index, connection generation and cycle index. Compare expected/actual WKC, AL status/code, reply timeouts, transport errors, missed deadlines and logger overruns separately. An input-loss policy stops sustained unusable input and performs the approved cleanup; there is no automatic reinitialization or reconnect.

Use [CSV audits](capture-audit.md) for saved-file structure/hash/loss accounting and [scheduler comparisons](benchmark-comparison.md) for compatible repeated trials. Exported review JSON is not a new run report. The desktop's section **4** exposes saved review on a cancellable file worker. [Desktop review](desktop-review.md) and [PCAP/PCAPNG inspection](pcap-inspection.md) explain capture clocks, unsupported traffic and validity limits. Stale data and last-good values must not be described as current valid input.

## Discover and qualify a physical bench

`nics` enumerates driver interface identifiers without transmitting. On the user-identified isolated NIC, `scan --nic 'identifier'` sends read datagrams for bus position, station/port and AL diagnostics. It is not initialization and does not confirm PDO meaning. [ESC diagnostics](esc-diagnostics.md) describe static snapshots and unknown codes/counters.

Before native `run --backend safeop`, obtain approval for the concrete profile/NIC/device and initialization scope: EtherCrab ESC setup, SM/FMMU configuration from existing mappings, SAFEOP entry and INIT teardown. Only then use `--approve-esc-writes`. It does not authorize OP, output publishing, PDO downloads or other configuration writes. Those paths are unimplemented and need a separate reviewed contract/approval.

Confirm one SubDevice, identity/revision, sizes/layout, clear AL status, expected WKC and disabled-SYNC policy before relying on input. Establish whether the chosen device provides valid SAFEOP input with an independently observed change. Do not enter OP merely to obtain data without separate approval. The agreed benchmark must use the selected device with GUI and CSV active, repeated deadline/relative runs and recorded settings/outcomes. Request desktop interaction only when the user has explicitly authorized it in that chat.

For stop/close or Ctrl+C, let the session perform INIT confirmation and drain the writer. Keep cleanup failures and incomplete outcomes visible; do not label an ambiguous operation successful or repeat a write automatically.

## Software consumers and Codex

Use the opt-in [read-only HTTP input feed](http-input-feed.md) from GUI section **2** or `run --http-port PORT`. It binds only 127.0.0.1, serves status/latest/bounded history/setup metadata after backend setup and closes at run completion. Read-only consumers do not change hardware authorization. Check stream identity, freshness, invalid/null payloads and independent interface losses. CSV and saved inspection/review JSON remain available. The opt-in [MQTT input publisher](mqtt-input-feed.md) uses a trusted local broker, latest-value sampling, non-retained QoS 0 and independent queue/coalescing/network counters. The opt-in [Windows shared-memory input](shared-input-feed.md) offers a fixed raw/quality snapshot and an independent reader example; check stream/process identity, QPC age and contention/shutdown counters. Use the portable [native reader/inspector](shared-input-review.md) for one-shot IPC reads and saved-byte review without Python, with optional exact-effective-profile typed decoding. The desktop [saved snapshot reviewer](desktop-review.md#inspect-a-saved-shared-input-snapshot) uses the same historical decoder, with raw/current-frozen-profile/saved-run mapping choices and cancellable file jobs. Optional C-compatible embedding is [planned](interfaces-roadmap.md).

To install the bundled operating skill for future Codex chats, run `powershell -File tools/install-skill.ps1` from the package/repo. The installer records that application's root, preserves unrelated skill files and rejects modified managed files. The source skill is [here](../skills/ethercat-workbench/SKILL.md). Refresh the skill catalog in a new chat/session if the current session has already loaded its catalog.

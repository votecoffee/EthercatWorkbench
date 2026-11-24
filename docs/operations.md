# Operating EtherCAT Workbench

This guide is the starting point for the portable Windows app and headless CLI. Extract a verified ZIP beside its `samples` and `docs` folders. The GUI is `ethercat-workbench.exe`; commands below use `ethercat-workbench-cli.exe` from that folder. Offline workflows need no Npcap runtime. Native raw Ethernet uses a separately installed x64 Npcap driver/runtime and its access policy. See [installation/build prerequisites](../README.md#install) and the [source/backend review](ethercrab-review.md).

## Navigate the desktop

Use **Profiles…** to load/save settings, **Device** for ESI selection, **Mappings** for input/output definitions and ESI mode choices, **Logging** to arm CSV, then **Connect…** to review an offline or approved SAFEOP session. Successful starts select **Inputs**. **Outputs** stages bytes offline. **Integration**, **Diagnostics** and **Review** hold optional feeds, detailed evidence and saved-file tools. Stop/cancel controls stay above the tabs. Settings are locked during session/discovery/file work. The [desktop workflow guide](desktop-workspace.md) covers each page, popup and state boundary.

**Profiles…** uses separate load and create-new save paths. Resolve any unsaved draft before changing profiles, loading the demo, or closing. The save, discard, and cancel choices are described in [Save and replace profiles](desktop-workspace.md#save-and-replace-profiles).

## Check host prerequisites

In **Device**, choose **Host prerequisites…**, then explicitly **Check host metadata**. The isolated bench connection review links to the same window and clears its setup acknowledgement when leaving that review. Opening the window performs no query. Host reads and JSON export run in a background worker and are exclusive with acquisition, discovery and saved-file work. Closing the window retains its job/results; normal application close waits for host work to finish. The JSON export uses a fresh `.json` path and preserves existing files.

Use `check-runtime`, optionally with `--out NEW.json`, to inspect Npcap host files, service state and recorded access policy. It reads Windows metadata without opening an adapter or invoking Npcap exports. A successful collection or `present_unprobed` status is not a capture-permission or device test. The [host-check guide](runtime-check.md) explains missing/unavailable values, literal file versions, export behavior and the remaining commissioning steps.

## Review a proposed SAFEOP session

**Connect… → Isolated bench / SAFEOP** shows configured identity/PDO sizes, requested host cycle/duration and CSV settings. These are expectations, not device readback. Raw RxPDO staging and ESI timing hints stay offline; device synchronization readback is collected during approved setup and runtime DC/SYNC remains disabled. The acknowledgement/start controls stay below the scrolling details.

A valid profile, selected NIC and exact expected identity are required before acknowledging. A successful read-only scan reporting zero or multiple devices on that same NIC blocks the one-device preflight until corrected/rescanned. A scan is optional; neither absence of a scan nor a single historical result proves current compatibility. Physical, virtual and other-NIC results have separate labels. A failed scan is not a successful zero-device observation. A scan worker retains the NIC/model chosen when it started.

Acknowledgement binds the full effective profile, run duration, normalized CSV destination and discovery scope/data. Changing those settings, refreshing NICs, starting/completing a new scan, closing/reopening review or changing its source clears it. Profile save paths and offline decoder text do not change the run plan. Native setup independently validates actual device count, identity, PDO and AL evidence; this UI preflight does not replace authorization or device qualification.

## Choose the evidence and target

Use the [virtual group TxPDO readback](input-group.md#read-txpdo-descriptors-from-the-virtual-group) to collect modeled CoE and SII descriptors, compare their field offsets and save reusable evidence. [Replay with one PDO evidence file](input-group.md#replay-with-one-pdo-evidence-file) checks those descriptors against the raw setup replies for each generation. For a complete virtual report it also reconstructs the descriptors from the saved CoE and SII transactions. [Embedded PDO setup](input-group.md#capture-pdo-setup-inside-the-replay-fixture) keeps a separate raw transcript for each virtual generation in the group fixture. Use [offline input groups](input-group.md) to review ordered profiles, check saved register and TxPDO assignment evidence, check virtual station order and mapping readback, generate replies, replay replies to CSV and export audited evidence for relocation. Use the [two-station DC rehearsal](input-group.md#rehearse-two-distributed-clocks) to check distribution WKC, follower time difference and which modeled cycles qualify for input. [Clock-qualified CSV replay](input-group.md#replay-clock-qualified-inputs) rebuilds those decisions from saved raw replies and audits the resulting rows. Replay and audit recheck the saved raw topology probes and FMMU/SyncManager replies for each generation in newly generated fixtures. The topology-change scenario also tests station order during cyclic reads and a hold until fresh setup. The [three-station rehearsal](input-group.md#rehearse-a-group-with-a-no-pdo-station) includes an input-free station in topology and AL validation. The [three-station DC rehearsal](input-group.md#rehearse-three-distributed-clocks) verifies that station's clock as well as the other follower's before accepting PDO input. Its [topology-change scenario](input-group.md#monitor-station-order-after-the-clock-check) checks order on the same frame as the PDO read and holds input after a swap. The [modeled reconnect](input-group.md#requalify-the-clocks-after-a-modeled-reconnect) checks fresh setup and independent clock qualification in the second generation. Desktop [Grouped capture review](desktop-review.md#review-a-grouped-capture-bundle) verifies a portable bundle and shows the rebuilt cycle results and setup topology evidence. Physical cyclic setup still requires one SubDevice.

Use `samples/synthetic.json` for generated inputs, the matching `samples/virtual*.json` for the selected in-memory ESC model, and `samples/synthetic-replay.json` for authored raw-frame replay. They provide no physical device evidence. Put vendor ESI files, selected-NIC profiles, raw captures and receipts in ignored `.local/`.

For a physical bench, first obtain the exact model/revision, licensed ESI location, isolated NIC identifier and input value plus an independent way to vary/observe it. The roadmap records the pending selection; a new chat should verify current user context. Do not assume that a matching byte count proves a matching device or PDO layout.

## Import a description or configure manually

```powershell
.\ethercat-workbench-cli.exe esi-list .local/device.xml
.\ethercat-workbench-cli.exe esi-import .local/device.xml --device 0 --out .local/imported.json
.\ethercat-workbench-cli.exe validate .local/imported.json
.\ethercat-workbench-cli.exe review-pdos .local/imported.json
```

Choose the exact ESI device/revision entry, not just its display name. Use `esi-import --identity VENDOR/PRODUCT/REVISION` for a unique exact match, or combine it with `--device INDEX` to guard that entry. Decimal, `0x` and `#x` unsigned 32-bit components are supported; zero is literal. Missing or ambiguous matches create no profile. The [exact selection guide](pdo-selection.md#select-an-exact-esi-device) explains duplicate identities and source-provenance limits. The importer retains ESI filename/hash and identity, supported PDO candidates, defaults and timing annotations. [PDO selection](pdo-selection.md) describes offline alternatives, padding, SyncManager alignment and unsupported module/virtual annotations. [Sync review](esi-sync-review.md) covers staged DC modes and unresolved device-dependent timing. These operations do not download mappings or apply DC settings.

For a modular ESI, expand **Device → ESI modules and slots** to inspect declared slot choices and local PDO templates. The imported image uses device-level PDOs. Module placement and the composed layout require separate verification. [Modular ESI review](pdo-selection.md#review-modular-device-declarations)

Use `preview-modular-pdos` for explicit module choices in fixed, ungrouped slots. It shows resolved indexes and SyncManager hints from the selected ESI. [Fixed-slot preview](pdo-selection.md#preview-pdo-indexes-for-fixed-module-slots)

Add `--run-report` to compare those candidates with the matching device's saved PDO descriptors and SyncManager placement. [Readback comparison](pdo-selection.md#compare-module-candidates-with-saved-pdo-readback)

With the same saved report, pass `--tx-hex` or `--rx-hex` to decode a complete supplied payload at the saved bit positions of matched device and module PDOs. [Modular payload decode](pdo-selection.md#decode-a-modular-payload-from-saved-placement)

Use `export-modular-profile` to save the matched device and module fields and complete image lengths as an offline profile. Load it in **Profiles…** for the existing decoder, or reuse it through the CLI. [Profile export](pdo-selection.md#export-a-reusable-modular-decoder-profile)

Use `--module-inventory` to review configured and detected module IDs from saved CoE values. A complete detected list can supply the fixed-slot choices. [Module inventory review](pdo-selection.md#review-saved-module-identities)

Use `read-virtual-module-inventory --out .local/virtual-modules.json` to collect a fixed-slot sample in PREOP on the in-memory transport. Add `--pdo-report .local/virtual-pdos.json` to collect the PDO layout in the same session. The CLI reports unavailable evidence and confirms the final INIT state. [Virtual module inventory](pdo-selection.md#collect-module-inventory-in-the-simulator)

For an empty optional fixed slot, supply `--slot INDEX=0` with all other slot choices, or use a complete detected list containing an explicit zero at that position. [Optional fixed slots](pdo-selection.md#review-an-empty-optional-slot)

Use `--scenario grouped-fixed-slots` with `samples/grouped-fixed-slot-pdos.esi.xml` to exercise group-relative PDO indexes and the normal offline export. [Fixed slot groups](pdo-selection.md#resolve-fixed-slot-groups)

For an ESI declaration with equal positive instance limits, supply each expanded position in order or use a complete detected list. `--scenario repeated-fixed-slots` rehearses a two-instance declaration followed by a distinct slot. [Repeated fixed slots](pdo-selection.md#expand-fixed-count-slot-declarations)

Supply `--slot-count DECLARATION=COUNT` for each variable repeatable declaration before using manual slots or a detected list. A count of zero omits a declaration whose minimum permits it. [Variable slot counts](pdo-selection.md#choose-variable-slot-counts)

Use `--scenario mixed-slot-group-indexes` with `samples/mixed-slot-group-pdos.esi.xml` to review templates that combine slot-dependent mappings with group-dependent entries. [Slot and group indexes](pdo-selection.md#mix-slot-and-group-indexes-in-a-pdo-template)

Use `--scenario pdo-group-alignment` with `samples/module-pdo-group-alignment.esi.xml` to review device and module PDO groups and observed padding boundaries. Profile export rejects a group order, membership or padding conflict. [PDO group order and padding](pdo-selection.md#review-module-pdo-groups-and-padding)

Use `preview-modular-pdos --expect-layout FILE` with an explicit ordered assignment request to calculate an expected process image. With `--run-report` it compares the complete expected assignment and descriptors against saved readback. The `pdo-group-multiple-sync-managers` scenario rehearses whole groups on separate channels. The `pdo-group-split-across-sync-managers` scenario uses `samples/module-pdo-split-group.esi.xml` and `samples/module-pdo-expected-split.json` to review explicit padding for a split group. [Expected modular layout](pdo-selection.md#compose-an-expected-modular-pdo-image)

For manual setup, edit/save a profile through **Device**, **Mappings** and **Profiles…**, or use a new JSON profile based on an appropriate sample. Configure exact expected identity, Tx/Rx lengths, bit offsets/widths, numeric/raw types and transformations. `Field.source` identifies the definition as manual, ESI or override. Live PDO verification is separate discovered evidence. Staged output values are manual offline entries even when their field definitions came from ESI.

Profiles use schema 1 with defaults for omitted settings and validation on load/save. Saves create new paths, use UTF-8 and flush. Preserve the source profile when preparing variants. Typed staging has its own preview/apply guard; [output staging](output-staging.md) explains ranges, overlaps, zero initialization and provenance.

Use `preview-register-pdos ESI --device INDEX` to review device-level virtual TxPDO register addresses. Add `--snapshot FILE` to see the historical bytes that the saved ESC snapshot covers. Add `--fmmu FILE --station ADDRESS` to check their logical placement. Split placements list the logical range for each segment. Add `--logical-payload FILE` to reassemble an addressed payload through those checked ranges. Use `--lrd-reply FILE` for a saved Workbench frame. Schemas 1 through 3 require an explicit expected Working Counter. Schema 2 checks the selected station's AL status in the same reply. Schema 3 also checks station count, order and conflicting aliases. Schema 4 derives the expected Working Counter from the complete saved FMMU table and withholds fields where another station has an active read mapping in the same logical range. [Register-backed virtual TxPDOs](pdo-selection.md#review-virtual-txpdos-backed-by-esc-registers)

Use `preview-pdo-layout ESI --device INDEX --expect-layout REQUEST` to compose an offline device PDO image. An explicit entry list can fill an entryless virtual device PDO template. Add `--run-report` for an exact comparison with saved CoE descriptors. [Virtual PDO templates](pdo-selection.md#preview-an-entryless-virtual-pdo-template)

Use `inspect-pdo-readback PROFILE RUN_REPORT` to review the saved PDO layout for the profile's expected device. Add `--tx-hex` or `--rx-hex` to inspect raw values using observed entry positions. Use `export-observed-pdo-profile` to save a new offline decoder with supported ESI types or explicit `--tx-kind` and `--rx-kind` choices. [Saved dynamic PDO readback](pdo-selection.md#inspect-saved-dynamic-pdo-readback)

## Decode and stage offline

```powershell
.\ethercat-workbench-cli.exe decode samples/synthetic.json '04 00 00 00 00 00 80 3F'
.\ethercat-workbench-cli.exe decode samples/synthetic.json 'FE FF' --rx
.\ethercat-workbench-cli.exe stage-rx samples/output-staging.json --set '2=-1234' --out .local/staged.json
```

In the GUI, inspect raw/typed inputs in **Inputs** (or **Offline decoder…**) and staged outputs in **Outputs**. Typed staging prepares a frozen preview, shows overlapping views and updates only the offline staged image after Apply. Saving or loading a profile preserves staged bytes for explicit use. The native cycle remains input-only. Use [`rehearse-output`](output-staging.md#rehearse-an-rxpdo-write) to exercise a staged CoE profile through a single simulated output exchange, with per-step WKC and AL evidence. An optional [frozen output plan](output-staging.md#review-a-bench-output-plan) adds the reviewed safe image, optional serial check, modeled OP deadline and watchdog readback to the virtual sequence.

## Exercise the pipeline headlessly

Use `samples/mode-sync-managers.esi.xml` with `esi-import --device 0 --dc-mode 0 --out` for authored mode-specific SyncManager hints, then `review-sync PROFILE` to compare offline PDO choices. Optional `--readback SAVED_RUN` compares available exact-channel CoE SyncType values. Selecting a mode changes no PDO assignments or runtime DC settings. The separate `stage-mode-pdos PROFILE` CLI action previews supported hints; `--out NEW.json` saves the candidate for GUI loading. In **Mappings → ESI synchronization**, **Stage PDO choices from the selected ESI mode** provides the same frozen preview and explicit offline apply; use **Profiles… → Save new** afterward. Rx layout changes with staged bytes require a fresh discard choice, and profile edits or active acquisition/discovery/review invalidate pending previews. Review the [mode staging rules](pdo-selection.md#stage-pdo-choices-from-an-esi-mode), especially rebuilt decoder fields and `--clear-staged-rx` when Rx layout changes. The [ESI timing/SM guide](esi-sync-review.md#mode-specific-syncmanager-hints) distinguishes matched, different, unavailable and unresolved evidence.

```powershell
.\ethercat-workbench-cli.exe run samples/synthetic.json --seconds 3 --csv .local/synthetic.csv --report .local/synthetic-run.json
.\ethercat-workbench-cli.exe run samples/virtual-segmented.json --backend virtual --virtual-model coe-segmented --seconds 3 --csv .local/virtual.csv --report .local/virtual-run.json
.\ethercat-workbench-cli.exe run samples/synthetic.json --backend replay --replay samples/synthetic-replay.json --seconds 2 --csv .local/replay.csv --report .local/replay-run.json
.\ethercat-workbench-cli.exe verify-capture .local/virtual-run.json .local/virtual.csv
```

Use fresh paths. Runs reserve new report paths before starting; CSV rotation preserves existing parts and reports failures/losses. Replay must finish its fixture; playback timestamps are host execution timestamps. Virtual models exercise the shared EtherCrab setup/cleanup using authored memory transport. `rehearse-dc` separately checks SYNC0 or SYNC0+SYNC1 activation, clock and input replies, and deactivation on the [virtual DC path](ethercrab-review.md#virtual-sync0-rehearsal). Their normal/segmented upload policy changes after private initialization and does not resolve the earlier expedited-only initializer gap for arbitrary devices. Virtual faults `init-normal-upload` and `init-segmented-upload` intentionally reproduce the earlier rejection using samples/virtual.json. They return failed setup reports, record the injected mapping object/reply form and confirm INIT without cyclic I/O or CSV creation. The [source review](ethercrab-review.md#initializer-compatibility-fixtures-in-version-027) gives commands and limits; these fixtures do not identify a physical device's policy.

For saved PCAPNG containing several capture interfaces, use `inspect-pcap .local/bench.json .local/capture.pcapng --interface 1 --out .local/interface-1.json`, or select **PCAPNG interface** in desktop saved-file review. Choose the actual Ethernet interface ID from the file, not a Windows adapter index. A sole interface can be selected automatically; multiple descriptors require an explicit choice. The [capture guide](pcap-inspection.md) defines schema-4 inventory/excluded counts, original packet indexes, declared capture statistics and timing isolation. Capture-tool snapshots remain separate; missing counters mean unavailable and are not zero. Malformed excluded records still fail validation.

The virtual backend allows 100 ms per EEPROM wait to absorb short host scheduling pauses during setup. The native EEPROM deadline is 10 ms. The 15 ms setup PDU deadline is shared and an injected `setup-timeout` still fails before cyclic input. See [Virtual EEPROM setup timing](ethercrab-review.md#virtual-eeprom-setup-timing).

## Interpret timing, quality and losses

Optional `synchronization.coe_cycle` values are setup-only CoE cycle/minimum snapshots, in nanoseconds, with exact object indexes and explicit unavailable reasons. They are not refreshed by cyclic I/O and do not automatically change host timing. The [timing guide](esi-sync-review.md#coe-cycle-and-minimum-cycle-snapshots) covers zero, missing values, optional aborts and malformed-reply cleanup.

The requested host period (1,000 us is a bench target), configured/discovered synchronization/DC settings, host send/receive spacing and saved capture timestamps are different evidence. Deadline scheduling skips elapsed slots; stock relative scheduling rebases its next dispatch. Neither gives Windows hard real-time guarantees. Version 0.31 separately records host spacing between valid PDO inputs in `valid_receive_spacing`, independent of on-change CSV selection. Inspect that gap alongside all received replies and WKC/AL/timeout counters; the [timing guide](benchmark-comparison.md#valid-input-spacing) distinguishes unrecorded, zero intervals and measured values.

The logger can record every valid exchange, including unchanged values, or selected-bit changes. Its bounded preallocated queue and batched writer are separate from cyclic I/O. Rows retain UTC capture start, near-receive monotonic elapsed microseconds, sample index, connection generation and cycle index. Compare expected/actual WKC, AL status/code, reply timeouts, transport errors, missed deadlines and logger overruns separately. An input-loss policy stops sustained unusable input and performs the approved cleanup; there is no automatic reinitialization or reconnect.

Use [CSV audits](capture-audit.md) for saved-file structure/hash/loss accounting and [scheduler comparisons](benchmark-comparison.md) for compatible repeated trials. Exported review JSON is not a new run report. The desktop's **Review** tab exposes saved review on a cancellable file worker. [Desktop review](desktop-review.md) and [PCAP/PCAPNG inspection](pcap-inspection.md) explain capture clocks, unsupported traffic and validity limits. Stale data and last-good values must not be described as current valid input.

## Discover and qualify a physical bench

Use the [first bench session guide](bench-qualification.md) for a virtual rehearsal, setup worksheet and physical trial evidence checklist.

`nics` enumerates driver interface identifiers without transmitting. On the user-identified isolated NIC, `scan --nic 'identifier'` sends read datagrams for bus position, station/port and AL diagnostics. It is not initialization and does not confirm PDO meaning. [ESC diagnostics](esc-diagnostics.md) describe static snapshots and unknown codes/counters.

Before native `run --backend safeop`, obtain approval for the concrete profile/NIC/device and initialization scope: EtherCrab ESC setup, SM/FMMU configuration from existing mappings, SAFEOP entry and INIT teardown. Only then use `--approve-esc-writes`. It does not authorize OP, output publishing, PDO downloads or other configuration writes. Those paths are unimplemented and need a separate reviewed contract/approval.

Confirm one SubDevice, identity/revision, sizes/layout, clear AL status, expected WKC and disabled-SYNC policy before relying on input. Establish whether the chosen device provides valid SAFEOP input with an independently observed change. Do not enter OP merely to obtain data without separate approval. The agreed benchmark must use the selected device with GUI and CSV active, repeated deadline/relative runs and recorded settings/outcomes. Request desktop interaction only when the user has explicitly authorized it in that chat.

For stop/close or Ctrl+C, let the session perform INIT confirmation and drain the writer. Keep cleanup failures and incomplete outcomes visible; do not label an ambiguous operation successful or repeat a write automatically.

## Software consumers and Codex

Use the opt-in [read-only HTTP input feed](http-input-feed.md) from **Integration** or `run --http-port PORT`. It binds only 127.0.0.1, serves status/latest/bounded history/setup metadata after backend setup and closes at run completion. Read-only consumers do not change hardware authorization. Check stream identity, freshness, invalid/null payloads and independent interface losses. CSV and saved inspection/review JSON remain available. The opt-in [MQTT input publisher](mqtt-input-feed.md) uses a trusted local broker, latest-value sampling, non-retained QoS 0 and independent queue/coalescing/network counters. The opt-in [Windows shared-memory input](shared-input-feed.md) offers a fixed raw/quality snapshot and an independent reader example; check stream/process identity, QPC age and contention/shutdown counters. Use the portable [native reader/inspector](shared-input-review.md) for one-shot IPC reads and saved-byte review without Python, with optional exact-effective-profile typed decoding. The desktop [saved snapshot reviewer](desktop-review.md#inspect-a-saved-shared-input-snapshot) uses the same historical decoder, with raw/current-frozen-profile/saved-run mapping choices and cancellable file jobs. Optional C-compatible embedding is [planned](interfaces-roadmap.md).

To install the bundled operating skill for future Codex chats, run `powershell -File tools/install-skill.ps1` from the package/repo. The installer records that application's root, preserves unrelated skill files and rejects modified managed files. The source skill is [here](../skills/ethercat-workbench/SKILL.md). Refresh the skill catalog in a new chat/session if the current session has already loaded its catalog.

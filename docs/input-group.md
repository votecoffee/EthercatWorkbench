# Offline input groups

Use the CLI to inspect the layout of one planned Logical Read (LRD) across multiple SubDevices and decode a complete saved LRD payload. A group manifest references existing schema 1 profiles and can be moved with its relative profile files.

```powershell
.\ethercat-workbench-cli.exe inspect-input-group samples/input-group.json
.\ethercat-workbench-cli.exe inspect-input-group samples/input-group.json --hex "2a 00 01 00 00 00 80 3f 12 34 00 00 00 00 00 40" --wkc 2 --out .local/group-decode.json
.\ethercat-workbench-cli.exe inspect-input-group samples/input-group.json --frame samples/input-group-frame.json
.\ethercat-workbench-cli.exe inspect-input-group samples/input-group.json --fmmu samples/input-group-fmmu.json --frame samples/input-group-frame.json
.\ethercat-workbench-cli.exe inspect-input-group samples/input-group.json --fmmu samples/input-group-fmmu.json --sync-managers samples/input-group-sync-managers.json --frame samples/input-group-frame.json
.\ethercat-workbench-cli.exe inspect-input-group samples/input-group.json --fmmu samples/input-group-fmmu.json --sync-managers samples/input-group-sync-managers.json --pdo samples/input-group-pdo.json --frame samples/input-group-frame.json
```

The bundled manifest uses two authored virtual device profiles. The first occupies bytes 0–7 and the second bytes 8–15. With WKC 2, the example decodes counters 42 and 13,330, boolean values true and false, and floating-point values 1 and 2. Each device reports its raw bytes and local field offsets, widths, source labels and decoded values.

## Prepare a manifest

1. Save one validated profile for each expected bus position. Enter its exact vendor, product and revision and check its TxPDO size and typed fields.
2. Copy the bundled manifest and set each row's `position`, `profile` and `identity`. Keep the rows in zero-based bus order with no gaps. Profile paths can be absolute or relative to the manifest's folder. Workbench requires the row identity and profile identity to match exactly.
3. Inspect the group. The report lists source profile hashes, per-device offsets and TxPDO lengths, the total read size and expected WKC. Devices without TxPDO bytes keep their positions with null offsets and no WKC contribution.
4. To decode, pass the full LRD data field as hex bytes and pass that datagram's WKC. Workbench withholds decoding if either the length or WKC differs from the plan. An optional `--out` saves the inspection to a new JSON path.

This planner supports 1–16 positions and up to 1,024 input bytes in one datagram with byte-aligned, contiguous ranges beginning at logical address zero. It assumes each nonempty device input image is mapped to its planned range and can be read. In that layout each successfully addressed ESC contributes one to the LRD WKC. WKC counts successful ESC reads and cannot establish that all bytes were read, identify a missing position, or qualify per-device AL state. [Beckhoff ESC technology reference, sections 2.3.2 and 2.4](https://download.beckhoff.com/download/document/io/ethercat-development-products/ethercat_esc_datasheet_sec1_technology_v2.5.pdf)

## Inspect a saved group reply

Use `--frame` with a schema 1 JSON file containing the expected datagram `index` (0–255), ordered `stations` (one unique nonzero address per manifest position), and `reply_hex` containing the full Ethernet II reply without FCS. The bundled example is authored. The reader matches Workbench's returned source address and the datagram headers. The expected chain starts with the planned LRD and then has one configured-address physical read (FPRD) of six bytes at AL register `0x0130` for each station. AL status and code come from `0x0130` and `0x0134`. [Beckhoff ESC command reference](https://download.beckhoff.com/download/document/io/ethercat-development-products/ethercat_esc_datasheet_sec1_technology_v2.5.pdf), [Beckhoff AL register reference](https://download.beckhoff.com/download/document/io/ethercat-development-products/ethercat_esc_datasheet_sec2_registers_3i0.pdf)

For a matched reply, the report retains the raw-frame SHA-256, aggregate LRD WKC, and each position's AL read WKC and decoded status. An AL read with WKC other than 1 has null status. `frame.valid` requires the planned LRD WKC and clean SAFEOP at every listed position, including devices with zero TxPDO bytes. Clean SAFEOP means state SAFEOP, clear error flag, and status code zero. Other AL bits remain visible. Any failed check leaves all `input` values null. An invalid matched reply can still be exported as a diagnostic result. A structurally mismatched or malformed frame fails the command without creating an export.

The original `--hex` and `--wkc` options decode a payload by itself. They cannot be combined with a saved frame or FMMU snapshot.

## Check a saved FMMU snapshot

Use `--fmmu` to check the configured logical input ranges. Copy the schema 1 sample and record one row per manifest position, in bus order. Supply the station address, the single-byte supported-channel count read from `0x0004` and all reported 16-byte FMMU register images in slot order, starting at `0x0600`. Each read includes its actual WKC and value. Store register images as arrays of 16 decimal bytes. [Beckhoff ESC register reference, sections 2.4 and 2.47](https://download.beckhoff.com/download/document/io/ethercat-development-products/ethercat_esc_datasheet_sec2_registers_3i0.pdf)

The check requires WKC 1 for the count and every declared slot. Each station's active read-enabled mappings must cover its entire planned byte slice without gaps, overlap or extra ranges. Multiple adjacent mappings are supported. Disabled and write-only mappings remain visible and contribute no input bytes. A position with no TxPDO bytes must have no active read mapping. For input mappings, logical start bit, logical stop bit and physical start bit must be 0, 7 and 0, respectively. The check reports each physical start and rejects address overflow. [Beckhoff FMMU technology reference, section 7](https://download.beckhoff.com/download/document/io/ethercat-development-products/ethercat_esc_datasheet_sec1_technology_v2.5.pdf)

With `--frame`, the inspector also compares station addresses in order. It requires `frame.valid` and `fmmu.valid` before decoding. A structurally readable snapshot with coverage or WKC issues can still be exported as diagnostics. The report hashes the supplied FMMU JSON bytes and retains the per-slot reads.

## Check saved SyncManager registers

Use `--sync-managers` with `--fmmu` to check each station's physical input mapping. Use the same station order and record the supported-channel count from `0x0005` and every eight-byte channel starting at `0x0800`. The schema 1 sample keeps the raw bytes and actual WKC for each read. WKC 1 is required for the count and each reported slot. [Beckhoff ESC register reference, sections 2.5 and 2.48](https://download.beckhoff.com/download/document/io/ethercat-development-products/ethercat_esc_datasheet_sec2_registers_3i0.pdf)

The audit compares the physical coverage of read-enabled FMMUs with the first-buffer address ranges of enabled, buffered EtherCAT-read SyncManagers. The ranges must match exactly and cannot overlap or alias. An eligible input range cannot overlap another enabled channel's first buffer. An input disabled by its PDI fails the check. Mailbox and output channels remain visible. The report lists the FMMU slots that intersect each input buffer and keeps each raw read. [Beckhoff ESC technology reference, section 8.1](https://download.beckhoff.com/download/document/io/ethercat-development-products/ethercat_esc_datasheet_sec1_technology_v2.5.pdf)

When a frame is supplied, decoding requires `frame.valid`, `fmmu.valid` and `sync_managers.valid`. This check covers the declared first-buffer geometry.

## Check saved TxPDO assignments

Use `--pdo` with `--fmmu` and `--sync-managers`. The schema 1 file lists one station and exact vendor, product and revision per position. Include the device's ordered TxPDO layout in `tx`, with an explicit `mapping_source` of `coe` or `sii`. Each SyncManager lists the assigned PDOs and the ordered 32-bit object, subindex and bit-width descriptors, including padding. Zero-input positions use an explicit empty layout. An unavailable layout can be recorded as `tx: null` with a `tx_unavailable` reason and leaves the audit invalid. [Beckhoff TxPDO assignment example](https://infosys.beckhoff.com/content/1033/el5042/4217274123.html)

Workbench compares descriptor widths and positions against fields with PDO references. It compares the complete assignments when the profile has an explicit ESI PDO selection. Manual fields retain their manual interpretation. The audit then checks that each SyncManager's TxPDO bytes occupy the correct logical offset through the saved FMMUs. Two buffers can cover the right physical and logical ranges while landing in the wrong logical order. With `--frame`, decoding also requires `pdo.valid`.

Use all saved evidence from the same configuration. The reports retain file hashes, per-field checks and per-SyncManager placements. Live device identity, PDO readback, snapshot freshness, ESC-specific buffer allocation, and physical unit swaps still require separate evidence.

## Read back the virtual group mapping

```powershell
.\ethercat-workbench-cli.exe inspect-virtual-group-mapping samples/input-group.json --out .local/virtual-mapping.json
.\ethercat-workbench-cli.exe inspect-virtual-group-mapping samples/input-group.json --scenario swapped-stations
```

Read-only topology probes bracket the fixed-address FMMU and SyncManager reads. Each probe uses broadcast WKC as the station count and auto-increment reads to collect the configured station address and alias at each planned position. `inspection.topology` retains both raw frame replies, each position's WKC, the observed count and whether the two observations agree. Station address and alias are unavailable at a position whose read WKC differs from one. The overall check requires the planned order and count at both observations, plus valid logical byte ranges and physical input buffers. [Beckhoff ESC technology reference, sections 2.3 and 2.4](https://download.beckhoff.com/download/document/io/ethercat-development-products/ethercat_esc_datasheet_sec1_technology_v2.5.pdf) · [Beckhoff ESC register reference, sections 2.9 and 2.10](https://download.beckhoff.com/download/document/io/ethercat-development-products/ethercat_esc_datasheet_sec2_registers_3i0.pdf)

The report retains the FMMU and SyncManager reads and their per-position findings. A channel-count read with WKC other than one, or a count above 16, prevents slot reads for that bank. Other banks remain visible. `stations_match` compares the addresses in the mapping evidence. Consult `inspection.topology` for observed traversal order.

The default `clean` scenario passes. `swapped-stations` keeps each station's mapping intact while reversing its position. `swap-during-readback` changes the chain after the first probe. `extra-station` increases broadcast WKC to three while the two planned addresses remain in order. `duplicate-station` assigns both devices the first address. `position-wkc` returns WKC two for the downstream position read. Each case fails topology checks. `logical-shift` and `physical-shift` change mapping geometry. `station-missing` moves the expected downstream address, and `excess-channels` reports slot counts of 255. A failed check returns a diagnostic report with `valid: false`. Inspection sends no cyclic traffic. The grouped input and DC generators require successful preflight on their own in-memory wire.

The nested `fmmu_snapshot` and `sync_manager_snapshot` objects use the same schema as the saved snapshot files. Save each object to its own JSON file to use it with `inspect-input-group` or replay. Their `source_sha256` values in the preflight report identify the compact JSON object bytes. A separately saved file may have different formatting and a different hash. Review of actual TxPDO descriptors still uses separate `--pdo` evidence.

## Rehearse two distributed clocks

```powershell
.\ethercat-workbench-cli.exe rehearse-group-dc samples/input-group-dc.json --period-ns 700000 --difference-limit-ns 500 --out .local/group-dc.json
.\ethercat-workbench-cli.exe rehearse-group-dc samples/input-group-dc.json --scenario follower-stale
```

The sample uses two authored CoE/DC SubDevices at `0x1000` and `0x1001`. The rehearsal checks their station order, FMMUs and SyncManagers, then reads the seeded SYNC0 activation and period from both stations. Each cycle sends an eight-byte FRMW to `0x0910`. The reference supplies the timestamp and the follower consumes it. The expected aggregate WKC is 2. A subsequent FPRD frame reads each station's system time and the follower's filtered system time difference at `0x092C`. The separate frame allows for the ESC's end-of-frame difference update. [Beckhoff ESC technology reference, sections 2.4 and 9.1.3.3](https://download.beckhoff.com/download/document/io/ethercat-development-products/ethercat_esc_datasheet_sec1_technology_v2.5.pdf) · [Beckhoff ESC register reference, section 2.49.2](https://download.beckhoff.com/download/document/io/ethercat-development-products/ethercat_esc_datasheet_sec2_registers_3i0.pdf)

A cycle needs FRMW WKC 2, WKC 1 for each fixed-address read, a reference readback matching the FRMW payload, both clocks increasing from the last accepted observation, and an absolute filtered difference at or below `--difference-limit-ns`. The register stores received time minus follower local time as sign and magnitude. The report also shows raw follower time minus raw reference time separately. The raw subtraction does not set the acceptance limit. After clock acceptance, the grouped LRD still needs its expected WKC and both stations in clean SAFEOP before exposing inputs.

`follower-wkc`, `follower-stale`, `follower-offset`, `difference-read-wkc` and `reference-regression` inject a fault on cycle two. Diagnostic runs still return a report. Check `clock_rejections`, `valid_input_cycles` and each cycle's `clock.issues`. A clock failure leaves `input` null and skips the LRD. Set `--cycles` from 1 to 64. The default 1,000,000 ns SYNC0 period advances authored time without pacing the host. The virtual wire audit records FRMW distribution separately from configuration, state requests and PDO writes. Physical DC initialization, propagation compensation, phase convergence and measured frame intervals require bench evidence.

## Replay clock-qualified inputs

```powershell
.\ethercat-workbench-cli.exe generate-group-dc-replay samples/input-group-dc.json --scenario follower-stale --period-ns 700000 --cycles 8 --out .local/dc-frames.json
.\ethercat-workbench-cli.exe replay-input-group samples/input-group-dc.json .local/dc-frames.json --csv .local/dc.csv --out .local/dc-replay.json
.\ethercat-workbench-cli.exe verify-group-replay samples/input-group-dc.json .local/dc-frames.json .local/dc-replay.json .local/dc.csv
```

The generator uses the same clock and mapping checks as `rehearse-group-dc`. It saves a schema 4 fixture for the two authored CoE/DC stations, with raw setup topology and mapping replies, raw SYNC0 readback, the declared difference limit, and the FRMW and FPRD replies for each cycle. The fixture contains any matched grouped input reply. Replay checks the setup and raw clock frames, then reevaluates the gate in cycle order before opening the CSV. It rejects a fixture that attaches input bytes or an input timestamp to a cycle whose clocks fail.

Inspect `counts.clock_rejections` and each cycle's `clock.issues` in the replay receipt. An unanswered LRD after accepted clock checks counts under `unmatched_cycles`. When an LRD matches, its own input WKC and AL still determine whether it can reach the writer. In the example, the follower returns full WKC with a stale time in cycle two. Every-valid mode logs seven rows, with a 1,400 µs gap between the first two samples. The CSV keeps the original cycle indexes and consecutive sample indexes. `--on-change` writes cycles one and six for this example. Writer mode and rotation do not change the spacing statistics.

The generator derives elapsed microseconds from the modeled cycle index and SYNC0 period. The raw clock differences and saved elapsed times describe an authored offline run. Use the same fixture for `verify-group-replay` and `bundle-group-replay`. The audit rebuilds the clock decisions from the raw frames and checks the CSV rows, including when reopening a moved bundle. Older input-only schema 1 and DC schema 2 replay fixtures still work.

## Rehearse three distributed clocks

```powershell
.\ethercat-workbench-cli.exe rehearse-group-dc samples/input-group-dc-three.json --scenario middle-follower-stale
.\ethercat-workbench-cli.exe generate-group-dc-replay samples/input-group-dc-three.json --scenario middle-follower-stale --period-ns 700000 --cycles 8 --out .local/dc-three-frames.json
.\ethercat-workbench-cli.exe replay-input-group samples/input-group-dc-three.json .local/dc-three-frames.json --csv .local/dc-three.csv --out .local/dc-three-replay.json
.\ethercat-workbench-cli.exe verify-group-replay samples/input-group-dc-three.json .local/dc-three-frames.json .local/dc-three-replay.json .local/dc-three.csv
```

The sample has a reference at `0x1000` and followers at `0x1001` and `0x1002`. The middle station has zero configured PDO bytes. All three take part in the modeled FRMW exchange, which expects WKC 3. The PDO read expects WKC 2 and still checks AL for all three stations. Setup reads SYNC0 configuration at each address. A subsequent FPRD frame checks the reference and each follower's time and filtered difference. [Beckhoff ESC technology reference, sections 2.4 and 9.1.3.3](https://download.beckhoff.com/download/document/io/ethercat-development-products/ethercat_esc_datasheet_sec1_technology_v2.5.pdf)

Each follower must advance and stay within the supplied difference limit before the generator requests the PDO input. The first follower stays at `clock.follower` and `clock.difference`. `clock.additional_followers` records the other follower with its readback and issues. `middle-follower-stale` holds the no-PDO station's time on cycle two. The standard follower fault scenarios target the last follower in this sample. The reference-regression scenario still targets the reference.

Replay and bundle audit reconstruct the independent clock checks from the saved frames. The eight-cycle stale-middle example writes seven rows, with PDO columns for positions 0 and 2. This rehearsal uses authored clocks and timestamps.

## Generate a two-device replay

```powershell
.\ethercat-workbench-cli.exe generate-group-replay samples/input-group.json --scenario faults --out .local/virtual-group.json
.\ethercat-workbench-cli.exe replay-input-group samples/input-group.json .local/virtual-group.json --csv .local/virtual-group.csv --out .local/virtual-group-replay.json
.\ethercat-workbench-cli.exe verify-group-replay samples/input-group.json .local/virtual-group.json .local/virtual-group-replay.json .local/virtual-group.csv
```

The generator uses the sample CoE and SII virtual identities in that order, each with eight TxPDO bytes and two RxPDO bytes. It verifies station order and register mappings on the same virtual wire before the first LRD of each modeled generation. Each cyclic exchange then sends the planned LRD and per-station AL reads through both in-memory ESCs. The fixture saves 12 cycles over two modeled connection generations and wraps the datagram index from 255 to 0. Each device produces its own counter, bit and float values. The default `clean` scenario yields 12 valid cycles. `faults` yields seven valid cycles and exercises downstream PREOP, a nonzero AL code with full LRD WKC, a changed station address, a stale candidate, a late reply and a missing reply. Replay with `--on-change` yields three rows in either scenario.

Generated fixtures and replay receipts include `virtual_scenario`. The fixed UTC anchor and nominal 1,000 µs spacing are fixture data. They exercise the timing calculations. Host scheduling and physical frame spacing require a separately measured run. The generator uses memory only and requires a new output file.

## Verify saved setup topology

Schema 4 fixtures and the monitored schema 5 fixture include setup topology. Each entry in `setup_topology` binds a connection generation to two raw replies, one before and one after its mapping reads. Replay requires one pair for every generation in the cycle stream, in the same order. It checks the raw datagram structure and increasing probe indexes, broadcast and per-position WKC, configured station addresses, and stability of observed addresses and aliases. Copies of one probe cannot serve as both observations.

A missing or invalid pair stops replay before it creates the CSV. The receipt retains the rebuilt observations. Group audit requires agreement with the original fixture bytes and the rebuilt receipt, and reports `verified_topology_generations`. Portable bundle verification repeats this check using the copied fixture. The setup probes record evidence at those observations. The saved mapping snapshots and individual cyclic replies have their own checks.

Schema 3 fixtures keep the same topology checks. Schema 1 input-only and schema 2 DC fixtures remain usable and omit the topology fields from their receipts and audits.

## Verify saved setup mapping

In schema 4 and 5 fixtures, each `setup_topology` entry also contains `mapping_replies`. The list holds the FMMU and SyncManager register replies between that generation's two setup probes. Replay rebuilds the expected sequence from the station order and the reported channel counts. It checks each reply against its expected datagram index, station address, register offset, and width. It then checks WKC and the logical and physical mapping geometry before creating a CSV.

The replay receipt retains the rebuilt mapping per generation and the audit reports `verified_mapping_generations`. A missing reply, changed mapping or invalid register WKC can stop replay while the recorded cyclic replies still look healthy. The verified portable bundle retains the original fixture bytes.

Optional `--fmmu` and `--sync-managers` files must describe the same register reads as the fixture in each generation. JSON formatting may differ. `inspect-virtual-group-mapping` exposes the corresponding snapshots for the authored input-only group. Optional `--pdo` evidence still has its own descriptor and placement checks. Older schema 1–3 fixtures follow their original mapping evidence rules.

## Rehearse a group with a no-PDO station

```powershell
.\ethercat-workbench-cli.exe inspect-virtual-group-mapping samples/input-group-three.json
.\ethercat-workbench-cli.exe generate-group-replay samples/input-group-three.json --scenario faults --out .local/three-station-frames.json
.\ethercat-workbench-cli.exe replay-input-group samples/input-group-three.json .local/three-station-frames.json --csv .local/three-station.csv --out .local/three-station-replay.json
.\ethercat-workbench-cli.exe verify-group-replay samples/input-group-three.json .local/three-station-frames.json .local/three-station-replay.json .local/three-station.csv
```

The authored group contains a CoE input station at `0x1000`, an SII station with zero configured PDO bytes at `0x1001`, and an SII input station at `0x1002`. The two input stations each contribute eight bytes. The middle station keeps its place in topology and AL checks and has inactive FMMU and SyncManager slots. The setup broadcast WKC is 3 and the expected LRD WKC is 2. The CSV has fields for positions 0 and 2.

`clean` accepts all 12 cycles. `faults` applies PREOP, an AL error, and a changed configured address to the middle station. Its LRD WKC stays at 2, and the replay records the three AL failures separately. This fixture accepts seven cycles. `topology-change` swaps the final two positions during generation one. Replay withholds two mismatched cycles and four later cycles held for fresh setup. The six accepted cycles include all four cycles from the newly verified second generation.

The same portable bundle workflow archives and rechecks the three profiles, including the no-PDO profile. The setup and cycle evidence comes from the authored virtual wire.

## Rehearse a station swap during acquisition

```powershell
.\ethercat-workbench-cli.exe generate-group-replay samples/input-group.json --scenario topology-change --out .local/topology-change.json
.\ethercat-workbench-cli.exe replay-input-group samples/input-group.json .local/topology-change.json --csv .local/topology-change.csv --out .local/topology-change-replay.json
.\ethercat-workbench-cli.exe verify-group-replay samples/input-group.json .local/topology-change.json .local/topology-change-replay.json .local/topology-change.csv
```

This scenario creates a monitored schema 5 fixture. Each cyclic reply carries the grouped LRD, per-station AL reads, then a broadcast count and position-based reads of the configured station addresses and aliases. Replay checks the matched reply against the last verified setup observation for its connection generation. A changed count, address, order or alias, or a wrong position WKC, withholds the sample and latches that generation. After the expected topology returns, the generation stays held until a fresh setup passes.

The two stations swap during cycles 3 and 4 of generation 1 while LRD WKC stays at 2 and AL stays clean SAFEOP. Those replies count as `topology_rejections`. The following four cycles match the setup again and count as `topology_hold_rejections`. Generation 2 passes a fresh setup check and accepts all four inputs. Every-valid mode writes six rows overall. On-change mode writes the first accepted row of each generation. Desktop **Review → Grouped capture** shows the observed station order and separates the two rejection counts.

Bundle audit rebuilds the topology decisions from the raw cyclic replies. Schema 1–4 fixtures keep their original frame rules. The scenario uses an in-memory wire and an authored receive timeline.

## Replay group cycles to CSV

```powershell
.\ethercat-workbench-cli.exe replay-input-group samples/input-group.json samples/input-group-replay.json --csv .local/group.csv --out .local/group-replay.json
.\ethercat-workbench-cli.exe replay-input-group samples/input-group.json samples/input-group-replay.json --csv .local/group-changes.csv --on-change --rotate-rows 2
```

A replay fixture supplies a UTC capture-start anchor, a fixed ordered station list and up to 4,096 cycles. Each cycle records the connection generation, cycle index, expected datagram index and up to 64 received Ethernet candidates in order. A matching reply must be last. Supply its recorded `elapsed_us`, or null when no reply matches. Matched timestamps must be nondecreasing. The replay checks the complete fixture before it opens the CSV. To apply the saved configuration checks, pass the same optional `--fmmu`, `--sync-managers` and `--pdo` files used by the inspector.

The replay uses the existing bounded CSV writer. Columns follow bus order and use the profile's selected fields, prefixed by position. Every-valid logging includes unchanged values. On-change logging records the first valid row of a generation and subsequent selected-field changes. Invalid cycles do not enter the writer or its change comparison. CSV rows keep the recorded UTC anchor and elapsed receive time, their sample index, the connection generation and the cycle index. Rotation uses numbered parts and preserves existing files.

The receipt records match and quality evidence by cycle, independent WKC and AL failures, ignored candidates, and selected/written rows and overruns. Receive spacing uses the saved clock, with exact nearest-rank percentiles for matched replies and valid input separately within each generation. The command replays without pacing and measures no host deadline or physical bus timing. A write failure leaves completed CSV parts and reports the incomplete capture.

## Verify a saved group CSV

```powershell
.\ethercat-workbench-cli.exe verify-group-replay samples/input-group.json samples/input-group-replay.json .local/group-replay.json .local/group.csv --out .local/group-audit.json
```

Supply the original manifest, profiles, raw frame fixture, replay receipt, and CSV base name. Reuse any `--fmmu`, `--sync-managers` and `--pdo` evidence supplied when creating the capture. For rotation, give the base name without the numbered suffix.

The audit rebuilds the recorded cycles, timing, and selection from the original inputs. It checks every row against the group payload, including the timestamp, sample index, generation, cycle index and typed field text. On-change verification uses the selected bits, so two distinct NaN encodings can correctly appear as consecutive `NaN` values. The audit checks headers and part boundaries and returns SHA-256 hashes of the saved receipt, raw frame fixture and every CSV part it read.

A completed capture must contain all selected rows and sets `complete` to true. When the receipt records a writer failure, the audit can verify the exact saved prefix. It sets `complete` to false and retains the capture error. It reads only the declared parts and preserves the input files. Saved evidence covers the supplied offline sequence and mapping.

## Export and reopen group evidence

```powershell
.\ethercat-workbench-cli.exe bundle-group-replay samples/input-group.json samples/input-group-replay.json .local/group-replay.json .local/group.csv --out .local/group-bundle
.\ethercat-workbench-cli.exe verify-group-bundle .local/group-bundle --out .local/bundle-audit.json
```

Supply the same optional FMMU, SyncManager and PDO files used for the original replay. Export audits the source first and copies its verified bytes into a new directory. It archives the manifest, frame fixture, replay receipt, profiles, mapping evidence and declared CSV parts. `bundle.json` records their lengths and SHA-256 hashes. It is written after the copied evidence has been flushed.

Use `verify-group-bundle` with the folder at its new location. It loads the copied profiles by manifest position, checks the fixed inventory and reruns the group audit using the copies. The original manifest and receipt retain their path strings as saved evidence. Completed captures and verified prefixes of interrupted captures can be exported. Check `complete`, `verified_rows` and `expected_rows` in the receipt.

The desktop opens these same bundles in [Review → Grouped capture](desktop-review.md#review-a-grouped-capture-bundle), with verified row counts, saved timing and problem-cycle details.

Live SAFEOP sessions require exactly one isolated SubDevice. Live grouped acquisition remains on the [roadmap](../ROADMAP.md).

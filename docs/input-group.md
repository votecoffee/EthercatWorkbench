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

## Replay group cycles to CSV

```powershell
.\ethercat-workbench-cli.exe replay-input-group samples/input-group.json samples/input-group-replay.json --csv .local/group.csv --out .local/group-replay.json
.\ethercat-workbench-cli.exe replay-input-group samples/input-group.json samples/input-group-replay.json --csv .local/group-changes.csv --on-change --rotate-rows 2
```

The schema 1 replay fixture supplies a UTC capture-start anchor, a fixed ordered station list and up to 4,096 cycles. Each cycle records the connection generation, cycle index, expected datagram index and up to 64 received Ethernet candidates in order. A matching reply must be last. Supply its recorded `elapsed_us`, or null when no reply matches. Matched timestamps must be nondecreasing. The replay checks the complete fixture before it opens the CSV. To apply the saved configuration checks, pass the same optional `--fmmu`, `--sync-managers` and `--pdo` files used by the inspector.

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

Live SAFEOP sessions require exactly one isolated SubDevice. Live grouped acquisition remains on the [roadmap](../ROADMAP.md).

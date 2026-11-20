# Offline input groups

Use the CLI to inspect the layout of one planned Logical Read (LRD) across multiple SubDevices and decode a complete saved LRD payload. A group manifest references existing schema 1 profiles and can be moved with its relative profile files.

```powershell
.\ethercat-workbench-cli.exe inspect-input-group samples/input-group.json
.\ethercat-workbench-cli.exe inspect-input-group samples/input-group.json --hex "2a 00 01 00 00 00 80 3f 12 34 00 00 00 00 00 40" --wkc 2 --out .local/group-decode.json
.\ethercat-workbench-cli.exe inspect-input-group samples/input-group.json --frame samples/input-group-frame.json
.\ethercat-workbench-cli.exe inspect-input-group samples/input-group.json --fmmu samples/input-group-fmmu.json --frame samples/input-group-frame.json
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

With `--frame`, the inspector also compares station addresses in order. It decodes the frame only if both `frame.valid` and `fmmu.valid` are true. A structurally readable snapshot with coverage or WKC issues can still be exported as diagnostics. The report hashes the supplied FMMU JSON bytes and retains the per-slot reads. Use evidence from the same device configuration. These saved files do not establish the age of a snapshot, validate physical SyncManager or PDO assignments, or distinguish identical units swapped on the bus.

Live SAFEOP sessions still require exactly one isolated SubDevice. Live identity and PDO binding, configured FMMU readback, topology changes and grouped cyclic logging remain on the [roadmap](../ROADMAP.md).

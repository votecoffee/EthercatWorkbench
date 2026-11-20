# Offline input groups

Use the CLI to inspect the layout of one planned Logical Read (LRD) across multiple SubDevices and decode a complete saved LRD payload. A group manifest references existing schema 1 profiles and can be moved with its relative profile files.

```powershell
.\ethercat-workbench-cli.exe inspect-input-group samples/input-group.json
.\ethercat-workbench-cli.exe inspect-input-group samples/input-group.json --hex "2a 00 01 00 00 00 80 3f 12 34 00 00 00 00 00 40" --wkc 2 --out .local/group-decode.json
```

The bundled manifest uses two authored virtual device profiles. The first occupies bytes 0–7 and the second bytes 8–15. With WKC 2, the example decodes counters 42 and 13,330, boolean values true and false, and floating-point values 1 and 2. Each device reports its raw bytes and local field offsets, widths, source labels and decoded values.

## Prepare a manifest

1. Save one validated profile for each expected bus position. Enter its exact vendor, product and revision and check its TxPDO size and typed fields.
2. Copy the bundled manifest and set each row's `position`, `profile` and `identity`. Keep the rows in zero-based bus order with no gaps. Profile paths can be absolute or relative to the manifest's folder. Workbench requires the row identity and profile identity to match exactly.
3. Inspect the group. The report lists source profile hashes, per-device offsets and TxPDO lengths, the total read size and expected WKC. Devices without TxPDO bytes keep their positions with null offsets and no WKC contribution.
4. To decode, pass the full LRD data field as hex bytes and pass that datagram's WKC. Workbench withholds decoding if either the length or WKC differs from the plan. An optional `--out` saves the inspection to a new JSON path.

This planner supports 1–16 positions and up to 1,024 input bytes in one datagram with byte-aligned, contiguous ranges beginning at logical address zero. It assumes each nonempty device input image is mapped to its planned range and can be read. In that layout each successfully addressed ESC contributes one to the LRD WKC. WKC counts successful ESC reads and cannot establish that all bytes were read, identify a missing position, or qualify per-device AL state. [Beckhoff ESC technology reference, sections 2.3.2 and 2.4](https://download.beckhoff.com/download/document/io/ethercat-development-products/ethercat_esc_datasheet_sec1_technology_v2.5.pdf)

Treat the identity, position and WKC as offline expectations and supplied evidence. Identical device identities can occupy different positions, and the file cannot distinguish two units of the same revision that were swapped on the bus. Inspection uses the manifest, referenced profiles and supplied sample values. Live SAFEOP sessions still require exactly one isolated SubDevice. Live identity/PDO binding, per-device AL gating, topology changes and grouped cyclic logging remain on the [roadmap](../ROADMAP.md).

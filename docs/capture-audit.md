# Offline CSV capture audit

`verify-capture REPORT CSV_BASE` reads a saved run report and its declared CSV files without bus operations or file changes. It requires the versioned effective-profile context introduced in Workbench 0.10. Older reports without that context must be recollected. The result hashes the exact report bytes and each CSV part read, records the auditor and recorded application versions, and retains rows, encoding, record terminators, index gaps and run outcome. Reported valid/invalid exchanges, reply timeouts, WKC/AL mismatches and transport errors remain separate from logger overruns.

```powershell
.\ethercat-workbench-cli.exe run samples/synthetic.json --seconds 3 --csv .local/trial.csv --report .local/trial.json
.\ethercat-workbench-cli.exe verify-capture .local/trial.json .local/trial.csv
```

Pass the original CSV base path, including `.csv`, even when rotation produced only `trial.0001.csv`, `trial.0002.csv`, and so on. With rotation disabled, the base file is read directly. Parts are derived from the report's rotation setting and part count. Every declared part is required, and its row count must match the rotation and written totals. Files outside that declared sequence are not inspected or removed. A header-only capture with zero valid samples can pass structural auditing; it does not establish usable input.

## Checked evidence

- The report's profile hashes, CSV-enabled setting, selected fields, timing settings and exchange counters must be consistent. Selected, written and overrun counts must balance, and every-valid mode must have selected all reported valid exchanges.
- Each part must have the five metadata columns followed by the selected field names in profile order. Metadata names cannot be reused as field names. Headers retain quoted commas, quotes and Unicode names.
- Every row must retain the report's exact UTC capture anchor and connection generation. Elapsed microseconds cannot decrease. Sample and cycle indexes must be positive, strictly increasing across all parts, and stay within reported bounds. Cycle indexes can include skipped deadline slots. Sample-index gaps, including leading and trailing gaps, account for logger overruns separately from invalid exchanges.
- Unsigned and signed decimal values must fit their field widths. Boolean text must be `true` or `false`; raw values must be exact-length uppercase hex. Floating point values must use Workbench's canonical f32/f64 text. Non-finite values remain valid text and are counted with a warning.
- Every-valid mode permits unchanged values. On-change mode rejects repeated identical selected values unless NaN text makes the underlying bit changes ambiguous. Different NaN payloads can both display as `NaN`; an allowed repeat does not prove that the bits changed.

A failed or cancelled run can have a structurally valid, fully drained capture. Its original error/cancellation remains in the receipt with a warning. An incomplete writer, unbalanced counters, missing part, wrong row count, malformed metadata or invalid typed text causes failure. Auditing does not turn an unsuccessful run into an accepted benchmark.

## Format and limits

The accepted dialect is Workbench writer CSV: comma delimiter, double-quoted fields when needed, doubled embedded quotes, UTF-8 with an optional header BOM, and one physical record per row. Each part may use LF or CRLF consistently and must have a final newline. Extra quoting and malformed quote forms are rejected by parsing and comparing with the canonical writer representation. Embedded record separators are outside this format: profile field names cannot contain them, and logged typed values do not contain them. No whitespace, values or files are rewritten.

Reading is bounded to 16 MiB per report, 1 MiB per physical CSV record, 100,000 declared parts and 64 GiB of CSV bytes in total. Hashing and metadata checks run while streaming the records, outside cyclic I/O and the CSV writer. File length and modification metadata are checked for changes during each part's read. Audit completed, stable captures rather than files being written.

## Audited timing comparisons

Repeat `--csv` once per report, in the same order, to add audits to `compare-runs`:

```powershell
.\ethercat-workbench-cli.exe compare-runs .local/deadline.json .local/relative.json --csv .local/deadline.csv --csv .local/relative.csv
```

The result includes `csv_audits` and binds each audit to the corresponding report hash. Without `--csv`, comparison retains its original report-counter checks and sets `csv_audits` to null. Run compatibility, chronological order, device/PDO/sync checks and per-run percentile summaries are unchanged. See the [trial comparison procedure](benchmark-comparison.md).

These checks establish saved-file structure, typed text and metadata consistency. CSV does not retain the full payload, per-row WKC/AL evidence or all floating point bit patterns. The audit cannot independently establish PDO decoding, which individual cycles were valid, original payload bits or physical input meaning. Saved JSON and CSV can be edited together; hashes bind bytes read rather than provide signed runtime attestation. Physical device qualification, independent input observation and GUI-plus-logger timing remain separate bench work.

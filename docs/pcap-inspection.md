# Offline Ethernet capture inspection

Version 0.14 adds a headless inspector for saved **classic Ethernet PCAP 2.4** files. It reads a bounded file using Rust file I/O, without loading Npcap, opening a NIC or transmitting packets. The GUI's existing offline hex decoder remains available; PCAP inspection currently uses the CLI.

```powershell
.\ethercat-workbench-cli.exe inspect-pcap .local/bench.json .local/bench.pcap --station 0x1000 --preview 16 --out .local/inspection.json
```

Use the effective profile saved with the corresponding run. `--station` accepts decimal or `0x` hexadecimal and defaults to `0x1000`, EtherCrab's initial configured station address in the current one-device path. Supply the actual configured address when it differs. The address, profile identity, image length and field definitions are expectations supplied by the operator. This inspection does not discover or confirm device identity, mapping or field meaning.

The CLI writes JSON to stdout. Optional `--out` writes UTF-8 without a BOM and with a final newline, flushes it before stdout, and requires a new `.json` path. Existing files are preserved. Parse errors return a nonzero exit code and produce no inspection export. A structurally readable capture with no matching frames or invalid input quality still produces a report and exits successfully; inspect its counts and notes.

## Recognized frames and input quality

The inspector uses the same reply parser as the live input-only path. It recognizes untagged EtherType `0x88A4` frames with the Workbench MAC signature, one LRD at logical address zero of exactly the profile's TxPDO length, followed by one six-byte FPRD of AL status at the selected station's `0x0130`. Exact outbound Workbench frames are counted separately. Other EtherCAT traffic remains unmatched. This is a deliberately limited Workbench trace inspector, not a generic EtherCAT protocol analyzer.

For each recognized returned frame, input WKC must equal one, the AL-register WKC must equal one, the low five AL-status bits must equal SAFEOP with no error flag, and the AL code must equal zero to count as `valid_safeop_replies`. Input WKC and AL failures are counted independently and can overlap. A preview retains both WKCs, raw status and code, sequence, packet index, capture timestamp, raw payload and profile-decoded typed values. Invalid previews remain explicitly labeled; decoded bytes alone are not valid input evidence. All TxPDO fields are decoded, including fields excluded from logging, with the same bit, endian and word transformations as the offline payload decoder.

Requests and returned frames are counted independently. The inspector does not correlate pairs, discard duplicates, infer timeouts or create application cycle indexes, generations or missed-deadline counts. A reply can appear without its request in the saved file. Sequence reuse or a stale frame therefore does not establish a fresh exchange. This differs from live reply matching against one outstanding request and from the authored replay fixture's ordered candidates.

## Recorded timestamps and provenance

Reports retain raw-file SHA-256, byte count, full effective profile and its canonical JSON hash, application version, requested station, timestamp precision and the first/last packet timestamps. The first timestamp is also formatted as UTC. A metadata change detected during file reading rejects the result. Hashes identify the bytes analyzed; they are not signed provenance or an attestation of a physical capture.

Request spacing, returned-frame spacing and valid-returned-frame spacing are separate summaries. Each gives count, p50, p95, p99 and the exact longest gap, in nanoseconds. Percentiles use a three-significant-digit histogram. Zero gaps, including duplicate timestamps, are retained. With fewer than two matching frames, the gap count is zero and values are null. If any packet timestamp goes backward, all spacing summaries are null and the report retains the regression count and payload previews.

Capture timestamps use the clock and placement of the capture tool. The file does not establish whether timestamps were taken at injection, dequeue or the wire, whether the capture includes both directions, or how many packets the capture tool dropped. Declared nanosecond precision is not a measurement of accuracy. These summaries remain separate from the application's monotonic receive timestamps, configured device synchronization/DC settings and requested scheduler period. An external capture setup still needs qualification before its timestamps can support a physical timing claim.

## Bounds and unsupported input

- Maximum file size: 64 MiB; maximum packet count: 1,000,000. The file is read into bounded memory before parsing. Snapshot length must be 1–262,144 bytes. Every record length and timestamp fraction is checked before slicing.
- Both byte orders and microsecond/nanosecond timestamp variants of classic PCAP 2.4 are supported. The parser uses the public layout documented in [libpcap 1.10.5's savefile reader](https://github.com/the-tcpdump-group/libpcap/blob/libpcap-1.10.5/sf-pcap.c) and [file header definition](https://github.com/the-tcpdump-group/libpcap/blob/libpcap-1.10.5/pcap/pcap.h). It is an independent Rust implementation; no libpcap source is bundled or used for offline inspection.
- PCAPNG, modified/older PCAP formats, non-Ethernet link types and link-type words with additional FCS flags are rejected. Export classic Ethernet PCAP before inspection. VLAN-tagged traffic is counted as other traffic and is not unwrapped. No FCS validation is performed.
- A packet whose captured length is smaller than its declared original length is counted as snapshot-truncated and never decoded, even if its available bytes include the PDO. A physically truncated record or partial record header rejects the file.
- `--preview` is 0–64, default 16. All recognized frames contribute to counts and available spacing summaries; only the first requested number of returned frames retain payloads. Field names are bounded to 16 KiB combined for this report. There is no decoded CSV export or conversion into live/replay runs.

The verification workflow generates all binary PCAP fixtures under ignored `.local/`. No vendor capture is committed. Coverage is authored-file evidence; inspection of a selected physical device's capture remains pending.

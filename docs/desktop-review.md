# Saved run review in the desktop

Open **Review → Run reports and CSV** in the Windows application to review completed captures without using the CLI. Analysis reads saved files and performs no NIC enumeration, EtherCAT exchange, device setup or output writes. Report/CSV review uses the saved report's effective profile for decoding and logging settings. PCAP inspection instead freezes the currently edited commissioning profile when the inspection starts; a PCAP file supplies no verified mapping or device identity.

## Audit the latest desktop capture

After acquisition stops and CSV flush completes, **Logging** and **Diagnostics** show the completed run and its original CSV base. Review the suggested report destination, such as `capture.run.json` beside `capture.csv`, and choose **Save report and audit**. Existing files are preserved. If a save fails, choose a fresh destination and try again. **Save report** is available for exporting the report on its own.

Once the report is saved, **Audit saved capture** reopens that report and the original CSV files on the Review worker. The worker uses the run's frozen profile and the recorded number of parts. Edits to the current profile or the next CSV destination have no effect on those paths. The result appears on **Review → Run reports and CSV**, with the files and hashes it actually read. The latest-run controls remain available until the next session starts. To review older captures, enter their paths in the trial rows.

## Audit a capture

Enter a saved run JSON and its original CSV base path in a trial row, then choose **Audit this capture**. For a rotated capture, enter `capture.csv`, even when the files on disk are named `capture.0001.csv`, `capture.0002.csv`, and so on. Only the report's declared part sequence is read.

The result shows audited rows and parts, reported valid/invalid exchanges, reply timeouts, WKC/AL mismatches, transport errors, logger overruns and leading/interior/trailing sample-index gaps. Non-finite values and ambiguous NaN repeats remain visible. A structurally valid CSV from a failed or cancelled run retains that outcome prominently. Expand **Capture fields and file hashes** for field names and SHA-256 values. At most the first 32 part hashes are displayed; the exported JSON retains all of them.

## Compare schedulers

After saving a desktop run with CSV, choose **Add saved capture to comparison** in **Logging** or **Diagnostics**. From a completed CSV audit, choose **Add audited capture to comparison**. Workbench copies the report and original CSV base into the first empty trial row or appends a row. Partially entered rows are preserved, and adding the same report path again shows which row already contains it.

Arrange the trials by capture start and choose **Compare saved trials** when both schedulers are represented. Adding a pair records its paths. Comparison rereads the saved evidence and checks whether the trials are compatible. A capture can pass its CSV audit and still be ineligible for comparison, for example if the run was stopped early.

Add or remove trial rows and use **Up** / **Down** to put reports in capture-start order. Both Deadline and Stock relative must be present. Three trials per scheduler are recommended. Enter a CSV base for every report when **Audit CSV files during comparison** is selected, then choose **Compare saved trials**. Clear that checkbox for report-counter-only comparison; the CSV fields are then unused.

The comparison checks the same configuration, device/PDO/synchronization and evidence rules as `compare-runs`. It shows each trial's host send/receive p50, p95, p99 and longest gap separately, along with valid samples, timeouts, WKC/AL mismatches, missed deadlines, written rows and logger overruns. Scheduler summaries describe ranges of individual run p99 values. Percentiles are not pooled and the application does not declare a scheduler qualified or choose a winner.

**Inputs used** identifies the frozen input paths for the completed job. Editing path fields or reordering rows afterward does not relabel or recalculate that result. The input-file hashes bind the result to the bytes read during review; files changed afterward need a new review.

## Save and reopen a trial set

Under **Review → Run reports and CSV**, expand **Trial set files**. Enter a **New trial set JSON** path and choose **Save trial set**. Workbench creates the file at that path and preserves existing files. The set stores the ordered draft rows, including partial and empty rows, and the **Audit CSV files during comparison** setting. Keep private trial sets in `.local/` with the corresponding evidence.

Enter the saved path under **Existing trial set JSON**, then choose **Load trial set**. If you have populated rows or have turned off the audit option, confirm **Replace trial list** or choose **Keep current trial list**. Invalid files leave the current rows and option intact. Loading prepares the editor. Use **Compare saved trials** to read and check the referenced files. Completed results retain the inputs from their own review jobs.

References under the set's directory are saved as relative paths. Move or copy that directory as a unit to retain the links. Paths elsewhere are saved as absolute references and may require editing after a move. Trial sets contain file references, so retain the original reports and CSV parts alongside them.

Both the desktop and CLI read schema 1 UTF-8 JSON up to 2 MiB, with an optional BOM. The `trials` array holds 1–32 rows in display order. Each row has a `report` and `csv` string. Use an empty string for a missing path in a draft. Relative paths are resolved from the directory containing the trial set. The `audit_csv` boolean selects CSV audits when starting the comparison.

To run the saved comparison headlessly, use `ethercat-workbench-cli.exe compare-runs --trial-set .local/trials.json`. A comparison requires 2–32 complete report rows in capture-start order. The CLI identifies an incomplete report or CSV field by row number.

## Open a saved comparison

Choose **Review → Saved comparison** and enter a comparison JSON path. The view opens results written by desktop **Save new result** or `compare-runs --out FILE`. It reads schema 1 JSON up to 16 MiB and displays the saved file path and SHA-256, recorded timing and loss values, recorded CSV audit status, and trial file identifiers. Keep the JSON if someone needs the full warnings and original audit details. The view checks the result's structure and labels it as saved evidence. To check the original reports and CSV parts again, run a new comparison in **Run reports and CSV**.

## Check the source file hashes

Open a result in **Saved comparison**, expand **Source files and evidence export**, and choose **Check source hashes**. The app checks the reports and the CSV parts listed by the comparison. When the result uses relative paths, enter the original working folder in the field beside the button. Absolute paths are checked as recorded. Opening the comparison only reads its JSON. The separate check binds to the SHA-256 of the opened result, so reopen it if the result file has changed.

The check lists **Match**, **Changed**, **Missing**, **Unreadable**, or **Unresolved** per file. A changed CSV length is enough to flag the file. Files of the recorded length are hashed in chunks. The desktop shows up to 64 paths with exceptions first. For a full list, run `ethercat-workbench-cli.exe check-comparison .local/comparison.json --base . --out .local/source-check.json` from the comparison's original working folder. Omit `--base` for absolute references. The command prints JSON, including `all_match` and `csv_hashes_recorded`. A completed check returns success even when some entries differ. Use `all_match` to test the recorded paths in scripts, and `csv_hashes_recorded` to tell whether that covers CSV parts.

The match is against hashes stored in the selected comparison. When the comparison recorded report counters only, the check covers the report files. Run a new comparison with CSV auditing for a fresh audit of structure, values and timing evidence.

## Bundle comparison evidence

Open a comparison in **Review → Saved comparison** and expand **Source files and evidence export**. Enter the original working folder if the saved paths are relative. Enter a **New evidence folder** and choose **Export evidence bundle**. The export uses the opened comparison's SHA-256 and checks the source files again. The success message shows the completed folder and counts.

Use **Cancel file review** to stop copying. Closing the app requests cancellation and waits for the worker.

From the CLI, add `--base DIRECTORY` to the first command if the comparison uses relative source paths. Use its original working folder for that option.

```powershell
.\ethercat-workbench-cli.exe bundle-comparison .local/comparison.json --out .local/evidence
.\ethercat-workbench-cli.exe verify-bundle .local/evidence
.\ethercat-workbench-cli.exe compare-runs --bundle .local/evidence
```

The bundle preserves the original comparison byte for byte and gives the verified reports and CSV parts stable names under each trial folder. Use `trials.json` to rerun the analysis after moving the folder. Comparisons made with report counters alone include only report files. Keep bundles with private captures under ignored `.local/`.

The command requires a new destination directory. If the source check fails, run `check-comparison` for each file's status. A failure during copying can leave a partial folder. Use a new destination when retrying. A completed bundle contains a readable `bundle.json` with the comparison and trial-set hashes.

## Open and verify a bundle

In **Review → Saved comparison**, expand **Open evidence bundle**, enter the folder that contains `bundle.json`, and choose **Verify and open bundle**. Workbench uses that folder to look up the comparison and trial evidence. On success it shows the verified report and CSV part counts and opens the saved comparison. An incomplete or changed bundle reports the failed check.

Use `verify-bundle DIRECTORY` for the same check headlessly. A successful command prints the receipt, its SHA-256, and the verified report and CSV part paths and hashes. An incomplete or changed bundle returns a nonzero exit. Both checks require the schema 1 directory layout and ordinary bundle files and directories. They match bytes and references against the supplied receipt. Compare the receipt SHA-256 with a separately retained value when checking whether a copy is the same bundle.

## Recompare bundled trials

After verifying and opening a bundle, choose **Recompare bundled trials**. Workbench uses the folder and receipt hash of the opened bundle. It rereads the archived evidence in trial order, audits the CSV when the bundle includes it, and checks that the compared files still match the recorded hashes. The trial editor keeps its current draft. Use **Save new result** to export the fresh comparison to a new JSON file. If the receipt changed, verify and open the bundle again before retrying.

The equivalent headless command is `compare-runs --bundle DIRECTORY [--out NEW.json]`. It uses the receipt in the selected folder and returns an error if the evidence fails the checks. You can still use `compare-runs --trial-set DIRECTORY/trials.json` to run an ordinary comparison with the trial list.

## Inspect Ethernet PCAP

Load or edit the intended commissioning profile in **Device** and **Mappings** first. Choose **Review → Ethernet PCAP**, enter a classic Ethernet PCAP or supported PCAPNG path, its expected configured station address (decimal or `0x` hexadecimal), and a preview limit of 0–64. The default address `0x1000` is an expectation, not a value discovered from the file. Choose **Inspect PCAP with current profile**. Invalid profile/settings are rejected before a job starts. Version 0.23 supports up to 32 PCAPNG descriptors in one section. Leave **PCAPNG interface** blank for a sole interface or enter its ID (decimal or `0x`, 0–31). Multiple descriptors require an explicit selection; an ambiguity error lists IDs, link types and packet counts. Select Ethernet. A supplied interface choice on classic PCAP fails. All interfaces must use supported microsecond/nanosecond timestamps. Additional sections, generic EtherCAT dissection and VLAN decoding remain unsupported.

The result shows the capture format, independent request/returned-frame counts, valid SAFEOP frames, input WKC and AL status/WKC mismatches, unmatched EtherCAT, other/truncated/VLAN packets and timestamp regressions. PCAPNG results also show the selected interface, total versus excluded packet counts and a **Capture interface inventory** with each ID, link type, packet count, snapshot length and timestamp exponent/offset. Interface IDs are capture metadata, not verified physical NIC identities. Requests and replies are not paired, deduplicated or interpreted as fresh exchanges. Capture request, returned-frame and valid-returned-frame spacing have separate p50/p95/p99/longest-gap columns in **nanoseconds**. These use recorded capture timestamps, including any PCAPNG signed offset; the requested profile period is shown separately. Only selected-interface packets contribute to frame counts, first/last timestamps, regressions and spacing. A backwards timestamp on that interface makes all spacing summaries unavailable. Other interface clocks are never pooled; their malformed records still fail inspection. Version 0.24 also shows declared capture-tool statistics, with a prominent selected-interface drop indication and a scrollable list of all snapshots. Missing counters remain unavailable, explicit zeros remain zero and repeated snapshots are not summed. Other interfaces remain labeled as excluded. These declarations do not prove capture completeness or physical timing; [statistics details](pcap-inspection.md#declared-capture-statistics) describe bounds and semantics.

Expand the payload previews to see the original whole-file packet index (including excluded-interface positions), sequence, capture timestamp, both WKCs, raw AL status/code, decoded AL description, raw bytes and typed values with their profile provenance. Invalid input quality is labeled before showing its bytes and values. A preview limit of zero retains counts and available timing summaries without payloads. **Capture and profile hashes** identifies the analyzed file and frozen profile; **Inputs used** retains the job's station, limit and expected identity. Later profile/path edits do not change the completed result. Export JSON for all frozen profile settings, including ESI provenance and field transformations.

The same result and new-file export controls below apply to PCAP inspection. Its JSON matches `inspect-pcap`; it is not a run report for `compare-runs`. [PCAP inspection rules](pcap-inspection.md) describe format/size bounds, capture-clock limits and unsupported traffic. File consistency and a valid SAFEOP frame do not independently verify the physical device, PDO meaning, capture losses or timestamp accuracy.

## Inspect a saved shared-input snapshot

Version 0.22 adds **Inspect a saved shared-input snapshot** to **Review → Saved input snapshot**. Enter the path to a schema-1, 2560-byte `.bin` image, then choose **Raw/status only**, **Current profile (frozen)** or **Saved run's effective profile**. The report choice requires its saved run JSON path. Choose **Inspect saved snapshot**. These actions only read saved files; they do not open IPC objects, query a recorded process, compare against the current QPC clock or start a MainDevice session.

Raw/status mode leaves typed values absent. Current-profile mode freezes the entire edited profile when the job starts; later edits cannot change the result. Report mode reads the effective profile from that saved context on the worker. Both typed modes enforce the full canonical profile hash, TxPDO length and expected-identity agreement. A mismatch fails visibly; selecting raw/status is an explicit separate choice. Report-based mapping extraction does not qualify the run, prove that this snapshot came from it, or verify a physical PDO meaning. See [native shared-input review](shared-input-review.md) for exact profile and file bounds.

The result is prominently **Historical shared-input snapshot**. Recorded active/fresh flags remain recorded metadata, and current usability/age/liveness remain unavailable. It shows raw-byte/profile hashes, backend/stream/generation, UTC and monotonic publication clocks, requested host cycle versus publication/freshness settings, expected versus setup-observed identity, and independent bus/CSV/shared-consumer counters. Device/DC settings and mapping verification still require the original run/profile evidence. Live counter snapshots do not prove a final clean drain.

The latest recorded exchange shows expected/actual WKC, nullable AL state/code and input issue. Invalid latest input has no current payload or typed values. **Historical last-valid input** is separate, with its age at publication; its old WKC/AL readback is not stored in this binary format and is not invented. Expand raw/typed payloads to inspect complete raw TxPDO hex and verified-profile strings with definition provenance and bit/width. Text previews longer than 512 characters are marked as truncated; JSON export preserves complete values and definitions. A reserved/not-ready image shows no captured input or verified mapping. Unexpected live evidence is rejected by this saved-file view.

**Inputs used** retains the snapshot path and original raw/frozen-profile/report mapping choice, independently of later path/radio/profile edits. The common result export writes the same `shared_input_inspection` JSON as CLI `inspect-shared`; this is not a new run report. Source snapshots, profiles and reports are preserved. Native `read-shared` remains the one-shot live IPC consumer; this desktop panel only inspects saved bytes.

## Worker, cancellation and export

One background review worker runs at a time for report/CSV analysis, saved comparison viewing, PCAP inspection or saved shared-input review. New bus, discovery and review starts are disabled while it is running; review starts and exports are disabled while a bus or discovery job is active. File analysis runs outside the UI, cyclic I/O and CSV writer threads. Status updates are polled without waiting on an unfinished worker.

**Cancel file review** requests cooperative cancellation. Checks run between report reads, CSV buffer reads, records and parts. PCAP checks run between 64 KiB file reads, packet records and 64 KiB raw-file hash chunks. Shared-input jobs check cancellation before/after effective-profile loading and the bounded snapshot read/validation/decoding. An individual blocking file-system operation, profile validation/serialization or in-progress record parse cannot be interrupted immediately. A cancellation also discards a success that finished but had not yet been published. No result can be exported while the job is running, cancelling, cancelled or failed. There is no automatic retry.

Closing the window requests review cancellation without waiting for read-only file operations. Existing live-run close behavior still waits for the approved INIT cleanup and CSV drain. No review output is written automatically.

After a successful review, enter a fresh **New review JSON** path and choose **Save new result**. Export preserves existing files and writes UTF-8 JSON with a final newline and a clean flush. It saves the same audit, comparison, PCAP or shared-input inspection schema as the CLI, retaining the reviewed input hashes and applicable captured run outcome. It is a review result rather than a new run report. Export is an explicit write after review; source reports, CSVs, PCAP files, binary snapshots and commissioning profiles remain unchanged.

The file checks and their limits are documented in [CSV capture audit](capture-audit.md), [timing trial comparison](benchmark-comparison.md) and [PCAP inspection](pcap-inspection.md). Saved-file consistency does not independently establish PDO meaning, wire frame timing, physical input validity or hardware acceptance. Pure egui layout tests cover PCAP quality/timing and declared capture-statistics labels, shared-input historical/invalid/provenance labels and mapping/bus-exclusion guidance without opening a native window. Native GUI interaction has not been exercised by the headless checks. The agreed GUI-plus-logger physical benchmark remains pending the selected bench device and NIC.

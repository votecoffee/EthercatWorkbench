# Saved run review in the desktop

Open **4 Saved run review** in the Windows application to review completed captures without using the CLI. Analysis reads saved files and performs no NIC enumeration, EtherCAT exchange, device setup or output writes. The saved report's effective profile supplies the decoding and logging settings; the editable commissioning profile is not used to reinterpret the saved capture.

## Audit a capture

Enter a saved run JSON and its original CSV base path in a trial row, then choose **Audit this capture**. For a rotated capture, enter `capture.csv`, even when the files on disk are named `capture.0001.csv`, `capture.0002.csv`, and so on. Only the report's declared part sequence is read.

The result shows audited rows and parts, reported valid/invalid exchanges, reply timeouts, WKC/AL mismatches, transport errors, logger overruns and leading/interior/trailing sample-index gaps. Non-finite values and ambiguous NaN repeats remain visible. A structurally valid CSV from a failed or cancelled run retains that outcome prominently. Expand **Capture fields and file hashes** for field names and SHA-256 values. At most the first 32 part hashes are displayed; the exported JSON retains all of them.

## Compare schedulers

Add or remove trial rows and use **Up** / **Down** to put reports in capture-start order. Both Deadline and Stock relative must be present. Three trials per scheduler are recommended. Enter a CSV base for every report when **Audit CSV files during comparison** is selected, then choose **Compare saved trials**. Clear that checkbox for report-counter-only comparison; the CSV fields are then unused.

The comparison checks the same configuration, device/PDO/synchronization and evidence rules as `compare-runs`. It shows each trial's host send/receive p50, p95, p99 and longest gap separately, along with valid samples, timeouts, WKC/AL mismatches, missed deadlines, written rows and logger overruns. Scheduler summaries describe ranges of individual run p99 values. Percentiles are not pooled and the application does not declare a scheduler qualified or choose a winner.

**Inputs used** identifies the frozen input paths for the completed job. Editing path fields or reordering rows afterward does not relabel or recalculate that result. The input-file hashes bind the result to the bytes read during review; files changed afterward need a new review.

## Worker, cancellation and export

One background review worker runs at a time. New bus, discovery and review starts are disabled while it is running; review starts and exports are disabled while a bus or discovery job is active. Report/CSV analysis runs outside the UI, cyclic I/O and CSV writer threads. Status updates are polled without waiting on an unfinished worker.

**Cancel file review** requests cooperative cancellation. Checks run between report reads, CSV buffer reads, records and parts. An individual blocking file-system operation or an in-progress parse cannot be interrupted immediately. A cancellation also discards a success that finished but had not yet been published. No result can be exported while the job is running, cancelling, cancelled or failed. There is no automatic retry.

Closing the window requests review cancellation without waiting for read-only file operations. Existing live-run close behavior still waits for the approved INIT cleanup and CSV drain. No review output is written automatically.

After a successful review, enter a fresh **New review JSON** path and choose **Save new result**. Export preserves existing files and writes UTF-8 JSON with a final newline and a clean flush. It saves the same audit or comparison schema as the CLI, retaining the reviewed input hashes and captured run outcome. It is a review result rather than a new run report. Export is an explicit write after review; source reports, CSVs and commissioning profiles remain unchanged.

The file checks and their limits are documented in [CSV capture audit](capture-audit.md) and [timing trial comparison](benchmark-comparison.md). Saved-file consistency does not independently establish PDO meaning, wire frame timing, physical input validity or hardware acceptance. Native GUI interaction has not been exercised by the headless checks. The agreed GUI-plus-logger physical benchmark remains pending the selected bench device and NIC.

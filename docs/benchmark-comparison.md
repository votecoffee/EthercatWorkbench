# Saved timing trial comparison

Workbench 0.10 adds a versioned context to GUI and CLI run reports. It records the application version, frontend, source or fixture options, effective profile, duration limit and whether CSV was enabled. The effective profile includes CLI overrides. Its SHA-256 is calculated from Workbench's compact serialized profile, including default values; it is not a hash of the original profile file. A second hash normalizes only the scheduler to `deadline` for comparison.

The root `cyclic_elapsed_us` measures the monotonic cyclic loop interval. It excludes setup, INIT cleanup and the final CSV drain. The loop can finish after its last scheduled exchange, up to one requested period before the duration limit. A delayed exchange or scheduler wake can extend the measured interval. The duration limit, requested period, actual elapsed interval and observed send/receive spacing remain separate values.

## Offline example

Run from the unpacked portable build. Use fresh output paths each time.

```powershell
New-Item -ItemType Directory -Force .local | Out-Null
.\ethercat-workbench-cli.exe run samples/synthetic.json --seconds 2 --scheduler deadline --csv .local/deadline.csv --report .local/deadline.json
.\ethercat-workbench-cli.exe run samples/synthetic.json --seconds 2 --scheduler relative --csv .local/relative.csv --report .local/relative.json
.\ethercat-workbench-cli.exe compare-runs .local/deadline.json .local/relative.json
```

`run --report` writes UTF-8 JSON directly and still prints the report to stdout. It reserves a new `.json` file before running; an existing path is preserved and prevents the run from starting. A crash or interrupted report write can leave a reserved empty or partial file, which comparison rejects. GUI users can save a completed run with **New report JSON / Save report** and inspect **Saved trial settings**. The recorded frontend identifies the application entry point; it does not prove that a window was visible, under a particular rendering load or being operated.

## Comparison rules

Supply 2–32 reports, each no larger than 16 MiB, in capture-start order. Both schedulers must be present. UTF-8 with or without a BOM is accepted. Reports without the new context must be recollected; the command does not infer their settings.

Comparison checks matching application version, frontend, source and fault options, duration and effective profile apart from scheduler. It also checks observed device identity, serial, topology and image lengths, PDO assignment/verification results and synchronization settings. Initial DC offset and propagation-delay measurements may vary between startups; these two measurements are excluded from settings equality and remain in the original reports. CSV filenames, UTC anchors and connection generations can differ between trials.

Each report must describe a successful, uncancelled run with at least two valid replies, consistent spacing and exchange counters, selected fields, and a drained capture. Every-valid logging must select every valid reply. Virtual and physical SAFEOP trials must retain confirmed INIT cleanup, matching profile/device identity and synchronization readback with disabled SYNC. Replay is excluded because its spacing measures playback. Duplicate input hashes or capture anchors, changed settings, incompatible PDO readbacks and incomplete counters are rejected.

Version 0.18 also retains each trial's independent [HTTP feed counters](http-input-feed.md). Enabled settings must match between trials; settled reports must be inactive and account for offered events as dispatched, queue drops or pending. Feed loss, client errors and worker failures produce separate warnings without becoming CSV overruns or bus faults. Use separate compatible trial groups to compare feed-enabled and feed-disabled workloads. Older profiles omit disabled HTTP settings when hashed, preserving earlier saved-profile fingerprints.

Output retains each trial's input-file hash, UTC anchor, generation, elapsed interval, cycles, replies, valid samples, timeouts, missed deadlines, WKC/AL mismatches, ignored frames, CSV counters and full send/receive p50/p95/p99/longest-gap values. Each scheduler summary gives the minimum, median and maximum of its individual run p99 values. It does not pool histograms or infer a combined percentile. Warnings flag fewer than three trials per scheduler, nonalternating order, invalid exchanges and logger overruns. Logger losses remain visible and do not prevent comparison when the capture counters account for them.

By default the command inspects saved JSON counters and sets `csv_audits` to null. Repeat `--csv BASE` once per report to stream and hash the CSV parts and check their headers, typed text and metadata. The [CSV audit rules](capture-audit.md) describe this additional evidence. Neither mode independently verifies original payload bits or physical field meaning. Input-file hashes bind the result to particular saved bytes. The JSON and hashes are editable evidence, not signed runtime attestation. Results do not select a winner or grant bench acceptance.

Version 0.19 also retains independent [MQTT counters](mqtt-input-feed.md). Final inactive/disconnected reports must balance queue and coalescing/attempt domains. Network errors, dropped/unsent input and worker failures produce separate warnings; normal latest-value coalescing is visible without becoming CSV or bus loss. TCP writes do not prove subscriber delivery. Enabled MQTT settings must match between trials; use separate compatible groups for enabled/disabled workloads.

Version 0.20 also retains independent [shared-memory counters](shared-input-feed.md), including coalescing, mutex misses/recovery, queue loss and inactive-publication outcome. Final reports must balance both event domains and be inactive. Contention, loss, recovery, worker failure or a skipped inactive copy produces a separate warning; successful copies do not prove reader delivery. Enabled settings must match between scheduler trials.

## Desktop review

The **Review** panel can compare the same reports without the CLI, with optional CSV audits, per-trial timing/loss tables and new-file JSON export. See [desktop review](desktop-review.md) for worker and cancellation behavior.

## Valid-input spacing

Version 0.31 adds `valid_receive_spacing` to runtime reports and comparison trials. It uses the same near-receive monotonic timestamp as the all-reply histogram, recording only inputs that pass the existing expected-WKC and SAFEOP/clear-AL checks. Bad WKC/AL replies and timeouts do not add samples; intervals between valid samples span these interruptions. An unchanged valid input still contributes even with on-change CSV logging or no CSV logger. An outage after the last valid input does not create a completed interval until another valid input arrives; inspect input-health age and invalid-duration counters while that outage continues.

| Measurement | Interval count | Meaning |
| --- | --- | --- |
| `receive_spacing` | `max(replies - 1, 0)` | All matched received replies, including invalid input quality |
| `valid_receive_spacing` | `max(valid - 1, 0)` | Only input samples accepted as valid |
| Valid spacing object with count 0 | 0, percentiles/longest all null | Cyclic measurement ran, but fewer than two valid inputs exist |
| Null or absent valid spacing | Unavailable | Cyclic measurement was not reached, or saved metadata did not record it |

A third bounded histogram is allocated before cycling. Recording adds no CSV, GUI, mailbox or dynamically growing sample history to cyclic I/O. Counts and p50/p95/p99/longest values use microseconds. Every-valid CSV with no logger loss provides an independent longest-gap cross-check: subtract adjacent receive-based elapsed timestamps, allowing one microsecond for separate truncation. On-change rows are a selected subset and cannot reconstruct all valid intervals.

The desktop shows separate all-received and valid-input timing, including interval counts. `compare-runs` validates optional valid-spacing counts, percentile order and duration bounds, and requires equality with all-reply spacing when every reply was valid. Older reports remain loadable with a warning and unavailable valid-input values; they are never inferred from other counters. Each scheduler's `valid_receive_trials` counts trials with an available valid-input p99. `valid_receive_p99_us` reports min/median/max of those per-run p99 values only when every trial in that scheduler group has one. A mixed or incomplete group retains null instead of summarizing a subset. Percentiles are not pooled and no passing threshold or winner is inferred.

These are host observations, distinct from requested cycle period, device synchronization/DC settings, independent capture clocks and wire timing. The extra histogram's physical timing impact and GUI/logger behavior still require the selected bench run.

## Physical bench procedure

Once the device and NIC are selected, retain the model, revision, serial, ESI hash, NIC/driver, Windows configuration, wiring and the independent method of varying or observing the chosen input in ignored `.local/`. Review the existing approval scope for ESC setup, SAFEOP and INIT before starting a physical run. OP, PDO downloads and live outputs require their separate approval and remain unimplemented.

Use the GUI with the same selected fields, every-valid logging, queue size, rotation and duration for both schedules. Keep the requested period at the agreed target, initially 1,000 microseconds, and record device sync/DC readback separately. Collect at least three runs per scheduler with fresh CSV/report paths, alternating **Deadline** and **Stock relative**. Save each completed report before editing settings. Then pass all reports to `compare-runs` in capture-start order.

Inspect losses, WKC/AL counters, requested/observed timing, CSV contents and independently verified input changes together. Host timestamps near injection/dequeue do not establish wire frame spacing, device clock alignment or a hard deadline. Use an independent capture when wire timing is required. Offline fixtures and CLI trials are labeled accordingly and do not establish GUI-plus-logger physical behavior.

# First EtherCAT bench session

Rehearse the review workflow offline, then use the worksheet to agree on the first isolated one-device session. Keep the completed worksheet, vendor ESI and session evidence in `.local/`.

## Rehearse offline

From the extracted Windows package or a built checkout, run the virtual CoE rehearsal with a new output directory.

```powershell
powershell -NoProfile -File tools/rehearse-bench.ps1 -Output .local/rehearsal
```

The script runs three trials per scheduler for three seconds each. It alternates which scheduler runs first in a pair. The bundled virtual profile requests 1,000 µs and logs every valid input. Use `-Seconds` to change the trial duration and `-Pairs` to choose 1–16 pairs.

Open `comparison.json` under **Review → Saved comparison**. The script also creates `evidence/` with a verified receipt, portable trial list, reports and rotated CSV parts. After copying the bundle to a new location, select **Open evidence bundle**, then **Recompare bundled trials**. The original trial set and copied profile stay in the rehearsal directory. `rehearsal.json` records the CLI and profile hashes, trial order and bundle receipt hash. An interrupted rehearsal can leave a partial directory. Retry with a new destination.

These results use an authored virtual device and host-side measurements. Record native walkthrough and physical qualification outcomes separately.

## Record the setup for review

| Item | Record for the session |
| --- | --- |
| SubDevice | Model and hardware revision. Expected vendor ID, product code and revision from the selected ESI or manual profile. Retain the ESI SHA-256 if used. |
| Isolated NIC | Workstation, adapter description and exact NIC identifier. Retain the Npcap runtime check and driver/version evidence. |
| Topology | Bench wiring, the connected ESC port, and the read-only discovery result scoped to the selected NIC. |
| Input | TxPDO object/subindex, decoded field, bit offset, type, values and units to observe. Describe how the operator will independently vary or confirm the input. |
| Capture | Saved profile, selected fields, logging mode, rotation, output folder and agreed session duration. |
| Setup scope | Agreement for the selected NIC and device covering ESC setup, existing SM/FMMU mapping, SAFEOP entry and INIT teardown. Record separate approvals if any further operations are needed. |
| Benchmark | Requested host period, duration, trial order, repeat count and intended input variation. Record any pass criteria agreed for this bench. |

## Establish SAFEOP input

1. Check host prerequisites in **Device → Host prerequisites…**. Refresh NICs and run read-only discovery on the selected isolated NIC. Confirm the topology and recorded adapter match the worksheet.
2. Load the exact profile, configure CSV in **Logging**, and review the **Isolated bench / SAFEOP** connection plan. After the setup scope is agreed, acknowledge the plan and start the session.
3. Check exact bus identity, PDO layout readback, AL status/code and expected/actual WKC. Record readback availability and synchronization or DC settings separately from host timing. Check the raw and decoded TxPDO input against the independent observation.
4. Save the run report and audit its CSV after **Stop and flush** and INIT confirmation. Preserve partial or failed results with their setup stage, error and cleanup evidence. If valid input requires OP or vendor configuration, stop and review the additional operations before proceeding.

## Measure the 1 ms target

Use the same desktop build and keep the CSV logger active for every physical comparison trial. Hold the device, profile, capture fields, logging mode, duration and input procedure consistent across schedulers. Save a new report and CSV base for each trial and keep them in capture-start order. Both schedulers need successful, compatible trials for comparison. Preserve interrupted or failed attempts in the session notes.

Compare **Deadline** and **Stock relative** in **Review → Run reports and CSV**. Include send, all-reply and valid-input p50, p95, p99 and longest gap. Record missed deadlines, WKC and AL mismatches, transport timeouts and CSV overruns. Report requested host period and device synchronization/DC separately. External capture spacing has its own clock, capture-loss and placement evidence. Use the observed input change and the recorded bench criteria when reviewing the result. [Timing comparison rules](benchmark-comparison.md#comparison-rules)

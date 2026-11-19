# Desktop workflows

The desktop follows the same workflow tabs as EthernetIP Workbench. EtherCAT adds a **Review** tab for saved-file tools and retains its own SAFEOP and offline-output boundaries. The header stays outside the scrolling page: **Connect…**, **Profiles…**, **Record CSV…**, **Stop and flush**, session state, WKC, input issues, errors and CSV losses remain available while navigating. A running saved-file job also exposes **Cancel file review** there.

| Tab | Main task | Secondary detail |
| --- | --- | --- |
| Device | Import an ESI and select an exact device/revision, or start an offline demo | Host prerequisites use a separate window; expected identity/manual override and last discovery results expand separately |
| Inputs | Read typed input values and last-valid age | Raw TxPDO bytes expand; **Offline decoder…** opens a separate paste-and-decode window |
| Outputs | Preview and apply typed values to the offline staged RxPDO image | Raw RxPDO staging expands; mapping edits link to Mappings |
| Logging | Choose a new CSV path, every-valid/on-change mode and selected fields | Buffer/rotation and cycle settings expand separately |
| Mappings | Edit input or output fields, bit/byte positions, types, transforms and CSV selection | Separate pages for Input fields, Output fields, saved ESI PDO choices and ESI synchronization/mode-PDO staging |
| Integration | Configure optional read-only HTTP, MQTT and shared-memory feeds | Settings appear only for enabled feeds; worker results are in Diagnostics |
| Diagnostics | Inspect device/AL/PDO evidence, requested scheduling, observed spacing, synchronization and independent losses | Expand detailed metadata/readback; save a completed run report to a new path |
| Review | Audit/compare saved reports and CSV | Separate pages for run reports/CSV, Ethernet PCAP and saved input snapshots, each with its relevant completed result |

## First offline session

1. In **Device**, choose **Use offline demo**, or use **Profiles…** to load an existing profile. The demo is bundled in the executable and needs no NIC or working-directory setup.
2. Inspect **Mappings → Input fields** and choose the fields to log. For manual setup, enter image lengths and field definitions there. **Outputs** stages bytes offline.
3. In **Logging**, set a fresh CSV base path and logging mode. Expand **Advanced cycle scheduling** to choose requested cycle and scheduler; duration is on the main Logging page. The 1 ms period is a measurement target.
4. Choose **Connect… → Offline fixtures**, then start synthetic input, a matching virtual ESC model or an authored replay. A successful session start selects **Inputs**. No adapter is enumerated merely by opening the dialog or switching tabs.
5. Navigate freely while the worker runs. **Stop and flush** stops acquisition and drains the CSV writer. A configured duration also ends the session. Use **Logging → Save report and audit** afterward. Diagnostics offers the same action. Workbench suggests a new report path and uses the original CSV base for Review, including numbered capture parts.

CSV is configured before connection and runs with that session. **Record CSV…** navigates to its setup/status page; it does not start recording on an existing session. Stopping CSV independently while keeping acquisition active is not implemented. The selected-field summary links to Mappings instead of embedding its editor. Rotation uses a base path even when numbered files are produced.

## Save and replace profiles

Open **Profiles…** to see the last loaded or saved path. Enter a source under **Existing profile JSON** to load it. Enter a separate destination under **New profile JSON** and choose **Save new** to keep your draft. Workbench creates a new file and preserves existing files. Changes to profile settings, mappings, or applied RxPDO staging show **Unsaved profile changes** in the header. Reverting those settings to the last loaded or saved values clears the indicator.

Loading a profile, choosing **Use offline demo**, or closing the app prompts when the draft has edits. Choose **Save new and continue** to save the draft first, **Discard edits** to proceed with the requested action, or **Cancel** to keep editing. A failed save leaves the prompt open. A failed load preserves the draft. Closing during an acquisition first stops it and flushes CSV, then asks about unsaved profile edits. Cancel at that point keeps the app open with the acquisition stopped.

The CSV destination and duration belong to the session. The profile contains mapping definitions, staged bytes, cycle settings and logger options. Apply any pending offline preview to the draft before saving its settings.

## Host prerequisites

Choose **Device → Host prerequisites… → Check host metadata** for a read-only Npcap host snapshot. Opening the window performs no check. The same link is available from the isolated bench review. DLL, service and policy observations remain separate from capture access, which stays unprobed. Inspect full paths/errors under the raw-details disclosure or export the completed snapshot to a fresh JSON path. Collection and export use an exclusive background job, retained across window/tab navigation. Closing the application waits for it to finish. [Host check details](runtime-check.md#desktop-prerequisites-window) cover states, exports and evidence limits.

## Isolated bench review

After the target and hardware scope have been agreed, import/reload its exact profile and configure logging first. **Connect… → Isolated bench / SAFEOP** holds NIC selection, explicit NIC refresh/read-only discovery, the setup-effect review and the approval checkbox. Merely opening the dialog performs no discovery. Starting native SAFEOP requires reviewed approval for ESC setup, SM/FMMU configuration from the existing mapping, SAFEOP entry and INIT cleanup. The scrolling plan summarizes expected identity (ESI/manual/override), configured TxPDO/RxPDO sizes, requested host cycle/duration, selected CSV fields/buffer/rotation and the disabled-output/DC boundary. Device timing/readback remains unavailable until approved setup. The acknowledgement and Start controls stay pinned below the scroll area, including at the minimum window size.

The checkbox requires valid profile settings, a selected NIC and exact expected identity. A successful scan of the selected physical NIC finding zero or multiple devices blocks single-device preflight until corrected/rescanned. Scanning is optional and its result is historical: a single snapshot does not prove compatibility or current topology. Virtual snapshots and snapshots from another NIC are explicitly excluded from this physical check; failed scans are not successful zero-device results. Scan results retain their original NIC/model even if profile settings later change.

Acknowledgement binds the effective profile, duration, normalized CSV destination and discovery scope/data. Closing/reopening the review, changing its source page/settings, refreshing NICs or starting/completing a scan clears it. Profile save paths and offline decoder text are unrelated to this run plan and preserve it. The backend still verifies actual count/identity/mapping/state independently.

The acknowledgement records the user's existing authorization; it does not create permission. OP, PDO mapping downloads, enabled DC and live outputs remain unavailable. Staged RxPDO bytes are not sent. See [operations](operations.md) for exact hardware boundaries.

## State and review rules

Setup, output staging, mapping, logging and integration edits are locked during acquisition, discovery, saved-file or host-metadata work. The page explains the lock. Navigation, monitoring and applicable stop/cancel controls remain usable. Duplicate starts are rejected by the application as well as disabled controls. Offline drafts, page selection and completed file results survive navigation; one cancellable file worker retains frozen request inputs.

Invalid or stopped input is labeled historical and its typed live readbacks are hidden. Raw bytes require an explicit expansion. Input quality and CSV overruns remain visible in the header; detailed timing and consumer counters belong in Diagnostics. Saved snapshots remain historical regardless of recorded freshness flags.

The layout and workflows are tested through pure egui frames, synthetic UI events and an offline acquisition/CSV worker. These checks open no native window and do not establish perceived usability or physical timing. Native visual acceptance and the agreed GUI-plus-logger bench run remain pending.

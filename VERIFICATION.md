# EtherCAT Workbench verification

## Version 0.1.0 Windows x64 build

The release was built on Windows 11 Pro x64 build 26200 with Rust 1.99.1, MSVC 14.44 and Npcap SDK 1.17. PE inspection found the x64 GUI and console subsystem executables, static MSVC CRT linkage and a delay import for `wpcap.dll`. The CLI enumerated 12 candidate adapters through the installed Npcap 1.85 runtime on this host. Enumeration required no transmission. The selected bench interface and raw Ethernet round trip remain to be checked.

Formatting, Clippy and all three Rust tests passed. The Rust tests cover transforms and bit decoding, wire reply matching, and full-queue loss accounting with recovery and a visible sample-index gap. The test-only GUI and CLI harnesses can emit MSVC LNK4199 because they have no calls to delay-loaded Npcap.

## Headless fixture

`tools/verify.py` checks ESI revision selection, UTF-8/UTF-16 parsing, ESI hash and provenance, profile round trip, bit and float offsets, staged output decoding, the SAFEOP approval gate, strict CSV parsing and ordered monotonic timestamps. It checks field values independently from the application using cycle indexes.

At 1,000 µs requested, the three-second deadline run attempted 2,999 cycles. It logged all 2,949 valid exchanges, skipped 1 deadline slot and counted 20 injected timeouts and 30 injected WKC mismatches. The three-second relative run attempted 2,992 cycles and logged 748 changes. Both ran without queue overruns. A separate rotated run encountered an existing second part, preserved it byte for byte, reported the capture error and counted 500 flushed rows in the first part.

## GUI and logger timing

Six synthetic runs used a visible Windows GUI, a five-second duration, every-valid logging, 500-row rotation, a 4,096-sample queue, and a 1,000 µs request. The order alternated between deadline-first and relative-first. The fixture produces replies in the worker, so send and receive percentiles were equal at the reported resolution. Values below are in microseconds.

| Trial | Scheduler | p50 | p95 | p99 | Longest gap | Missed slots | Valid / CSV rows |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Deadline | 1,000 | 1,000 | 1,030 | 2,060 | 1 | 4,999 |
| 1 | Relative | 1,000 | 1,924 | 5,291 | 18,666 | 545 | 4,276 |
| 2 | Relative | 1,000 | 1,000 | 1,130 | 4,129 | 4 | 4,978 |
| 2 | Deadline | 1,000 | 1,081 | 1,808 | 2,497 | 22 | 4,978 |
| 3 | Deadline | 1,000 | 1,002 | 1,243 | 2,164 | 7 | 4,993 |
| 3 | Relative | 1,000 | 1,001 | 1,287 | 2,112 | 8 | 4,947 |

All 29,171 valid samples flushed with zero logger overruns. Host jitter varied between trials. The measurements cover Windows scheduling and the app's synthetic data pipeline. Physical frame spacing, valid device-specific SAFEOP data and device synchronization require the isolated bench.

Reproduce from the source checkout with the Windows release binaries and a fresh path under `.local/`.

```powershell
python tools/verify.py target/x86_64-pc-windows-msvc/release .local/verification --gui --gui-trials 3
```

## November 12 PDO verification update

Six Rust tests passed, including per-SyncManager byte alignment, mapping order, padding, overrides and unavailable readback. The headless release workflow imported the sample ESI and matched all four referenced fields against the synthetic CoE snapshot. A reordered snapshot with the same eight-byte input size was rejected. A manual bit/byte profile remained usable and its fields were labeled manual.

The existing synthetic capture checks also passed with zero queue overruns. The Windows helper for ESC SyncManager and CoE assignment reads was compiled and reviewed against the pinned EtherCrab source. Physical device readback remains pending.

## Version 0.2.0 raw-frame replay

The twelve-exchange fixture contains authored Ethernet II requests and candidate replies. The replay uses the same frame matcher, input parser, WKC/AL validation, bounded queue and CSV writer as the live cyclic path. It processes all twelve exchanges and classifies six as valid. The remaining cases produce one PDO WKC mismatch, three AL mismatches and two missing matching responses. Six outbound, stale, truncated, wrong-protocol or invalid-length candidates are ignored. Every-valid mode writes the six expected values, including unchanged inputs. On-change mode writes four rows. Both flush without logger overruns.

Headless checks reject a write command in a replay request, reject an all-invalid input run, and report a replay stopped by its duration limit as incomplete. They also cover saved PDO comparison and unavailable readback. Formatting, Clippy, all six Rust tests and the headless release workflow pass on Windows x64.

The November 12 checks use command-line tools and files. The GUI additions compile. The current device-specific SAFEOP run, raw NIC round trip, live CoE readback and physical timing benchmark remain pending the bench selection.

## Version 0.3.0 virtual ESC startup and cleanup coverage

The authored virtual ESC exercises the shared setup and teardown against the pinned EtherCrab implementation. A normal run reads SII identity and descriptors, performs 24 CoE uploads, configures the two process SyncManagers and FMMUs, requests SAFEOP, exchanges input data and confirms INIT on stop. The virtual device validates its SM/FMMU register image before accepting SAFEOP or returning a nonzero LRD Working Counter. The audit records zero CoE downloads, logical writes, physical output writes and OP requests during the checked application runs.

Eight Rust tests and the headless workflow pass. The workflow checks every-valid and on-change CSV values from the virtual input counter, repeated values, typed data and clean flush. Fault cases cover reordered mappings, SAFEOP with AL error 0x001D, mailbox aborts, unavailable readback, rejected INIT cleanup, a mismatched revision and capture-file creation failure. Setup faults preserve AL status/code and confirm INIT afterward. A rejected cleanup reports its final AL status/code and leaves the successful-stop field unset.

The SAFEOP fault exposed that EtherCrab's group state wait can finish with the desired state while the AL error flag remains set. Workbench now explicitly checks AL status and status code before the first cyclic exchange. INIT cleanup uses the error acknowledgement bit and requires cleared AL status. These checks are exercised through the virtual packet path. Physical controller, driver and timing acceptance remain pending.

## Version 0.4.0 SII mapping and virtual device coverage

The SII tests cover padding, unassigned PDOs and malformed category bounds. The SII model declares no CoE support, provides EEPROM PDO categories and uses two process SyncManagers. It reaches SAFEOP through EtherCrab's EEPROM configuration path, verifies all four referenced fields from SII, logs input values and returns to INIT. Its audit records zero CoE uploads. Both virtual models are checked with every-valid and on-change logging and configuration failures.

The headless functional checker accounts for reply timeouts separately from valid exchanges and validates CSV values against the virtual counter. Host scheduling can expire a receive wait even with an in-memory responder. A CoE readback failure retains its unavailable status, and SII readback is selected from the device's declared mailbox protocols. SII tests establish the authored fixture path. Physical SII device support remains pending acceptance.

## Setup cancellation and dropped responses

Twelve Rust tests pass. The cancellation tests release queued, sent and received PDU futures repeatedly beyond the eight storage slots, then confirm INIT cleanup while the stop flag remains set. A pre-start cancellation completes without sending datagrams. Cancelled runs expose a separate cancellation flag, and cleanup errors retain their failure result.

The CoE and SII headless workflows both exercise a dropped SII response during setup and periodic lost cyclic responses. The setup timeout retains its PDU timeout detail and confirms INIT. Cyclic loss increments reply timeouts, writes only valid received samples, flushes the capture and confirms INIT on stop. The fixture audit distinguishes dropped replies from logger overruns. These checks cover in-memory packet handling and host execution.

## Version 0.5.0 DC startup diagnostics

Thirteen Rust tests, formatting and Clippy pass. The full headless release workflow covers every-valid and on-change logging on the CoE, SII and new CoE/DC virtual models, plus the existing ESI, decoder, saved PDO, replay, fault, rotation and collision checks. The DC model advertises enhanced 64-bit clock support and exercises EtherCrab receive-time latching and initial offset/delay writes. It returns disabled activation and zero SYNC cycle registers. Reports retain those values separately from the requested 1,000 microsecond host cycle and observed send/receive spacing.

Injected active activation and unavailable activation both stop with zero cyclic samples, no CSV opened and confirmed INIT cleanup. Reports retain the readback value or failure reason and the pre-cleanup AL status. Audit counters record no OP, live output, SDO download, DC enable or cyclic clock-distribution requests. Ordinary and fault runs validate their received rows and clean flush. The startup fixture does not generate SYNC pulses, model oscillator drift or establish clock alignment.

All new execution is headless and uses authored, in-memory packets. GUI changes were compiled. Native GUI interaction, physical NIC exchange, device-specific SAFEOP input, enabled DC synchronization and the agreed physical 1 ms bench comparison remain pending the device and NIC selection.

## Version 0.6.0 input loss and transport failures

Fifteen Rust tests, formatting, Clippy and the full headless Windows release workflow pass. Tests cover quality interval timing and publication of invalid input before a failing teardown, retaining both transport and INIT cleanup errors. Older profiles receive the documented 1,000 ms loss timeout, and out-of-range timeout settings are rejected. The GUI setting and last-valid age display were compiled; this increment used no native desktop interaction.

Each of the CoE, SII and CoE/DC models passes six additional loss cases. A forty-reply outage recovers within the same connection generation with every-valid and on-change logging. Persistent reply loss stops under a 100 ms limit, preserves its earlier valid samples and confirms INIT. Monitor-only mode continues until the selected run duration, retaining its ongoing invalid-input interval. An injected transport failure stops immediately and confirms INIT when the transport remains available. A permanently unavailable transport preserves the cyclic failure and failed cleanup together and leaves INIT confirmation unset. All written rows are valid, typed values and indexes are checked, and logger overruns remain zero in these runs.

Input-loss intervals measure host execution from the first failed exchange's send time through the next valid receive or cyclic-loop exit. This is a software timeout policy checked between exchanges and at normal exit, with host scheduling and driver blocking limitations. It does not prove physical disconnect behavior or a hard stop deadline. No automatic configuration replay, OP request, live output, SDO download or DC enable request occurs in the fault fixtures. Physical recovery and the agreed GUI-plus-logger bench comparison remain pending hardware selection.

## Version 0.7.0 staged ESI synchronization review

Nineteen Rust tests, formatting, Clippy and the complete headless release workflow pass. New tests import both DC mode XML forms and retain signed shifts, timing annotations, factors and unsupported extensions. They cover namespace shadowing, duplicate/overflowing assignment values, invalid factors/booleans, split XML text, profile persistence and clearing a staged mode on reimport. Timing tests distinguish the SYNC0 and SYNC1 factor rules, preserve literal precedence, reject nonintegral or out-of-range cycle previews and leave device-dependent shifts unresolved.

The CLI workflow imports UTF-8 and UTF-16 timing fixtures, stages a mode with a manual sync-unit assumption, and demonstrates that changing the requested host period leaves the preview unchanged. It runs the staged profile against the CoE/DC virtual model and records different expected/observed register values while `applied` remains false. It verifies every valid CSV row with zero logger overruns and checks that no DC enable, clock distribution, live output, SDO download or OP request occurs. Saved-report comparison covers matched and different values, unavailable assignment readback from an older report, exact device identity enforcement and invalid selections that create no profile file. The existing replay, SII/CoE, cancellation, timeout, transport-loss and logger checks remain passing.

The authored XML passes namespace-aware well-formedness and Workbench consumer validation. Its XSD validity is not claimed. GUI staging and review controls were compiled; this increment used no native GUI interaction or physical bus traffic. Enabled DC configuration, device-specific mode/PDO extensions, oscillator alignment and the agreed physical benchmark remain pending hardware selection and separate approval for writes.

## Version 0.8.0 ESI PDO catalogs and offline choices

Twenty-two Rust tests, formatting, Clippy and the full headless Windows release workflow pass. Catalog tests retain unassigned PDOs, signed `Sm=-1`, mandatory/fixed flags, raw padding and datatype annotations. They enforce exclusions, mandatory choices, unique assignments, SyncManager bounds and direction separation, and reject unsupported module/virtual materialization. Failed builds leave the existing profile unchanged. Datatype scaling/swap annotations remain visible notes and do not silently change decoding.

The CLI workflow builds and reloads default and alternative profiles, checks chosen order within one SyncManager and byte alignment between SyncManagers, and explicitly assigns a mandatory PDO lacking a default. Invalid choices create no new profile. Older profiles without catalogs continue to load. The default authored profile logs valid typed values with zero logger overruns. Its same-size alternative is rejected against the virtual device before SAFEOP, records zero cycles and confirms INIT cleanup. No PDO downloads or live output writes occur. Separate saved-readback tests alter SyncManager identity or a padding descriptor while all named fields still match; full-selection verification rejects both.

Public hash-linked ESI fixtures have LF checkout rules. Their sample-profile hashes are checked against raw XML bytes. XML well-formedness and consumer validation pass; XSD validity is not claimed. GUI selection, ordering, rebuilding and detaching controls were compiled. All new execution used files, CLI and authored virtual devices. Physical device mappings, GUI interaction and the agreed hardware timing benchmark remain unqualified pending device/NIC selection. Live assignment writes, OP and outputs remain outside this offline selection workflow.

## Version 0.9.0 bounded CoE uploads

Twenty-five Rust tests, formatting, Clippy and the complete headless Windows release workflow pass. A direct comparison reproduces the pinned EtherCrab reader rejecting a legal zero-command segment response; the Workbench uploader then reads the exact 0x44332211 marker and the complete device name through the same packet path. Additional tests check mailbox-counter handoff filtering, bounded object sizes and cancellation during a missing-segment wait followed by confirmed INIT cleanup.

The normal and segmented virtual models switch reply policy after the original expedited-only PDI initializer completes. Both verify all four referenced PDO fields and synchronization types, preserve the exact device name, and exercise every-valid and on-change CSV capture. In the release check, the normal model logged all 999 valid rows and the segmented model all 1,000 valid rows; each on-change run wrote 250 rows. Logger overruns were zero. Counter checks account for actual LRD exchanges separately from cycle indexes that include skipped deadline slots.

Wrong toggles, an oversized declared object, a missing segment and a wrong response counter each stop before SAFEOP with zero cyclic exchanges, no capture opened and confirmed INIT cleanup. A valid server abort leaves the optional name unavailable while complete PDO readback and cyclic input continue. A valid partial initial payload preserves every name and PDO byte. All checked application runs retain zero SDO downloads, logical output writes, physical output writes, OP requests, mailbox counter conflicts and DC enable requests. Existing ESI, replay, SII/CoE/DC, loss, transport, rotation and collision checks remain passing.

The mailbox uploader runs only during setup, with explicit size/segment/time bounds and no automatic mailbox recovery. The source review records the remaining expedited-only initialization limitation and a source-level SOEM comparison. GUI additions were compiled; no native GUI interaction, physical bus traffic or SOEM execution occurred. Device-specific initialization, SAFEOP input and the agreed GUI-plus-logger physical timing benchmark remain pending the device and NIC selection.

## Version 0.10.0 saved timing trial comparison

Thirty-one Rust tests, formatting, Clippy and the complete headless Windows release workflow pass. The new tests verify profile fingerprints that normalize only the scheduler, retain per-trial measurements, compute ranges of individual run p99 values without pooling, and preserve visible logger losses. They reject legacy, failed, cancelled and inconsistent reports, changed profile or execution settings, mixed frontends, changed observed devices, duplicate evidence, reversed capture order and a missing scheduler.

The release workflow collects six alternating one-second synthetic trials, three per scheduler, with identical settings and every-valid CSV. All 5,984 valid samples flush with zero logger overruns. It independently verifies profile hashes, input-report hashes, saved counters, selected values and each summary range. Two additional virtual CoE/DC trials log 1,999 valid samples with zero overruns, verify PDOs, confirm INIT cleanup and compare matching settings while permitting the initial measured DC offset/delay to vary. Changed saved PDO descriptors are rejected even when the effective profile stays unchanged.

CLI `run --report` creates UTF-8 JSON directly, preserves an existing report byte for byte and rejects that collision before creating a CSV. The checker accepts UTF-8 BOM input, bounds report files at 16 MiB, and rejects unsupported context schemas, missing logging, malformed spacing, stale profile hashes, incompatible fixture options and replay timing. Existing ESI, decoder, CoE segmented/normal, replay, SII/DC, cancellation, transport/loss, rotation and collision checks remain passing.

Run context is captured before setup and shared with snapshots; profile hashing and comparison stay outside cyclic exchange. The measured cyclic interval excludes setup, INIT cleanup and final CSV drain. GUI context display and report tagging were compiled. All execution in this increment was headless with authored fixtures; no GUI interaction or physical bus traffic occurred. The comparison command checks saved JSON counters, not CSV bytes or field correctness, and does not establish hardware acceptance. Physical GUI-plus-logger trials, independently observed input values, driver behavior and the agreed 1 ms benchmark remain pending device/NIC selection.

## Version 0.11.0 offline CSV capture audits

Thirty-seven Rust tests, formatting, Clippy and the complete headless Windows release workflow pass. New tests check writer quoting, UTF-8/BOM and LF/CRLF records, integer widths and canonical text, signed limits, bool/raw values, f32/f64 special values and malformed records. They retain metadata state across parts, allow declared sample-index gaps, permit unchanged every-valid data and distinguish ambiguous NaN repeats from invalid on-change repeats.

The release workflow audits ordinary CoE/SII/DC captures and the drained files from input-loss and transport-failure runs, retaining their reported outcomes. Six alternating timing trials log 5,994 valid samples with zero logger overruns. The optional audited comparison checks 1,999 rows across four parts and binds each audit to the matching report hash. A separate native-writer fixture logs and audits 1,000 rows with quoted Unicode headers, signed byte-swapped fields, f64 values and raw hex. Python independently checks the raw report/CSV hashes and saved counters.

Authored CSV fixtures account for one leading, one interior and one trailing logger gap, accept consistent CRLF with a UTF-8 BOM, retain failed/cancelled run status and allow a header-only zero-valid capture. These are modeled files, not measured physical losses. Corruption checks reject wrong UTC/generation/indexes, regressing timestamps, out-of-range integers, invalid boolean/float text, changed headers, incomplete counters, mixed record endings, malformed or extra quoting, blank records, absent final newlines, oversized records and an index reset at a rotation boundary. Audited comparison also rejects the corrupted CSV. Unrelated later files remain untouched and outside the declared audit sequence.

The auditor streams and hashes records with bounds of 16 MiB per report, 1 MiB per physical record, 100,000 parts and 64 GiB total CSV bytes. It records its own version separately from the captured application's version. A structurally valid capture from a failed run remains labeled as such; incomplete writer accounting fails auditing. Default comparison remains counter-only unless CSV bases are supplied. The capture writer's filename calculation was shared with the auditor without changing its output format or cycle-thread path.

All execution in this increment used files, CLI and authored fixtures. The Windows GUI was compiled without native interaction; no physical bus traffic occurred. Auditing establishes typed text, metadata and saved-byte consistency. It cannot independently prove original PDO bits, individual-cycle WKC/AL validity, physical field meaning or runtime authenticity. Device-specific input acceptance and the agreed GUI-plus-logger 1 ms bench comparison remain pending device/NIC selection.

## Version 0.12.0 desktop saved-run review

Forty-five Rust tests, formatting, Clippy and the complete headless Windows release workflow pass. Eight new review-controller tests exercise real saved-file audit/comparison fixtures, capture outcomes, frozen requests, overlapping-job rejection, export guards, new-file preservation, failure/reset behavior, cooperative stop requests, cancellation before file access and suppression of an already-finished but unpublished success. The fixture exports retain the CLI's untagged audit/comparison schema, UTF-8 encoding and final newline. These controller tests run without creating a native window or accessing a NIC.

The desktop now exposes capture audits and ordered scheduler comparisons in a saved-run review panel. It shows per-trial host send/receive timing and loss counters, captured run outcomes, reported application/frontend, input hashes and optional CSV audits. Inputs are copied at job start; editing the path rows afterward cannot relabel a completed result. Rendering limits displayed part hashes to the first 32 while JSON exports retain all parts. Native layout and interaction have been compiled but were not exercised.

Report reads now check the review stop flag between bounded chunks. CSV review checks between buffer reads, records and parts, with a final cancellation check before publishing. A blocking file-system call or parse is still not immediately interruptible. The GUI allows one review worker, prevents new bus/discovery work while it is active, and rejects review starts/exports during an active bus or discovery job. Closing requests stop for read-only review work without joining a blocked reader. Existing live-run close behavior still waits for approved INIT cleanup and CSV drain. Exports remain explicit after successful review and preserve existing files.

The full CLI workflow logs 5,996 valid samples across six alternating synthetic trials with zero logger overruns. Its audited comparison verifies 1,998 rows across four CSV parts. Existing ESI/PDO/DC review, CoE/SII/segmented setup, replay, input-loss/transport faults, CSV corruption, rotation and collision checks remain passing through the shared backends. All execution in this increment was headless with authored saved files or virtual devices; no native GUI interaction or physical bus traffic occurred. Device-specific input meaning, wire timing and the agreed GUI-plus-logger physical benchmark remain pending bench selection and qualification.

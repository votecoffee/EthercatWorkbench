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

## SII mapping and virtual device coverage

Ten Rust tests pass, including SII padding, unassigned PDOs and malformed category bounds. The SII model declares no CoE support, provides EEPROM PDO categories and uses two process SyncManagers. It reaches SAFEOP through EtherCrab's EEPROM configuration path, verifies all four referenced fields from SII, logs input values and returns to INIT. Its audit records zero CoE uploads. Both virtual models are checked with every-valid and on-change logging and configuration failures.

The headless functional checker accounts for reply timeouts separately from valid exchanges and validates CSV values against the virtual counter. Host scheduling can expire a receive wait even with an in-memory responder. A CoE readback failure retains its unavailable status, and SII readback is selected from the device's declared mailbox protocols. SII tests establish the authored fixture path. Physical SII device support remains pending acceptance.

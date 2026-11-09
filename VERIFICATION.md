# EtherCAT Workbench 0.1.0 verification

## Windows x64 build

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

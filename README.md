# EtherCAT Workbench

Windows x64 Rust desktop application and headless CLI for EtherCAT MainDevice bench commissioning, SAFEOP input inspection, PDO decoding and CSV capture.

## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Maintainers](#maintainers)
- [Contributing](#contributing)
- [License](#license)

## Install

Extract the portable ZIP. Launch `ethercat-workbench.exe` for the GUI or use `ethercat-workbench-cli.exe` from PowerShell. Offline mode runs with no EtherCAT hardware. Live mode uses the separately installed x64 [Npcap runtime](https://npcap.com/#download), an Ethernet NIC connected to an isolated bench, and access permitted by the Npcap driver policy.

To build from source, install Rust 1.92 or later, the MSVC x64 toolchain and Windows SDK, and download the Npcap SDK. Keep the SDK and vendor ESI XML in ignored `.local/`. Set the x64 library directory for the build.

```powershell
$env:LIBPCAP_LIBDIR = (Resolve-Path .local/vendor/npcap/Lib/x64).Path
cargo build --locked --release --target x86_64-pc-windows-msvc
```

## Usage

From the unpacked package, create a local directory for profiles and captures. Choose the bundled synthetic profile in the GUI or use the commands below.

```powershell
New-Item -ItemType Directory -Force .local | Out-Null
.\ethercat-workbench.exe --profile samples/synthetic.json
.\ethercat-workbench-cli.exe run samples/synthetic.json --seconds 4 --csv .local/synthetic.csv
.\ethercat-workbench-cli.exe run samples/virtual.json --backend virtual --seconds 2 --csv .local/virtual.csv
.\ethercat-workbench-cli.exe run samples/virtual-sii.json --backend virtual --virtual-model sii --seconds 2 --csv .local/virtual-sii.csv
.\ethercat-workbench-cli.exe decode samples/synthetic.json "04 00 00 00 00 00 80 3F"
.\ethercat-workbench-cli.exe decode samples/synthetic.json "FE FF" --rx
.\ethercat-workbench-cli.exe esi-list samples/synthetic.esi.xml
.\ethercat-workbench-cli.exe esi-import samples/synthetic.esi.xml --device 0 --out .local/imported.json
.\ethercat-workbench-cli.exe verify-pdo .local/imported.json samples/synthetic-pdo.json
.\ethercat-workbench-cli.exe run samples/synthetic.json --backend replay --replay samples/synthetic-replay.json --seconds 2 --csv .local/replayed.csv
```

The ESI reader accepts UTF-8/UTF-16 and lists devices by vendor, product and revision. It imports PDO entries with a default `Sm` assignment, sorts by SyncManager, and preserves entry padding and byte alignment between SyncManagers. It records the ESI basename, hash, identity and field sources. The editable bit offsets and lengths are Workbench decoding settings. Use a new profile path to save edits. Select TxPDO fields for CSV and stage RxPDO hex with the expected image length. For aligned numeric fields, transforms apply in the order swap bytes in each 16-bit word, reverse the 16-bit words, then interpret endian order. Bit fields number bit 0 as the least-significant bit of the first byte.

Live discovery is read-only on the selected NIC. Select a profile with exact identity and Tx/Rx lengths. The initial live implementation requires one isolated SubDevice. The separate approval covers EtherCrab ESC initialization, configuring SyncManagers and FMMUs from the device's existing mapping, requesting SAFEOP and returning to INIT. During that session the cyclic path uses read datagrams only. OP, PDO assignment writes and live RxPDO transmission are outside this preview. After setup, Workbench reads enabled process SyncManagers and the SII mailbox protocol declaration. It reads CoE PDO assignments on CoE devices and SII PDO categories on devices that declare no CoE support. It compares object indexes, subindexes, widths and bit positions with referenced profile fields before requesting SAFEOP. A known mismatch stops setup and requests INIT. Setup confirms SAFEOP with a clear AL error flag and zero AL status code before cycling. Cleanup acknowledges AL errors, requests INIT and confirms a cleared status. A setup failure retains its AL status and code before cleanup. Reports and the GUI retain the readback, identify CoE or SII as the mapping source, and show each field as matched, manual, unavailable or mismatched. Devices with unavailable CoE readback retain an explicit verification warning. Manual fields describe the selected bits and bytes. Verify input changes on the bench before relying on field labels.

```powershell
.\ethercat-workbench-cli.exe nics
.\ethercat-workbench-cli.exe scan --nic '\Device\NPF_{your-nic-guid}'
# Run after approval for the isolated bench and ESC writes.
.\ethercat-workbench-cli.exe run .local/bench.json --backend safeop --approve-esc-writes --seconds 20 --csv .local/bench.csv
```

The bundled raw-frame replay fixture contains twelve authored Ethernet exchanges. Replay uses the live LRD/AL reply parser and the normal capture queue and CSV writer. It reports malformed or stale candidates as ignored frames and checks Working Counter and AL state before logging. It stops at the end of the fixture, and a duration limit that cuts a replay short produces an error. Playback spacing and timestamps come from the host clock during the replay. The fixture covers the cyclic input path.

The virtual controller backend runs the shared EtherCrab setup and teardown against authored CoE and SII ESC models in memory. It provides SII identity and mailbox descriptors, CoE expedited uploads, process SyncManagers, FMMUs and SAFEOP input reads. Its SAFEOP response depends on the configured SM/FMMU registers. Reports include SII/CoE counts, state requests and output-write audit counters. Use the corresponding bundled virtual profile and select the model in the GUI or with `--virtual-model coe` or `sii`. The CLI supports `--virtual-fault pdo-order`, `safeop-reject`, `mailbox-abort`, `readback-unavailable` and `cleanup-reject` to exercise failure paths. Mailbox and unavailable-CoE faults apply to the CoE model. Both models declare no Distributed Clock support, and its timestamps measure host execution.

The CLI prints a JSON report. Save a GUI run report after the session ends. The GUI shows live AL status and expected/actual WKC, raw TxPDO and typed values, requested period, synchronization and separate send/receive spacing. CSV runs on a separate writer thread behind a bounded preallocated queue. Each valid selected exchange is timestamped near receive using a monotonic clock. Rows contain a UTC capture anchor, elapsed microseconds, one-based sample index, connection generation and cycle index. With rotation, parts are named `capture.0001.csv`, `capture.0002.csv`, and so on. Existing files are preserved. Overruns count dropped offers and can cause sample-index gaps. On-change mode compares selected bits with the last queued row and includes the first valid value. A GUI session increments its generation for each run and each capture opens a new file series.

Send and receive spacing are host timestamps taken near Npcap injection and dequeue. The synthetic fixture measures the same application paths against generated data. Missed deadlines count full elapsed slots at the next dispatch. Deadline mode skips elapsed slots and relative mode rebases the next cycle. The run report separates WKC mismatches, AL mismatches, reply timeouts and logger overruns. A normal GUI close or CLI Ctrl+C stops the worker and drains the writer.

See the [EtherCrab source review](docs/ethercrab-review.md), [verification results](VERIFICATION.md), and [roadmap](ROADMAP.md).

## Maintainers

[votecoffee](https://github.com/votecoffee)

## Contributing

Run `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings` and `cargo test --locked --all-targets` on Windows x64. To reproduce the ZIP, install `cargo-about` 0.9.3 with its `cli` feature and run `./tools/package.ps1 -Zip .local/EtherCAT-Workbench-0.3.0-win-x64.zip` from a clean checkout. Use sanitized fixtures in commits and keep vendor files, private settings and raw captures in `.local/`.

## License

[MIT](LICENSE). The portable package includes third-party notices. Npcap is installed and licensed separately.

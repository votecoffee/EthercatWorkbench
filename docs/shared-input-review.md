# Native shared-input reading and saved-snapshot review

Version 0.21 adds `read-shared` and `inspect-shared` to the portable CLI. Reading or decoding needs no Python, Npcap, NIC selection or hardware approval. The commands consume the existing [Windows shared-input byte contract](shared-input-feed.md); they do not create a MainDevice session, write outputs or initialize/reconnect a bus. The Python example and C header remain independent interoperability examples.

```powershell
# Console 1: authored synthetic input with a fixed saved profile.
.\ethercat-workbench-cli.exe run samples/shared-input.json --seconds 30 --csv .local/run.csv --report .local/run.json
# Console 2: one read; optional typed decoding and new-file exports.
.\ethercat-workbench-cli.exe read-shared bench --profile samples/shared-input.json --save-raw .local/input.bin --out .local/input.json
# After the run: use its exact effective profile, including CLI overrides.
.\ethercat-workbench-cli.exe inspect-shared .local/input.bin --run-report .local/run.json --out .local/review.json
# Raw/status inspection also works without a profile:
.\ethercat-workbench-cli.exe inspect-shared .local/input.bin
```

Create `.local/` beforehand and use fresh output paths. `--out` writes UTF-8 JSON directly and stdout also receives the inspection. `--save-raw` is only on `read-shared` and writes the exact copied 2560 bytes to a new `.bin` file. Neither export overwrites an existing path; paths/extensions are checked before IPC/file inspection. Raw export requires a coherent initialized `ready` snapshot. Busy, abandoned or reserved/not-ready input creates no raw export. A failed write/flush can leave an owned partial output; inspect that outcome rather than overwrite/retry it automatically.

## Desktop saved-file review

Version 0.22 adds the same saved-file decoder to **4 Saved run review → Inspect a saved shared-input snapshot**. Choose raw/status, a frozen copy of the current profile, or a saved run's effective profile. The existing cancellable worker preserves the original request and exports the same inspection JSON without overwriting files. It never performs live IPC or process/clock queries, and shows historical/current-invalid versus last-good data separately. [Desktop instructions](desktop-review.md#inspect-a-saved-shared-input-snapshot) explain mapping failures, display limits and cancellation boundaries. Native GUI interaction remains unqualified by the headless tests.

## One-shot live read

`read-shared NAME` opens existing objects only, with a read-only mapping and synchronization/mutex-release rights. It attempts the mutex once with zero wait. It copies into a preallocated private buffer while owning the mutex, releases it and closes all mapping/mutex handles before validation, typed decoding or file output. It neither creates missing objects nor retains handles that would keep a finished producer's names alive. These Windows operations follow [OpenFileMapping](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-openfilemappingw) and [OpenMutex](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-openmutexw).

JSON `status` is `ready`, `not_ready` (all-zero reserved mapping), `busy`, or `abandoned`. Ready means a coherent initialized layout, not necessarily a received/valid/current exchange: a producer can publish setup metadata before its first attempt. Busy/abandoned copies have no snapshot or raw hash. Abandoned ownership is released and the copy discarded. There is no automatic polling/retry. Missing/inaccessible objects, malformed bytes or a requested profile mismatch return an error. Status JSON alone does not signal usable input; inspect `current_usable` and quality/age evidence. Requesting raw export for a non-ready status returns an error.

The consumer checks the publisher PID and creation FILETIME with query/synchronization rights, distinguishing alive, exited, reused identity and unavailable identity. It uses [process creation time](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes), rather than PID alone. Local QPC observations must have a matching positive frequency and a nondecreasing counter. Counter regression, unavailable timing, frequency differences or unrepresentable ages prevent current usability. Identity access/query failure remains explicit and cannot become an alive result.

`current_usable` requires that observation plus active/fresh-at-publication flags, exchange validity, matching producer/latest index and an observed sample age within the producer threshold. Observed ages and usability apply at the recorded reader QPC; decoding, printing, transport and consumer delay can age the result further. It is an age-qualified snapshot hint, not proof the bus stayed unchanged after the copy, nor physical PDO meaning. An alive GUI process with a stalled worker still ages out. Continue the application's own timeout policy after the last usable read.

## Saved bytes and typed mapping

`inspect-shared FILE` reads a regular file of exactly 2560 bytes, validates its schema/lengths/flags, timestamps/indexes, WKC/AL/issue consistency, last-good relationships, UTF-8 strings and zero padding. It never opens IPC, queries the recorded PID or consults the current QPC clock. Even bytes carrying active/fresh flags have `current_usable: false`, no live observation and no current age estimate. Ages **at publication** remain recorded evidence. All-zero saved bytes report `not_ready`. Unknown/malformed layouts are rejected before export.

Optional `--profile FILE` supplies the exact effective profile. `--run-report FILE` instead extracts the version-1 context's effective profile and checks its declared profile hash. These options are mutually exclusive; their JSON inputs are bounded to 16 MiB, and typed field names to 16 KiB combined. The profile is validated, compact-canonicalized and SHA-256 checked against the snapshot before any typed values are returned. TxPDO length and expected identity must also agree. CLI overrides, logging selections, staged values and other profile settings affect the full hash; do not silently normalize them. Use the actual run's effective profile or save the configured GUI profile before acquisition. If a profile/hash is unavailable or differs, requested typed decoding fails; omit that option for explicit raw-only inspection.

All named TxPDO fields, including `log: false`, decode through the same bit/type/endian/word transformations as `decode`. Values are strings, retaining wide integers and non-finite float text. Raw payloads remain hex. Invalid latest attempts have no current payload/values; separately labeled `last_valid` data remains historical. Its previous WKC/AL values are not stored in this byte contract and are not invented by the inspector. `decoding.tx_fields` retains input mapping provenance and definitions; RxPDO definitions and staged output bytes are not exported. Profile-hash checking binds a mapping to the bytes, not a physical meaning or signed producer identity.

## Inspection JSON schema 1

The root has `kind: "shared_input_inspection"`, `schema: 1`, inspector `app_version`, `source`, `status`, exact `raw_sha256` when a coherent copy exists, optional live `observation`, `publication_age_us`, `clock_error`, `current_usable`, `snapshot` and `decoding`. Source distinguishes live shared memory from a named saved file. The version is the inspector's version; binary schema 1 contains no separate producer application version.

Snapshot data retains backend/stream/process identity, UTC/elapsed/QPC timing, expected and setup-observed identity, requested period, WKC/AL/input issue, acquisition/CSV/interface counters and current versus historical payloads. Input records contain event/cycle/elapsed identity, age at publication and nullable age near the live observation. Current exchange `valid_at_exchange`, `fresh_at_publication` and root `current_usable` have distinct meanings. Saved-file observed ages stay null. JSON metadata contains 64-bit integers; consumers must preserve that precision. Typed field values are strings.

Live counters are separate atomic observations and can be briefly in flight; the inspector does not impose a settled run-counter equality on a live snapshot. Use the final run report/CSV audits for clean-drain/accounting proof. Inspection JSON is not a run report and is rejected by `compare-runs`. Using `--run-report` only verifies/extracts the mapping context; it does not qualify that report's success, CSV contents or association with a particular stream. Raw/profile hashes are editable evidence, not runtime attestation.

## Verification boundaries

Independent byte-vector Rust tests cover exact wide/float/swapped decoding, malformed/truncated/padded data, quality/timing/history contradictions, profile guards and historical/live clock rules. Windows tests check not-ready, busy/abandoned handling and handle release. Headless CLI checks exercise the publisher beside Python/HTTP/MQTT/CSV, typed raw export/reload, wrong profiles, malformed files, existing-path preservation, stale/dead publishers and abandoned readers. Saved 0.20 snapshots and effective profiles remain compatible with the schema-1 reader. Native GUI interaction, physical input meaning, cross-user access and the agreed device/NIC timing benchmark remain unqualified.

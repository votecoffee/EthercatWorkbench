# Developing EtherCAT Workbench

Read [AGENTS.md](../AGENTS.md) first. [Operations](operations.md) describes supported user workflows; this guide identifies ownership and change routes. [VERIFICATION.md](../VERIFICATION.md) separates actual offline/native/physical evidence. Keep those boundaries explicit when adding features.

## Data and ownership

| Area | Owner and change route |
| --- | --- |
| Profiles and typed mappings | `model.rs`: schema 1, validation, decoding, source provenance, create-new saves |
| ESI and offline expectations | `esi.rs`, `pdo_catalog.rs`, `mode_pdo_stage.rs`, `sync_review.rs`: device/revision import with exact identity or guarded index selection, retained candidates, layout/timing review and bounded mode-specific SM/PDO hints; no mapping/DC downloads |
| Windows host prerequisites | `runtime_check.rs`: bounded file headers/version resources and query-only service/registry metadata; no capture API, NIC ownership or service/configuration changes |
| Native transport/setup | `live.rs`, `live/coe.rs`, `live/pdo_readback.rs`, `wire.rs`, `sii.rs`, `sync.rs`: selected-NIC Npcap/EtherCrab setup, bounded readback including setup-only CoE cycle/minimum snapshots and retained partial diagnostics, input-only LRD/AL cycles, INIT cleanup |
| Virtual/replay evidence | `virtual_esc.rs`, `replay.rs`: authored memory/frame models, early-initializer compatibility injection receipts and write audits; they are not hardware acceptance |
| Acquisition and quality | `run.rs`, `health.rs`: independent cycle worker, scheduler, preallocated send/all-reply/valid-input histograms, near-receive timestamps, generation/cycle identity, WKC/AL/input-loss state and summaries |
| CSV pipeline | `capture.rs`: preallocated bounded samples, batched writer, rotation/flush and visible loss; keep file I/O off acquisition |
| Read-only input HTTP | `http_feed.rs`: prebound loopback listener, bounded fixed-record handoff/history, worker-owned HTTP/decoding, freshness and independent feed losses |
| MQTT input publishing | `mqtt_feed.rs`: bounded independent queue/latest snapshot, publish-only local MQTT worker, reconnect/loss/age/shutdown accounting; `input_feed.rs` shares fixed records and bounded JSON with HTTP |
| Windows shared memory | `shared_memory.rs`, `shared_memory/windows.rs`: pre-reserved owner-protected objects, independent fixed-record queue/latest worker, zero-wait mutex publication and explicit byte encoding; `examples/read_shared_memory.py` is an independent reader |
| Native shared-input review | `shared_memory/reader.rs`, `shared_memory/reader/windows.rs`: bounded strict byte parsing, read-only one-shot IPC, profile-bound decoding and explicit saved/live age evidence; saved inspection also has bounded cancellation boundaries for the desktop worker; no bus/session ownership |
| Offline output image | `output_stage.rs`: typed candidate, inverse transforms, overlap checks and profile-bound apply; no bus ownership |
| Saved-file analysis | `benchmark.rs`, `capture_audit.rs`, `capture_file.rs`, `pcap_inspect.rs`: compatible trials, streaming CSV audit and bounded Ethernet container analysis with explicit PCAPNG interface selection and declared per-interface capture statistics |
| Desktop | `main.rs`, `gui_mode_pdo.rs`, `gui_stage.rs`, `gui_review.rs`: profile/session controls, staging and one cancellable file worker in `review.rs`, including saved shared-input inspection with frozen raw/profile/report mapping requests |
| Headless surface | `src/bin/ethercat-workbench-cli.rs`: shared models/operations and JSON output; avoid a second implementation of protocol or decoding logic |

The session owns its transport and cyclic worker. The GUI reads snapshots and requests stop; it does not drive the cycle. The writer drains its own bounded queue. Saved-file review runs independently and is exclusive with new bus/discovery jobs. GUI close cancels read-only review without waiting, but a live session close waits for approved INIT cleanup and CSV drain. New interfaces must preserve these ownership boundaries; see [interface design/acceptance](interfaces-roadmap.md).

## Verification and release

On Windows x64 with the configured Rust/MSVC/Npcap SDK toolchain:

```powershell
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --release --target x86_64-pc-windows-msvc
python -B tools/verify.py target/x86_64-pc-windows-msvc/release .local/new-verification
```

Use a new verification directory. The script authors fixtures under `.local/`, checks CLI/profile/ESI/typed staging, virtual setup/faults, replay, capture containers, CSV audits, repeated scheduler comparisons and HTTP/MQTT/shared memory with stalled consumers, broker faults, named-object/liveness failures, native/saved shared-input review, typed profile guards and invalid input. Rust tests cover desktop snapshot worker/export/layout behavior and frozen PCAPNG interface selection. Mode-PDO desktop tests exercise frozen preview/apply, unchanged output preservation, fresh explicit Rx clearing, profile invalidation, active-work exclusion, unsupported hints and pure egui before/after/provenance layout; shared plan hashing/validation stays in the library. Independent Python-authored multi-interface captures check per-interface clocks/counts, excluded regressions, original packet indexes, empty selections and malformed excluded records. Early initializer fixtures inject normal/segmented PDO responses before process-image configuration, retain the first object/form, require failure plus INIT and verify expedited/SII controls. CoE timing fixtures check optional aborts versus malformed failures, primitive sizes, zero/unavailable/unqueried values, retained failed-setup diagnostics, unchanged upload counts during longer acquisition and legacy metadata. Host-check tests cover x64/x86/ARM64/non-DLL headers, malformed bounds, literal version resources, unreadable versus invalid images, missing/denied policy and unprobed status summaries. CLI checks preserve export paths, cross-check observed PE bytes and require absent Npcap executable modules before/after collection. Timing tests distinguish invalid-reply versus valid-input intervals without CSV, optional legacy metadata, complete-group ranges and unavailable versus zero intervals in a headless snapshot. CLI checks cross-check longest valid gaps against every-valid CSV timestamps and validate on-change independence. Exact-identity fixtures check numeric bounds, multiple products/revisions, reorder stability, guarded-index failure, duplicate ambiguity/disambiguation, legacy imports and non-mutating failures. Mode-PDO staging fixtures check unchanged/changed layouts, decoder and output preservation, explicit Rx clearing, stale plans, rejected hints/catalog constraints, create-new saves and actual virtual mapping rejection before SAFEOP. Mode-hint fixtures check both XML forms, source/hash compatibility, missing/zero/different readback, offline PDO order, detached selections, unsupported extensions and bounds. Statistics fixtures check both byte orders, split-word clocks versus scalar counters, wide integers, missing/zero/decreasing snapshots, malformed references/options and bounded inventories. `tools/mqtt_fixture.py` is an independent bounded TCP fixture, not a production broker. Its optional `--gui` launches native UI and requires explicit authorization; default headless use does not. Pure egui layout tests need no window, desktop input, screenshot or GPU. Test-only binaries may report MSVC LNK4199 for unused delay-loaded Npcap; distinguish that from compiler/Clippy failures.

Validate a changed skill with the available skill-creator `quick_validate.py` and read it against realistic app requests. `tools/install-skill.ps1` can be exercised against a fresh `.local/` destination before installing it in the user skill directory. Do not overwrite modified/unowned installed files.

From a clean committed checkout, use `tools/package.ps1 -Zip` with a fresh absolute ZIP path. It builds locked release binaries, generates third-party/font/Rust notices, records source commit/toolchain and hashes, and packages docs/samples/skill assets. It does not redistribute the Npcap runtime. Verify every manifest hash, PE x64 GUI/console subsystem and the extracted CLI using its bundled samples; retain receipts under `.local/`. Preserve older deliverables. Push verified cohesive commits when authorized; no automatic Actions tests are configured.

For documentation/skill-only changes, check links, command help/examples, installer preservation and packaging content. Do not rerun unchanged physical/native acceptance or claim new runtime evidence. Application version changes affect saved run context and comparison compatibility, even when behavior is unchanged.

## Protocol and authorization boundaries

EtherCrab is source-pinned; read [the review](ethercrab-review.md) before changing native initialization, Windows transport, mailbox upload or scheduling. The virtual normal/segmented fixtures do not fix the earlier private initializer's expedited-only small-object reads. Compare SOEM for a material selected-device gap; its licensing and backend tradeoffs need source-bound review. Keep optional/unavailable discovery distinct from observed values, including controller counters and synchronization registers.

A 1 ms request is a measurement target. Preserve separate host send/receive gaps, device/DC configuration and capture-clock evidence. Do not pool per-trial percentiles or silently merge generation/index domains. Logger losses, invalid bus exchanges, interface dispatch drops and per-consumer failures must remain independent.

The approved native path configures ESC state/SM/FMMUs and obtains SAFEOP inputs using read-only cyclic datagrams. OP, PDO downloads, live outputs and enabled DC need separate design, tests and explicit user approval before hardware use. Do not infer hardware permission from a profile, staged bytes, a command flag, successful virtual tests or an installed skill. Do not auto-retry ambiguous writes.

## Maintenance

Update the operational guide and relevant detailed docs when behavior/commands change; update this ownership map for new modules. Keep README runnable examples, ROADMAP statuses, AGENTS links, the repository skill and package manifest in sync. Record verification scope and pending physical work without treating stale test counts as current results. Vendor files/raw captures/private profiles stay in ignored `.local/`; reusable fixtures must be authored or licensed/sanitized.

EthernetIPWorkbench is a read-only reference for UX and consumer isolation, not a source of EtherCAT protocol semantics. The read-only loopback HTTP input feed is implemented; [its contract](http-input-feed.md) defines current semantics and bounds. The [MQTT publisher](mqtt-input-feed.md) implements a bounded publish-only subset for a trusted local broker; [Shared memory](shared-input-feed.md) implements a fixed C-readable byte snapshot with zero-wait publication; function FFI remains planned. Avoid advertising planned endpoints or ownership guarantees as implemented behavior.

# Research and handoff brief

Snapshot: 2026-11-14. Version **0.33.0** replaces the long numbered desktop page with the EthernetIP Workbench workflow tabs, focused dialogs and separate saved-review pages. The previous retained 0.32.0 build (`d73e88b9a9199219f93992c923858e18023aecc8`) remains a rollback baseline. See the current [verification record](../VERIFICATION.md) and each portable package's `BUILD.txt` for checked source/binary identity. Native GUI acceptance and physical bench qualification remain open.

## Decisions to retain

| Area | Current position | Detailed evidence |
| --- | --- | --- |
| Backend | EtherCrab 0.7.1, pinned to `fec2730823ce1eb62425f83d5df49d678f03b104`; Windows x64 Npcap transport and a dedicated cyclic worker | [Source/backend review](ethercrab-review.md) |
| Device scope | One SubDevice, identity/PDO/AL/WKC checks and input-only SAFEOP cycles; GUI and CSV work stay outside acquisition | [Operations](operations.md), [ownership](development.md) |
| Profiles | ESI identity/revision selection, retained catalogs, manual/overridden fields, offline mode/PDO and typed Rx staging; expectations remain separate from discovered evidence | [PDO choices](pdo-selection.md), [synchronization review](esi-sync-review.md), [typed staging](output-staging.md) |
| Timing/logging | A requested 1 ms period is a measurement target. Keep device/DC settings, host send/all-reply/valid-input spacing, capture clocks and independent losses separate. Every-valid logging includes unchanged data; on-change selection does not define valid-input timing | [Timing comparisons](benchmark-comparison.md), [CSV audits](capture-audit.md) |
| Desktop workflow | Device, Inputs, Outputs, Logging, Mappings, Integration, Diagnostics and saved Review; persistent stop/status, locked active settings and explicit SAFEOP review | [Desktop workflows](desktop-workspace.md) |
| Host readiness | `check-runtime` reads Npcap file/service/policy metadata; capture access stays unprobed | [Host checks](runtime-check.md) |

The portable package retains dependency notices and excludes Npcap runtime/driver files. Use the existing installation/licensing references in the [README](../README.md#install) and source review. EthernetIPWorkbench remains a read-only UX/pipeline reference, not an EtherCAT protocol specification.

## Known gap and next bench decision

EtherCrab's early private PDO initializer still expects expedited small-object CoE uploads. Workbench's later normal/segmented uploader does not replace that initializer. The authored failure fixtures preserve this phase boundary and verify INIT cleanup. If the selected device exposes the gap, compare a bounded initializer change or SOEM against its actual behavior and applicable licensing before choosing a backend change.

The user deferred the physical device/revision, ESI, isolated NIC and signal to log. Once selected, establish independent signal observation, review the existing ESC setup/SAFEOP/INIT authorization, and run agreed repeated deadline/relative trials with the GUI and logger active. OP, PDO downloads, live outputs and enabling DC remain unimplemented and require separate design and approval. Multi-device groups and optional embedding remain roadmap items. See the [roadmap](../ROADMAP.md) rather than treating these as completed work.

## Local retention after cleanup

- Retain each verified delivery ZIP with its matching receipt, plus the 0.32.0/0.31.0 pre-redesign baselines. Keep current GUI/CLI executables at the source release path; generated rebuild caches are disposable when no build is active.
- Keep the Rust toolchain/tool binaries, cached locked dependencies, current Cargo EtherCrab checkout, canonical SDK extraction/original ZIP, installed skill and current 0.32.0 verification data.
- Older private evidence/helpers are compressed under ignored `.local/research-archive/`. The development archive retains per-file hashes and original paths, including raw captures and prior failure receipts; generated executable copies were omitted. A second archive retains the clean pinned EtherCrab research checkout's file bytes, while its duplicate Git history was removed.
- Stale build caches, 31 older distribution ZIPs, duplicate extractions and superseded helper files were removed. The next Cargo build will recreate its build cache; no rebuild was performed merely to validate this cleanup.

The ignored `.local/cleanup-20261114/` receipt records the inventory, scoped deletion plan/log, archive hashes and post-cleanup checks. Historical paths inside archived reports remain historical. Extract selected evidence to a new directory when needed; do not treat archived snapshots as current input. The existing [verification history](../VERIFICATION.md) and detailed source review remain intact, so this brief can replace rereading the full development history for routine continuation.

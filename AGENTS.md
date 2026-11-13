# EtherCAT Workbench agent entry point

This repository is a Windows x64 Rust EtherCAT MainDevice workbench. Start with [README.md](README.md), then use the maintained guides below. Preserve the distinction between authored/offline evidence, native Windows operation and physical device acceptance.

- [Operations](docs/operations.md): ESI import, manual profiles, NIC/discovery, headless workflows, typed mappings/staging, timing/loss interpretation and hardware authorization.
- [ESI synchronization review](docs/esi-sync-review.md): staged DC/SM/PDO hints, CoE cycle/minimum setup snapshots, offline choices versus optional CoE readback, unsupported annotations and no-write boundaries.
- [Capture inspection](docs/pcap-inspection.md): offline PCAP/PCAPNG, explicit Ethernet-interface selection, separate capture clocks/counts, declared capture-tool statistics and schema-4 exports.
- [Development](docs/development.md): ownership, acquisition/GUI/writer boundaries, source review, tests, packaging and documentation maintenance.
- [Interfaces roadmap](docs/interfaces-roadmap.md): implemented read-only [HTTP input](docs/http-input-feed.md) and [MQTT publishing](docs/mqtt-input-feed.md), and [Windows shared-memory input](docs/shared-input-feed.md), with a [native reader/saved inspector](docs/shared-input-review.md), [desktop saved-snapshot review](docs/desktop-review.md#inspect-a-saved-shared-input-snapshot) and optional C ABI/C# embedding planned.
- [Roadmap](ROADMAP.md) and [verification record](VERIFICATION.md): remaining work and the evidence actually collected.
- [Codex skill](skills/ethercat-workbench/SKILL.md): app-specific operating instructions. `tools/install-skill.ps1` installs a discoverable local copy with an application-root binding.

Use headless CLI/files/APIs by default. Desktop input, screenshots and screen recording require an explicit request in the current chat. Do not launch native GUI verification merely because a headless verification script offers it.

Hardware scope follows the current user's authorization. Read-only discovery on an identified isolated NIC differs from initialization: native SAFEOP requires reviewed approval for EtherCrab ESC setup, SM/FMMU configuration from the existing mapping, SAFEOP entry and INIT cleanup. A CLI flag records consent; it does not create consent. OP, PDO downloads, live outputs and enabling DC are unimplemented and require separate approval and implementation. Offline profile edits and RxPDO staging send no bus writes. Honor approval already given for the exact current scope rather than asking again.

The physical device, ESI, NIC and value to observe have not yet been selected as of the current verification record. Continue useful offline work without probing arbitrary adapters or claiming bench acceptance. Check current chat evidence before treating this status as current.

Keep vendor files, raw captures, private profiles and receipts in ignored `.local/`; deliverable ZIPs may be stored outside the source tree. Commit authored reusable fixtures and documentation. The reference project is `C:\~LocalWork\Repos\Programming\~Github\EthernetIPWorkbench` ([GitHub](https://github.com/votecoffee/EthernetIPWorkbench)); treat it as read-only unless the user separately authorizes changes there. EtherNet/IP connection semantics do not apply to EtherCAT.

For implementation, inspect Git status/upstream/worktrees and preserve unrelated work. Run checks appropriate to the change; packaging requires a clean committed tree and locked dependencies. Keep automatic CI triggers absent unless explicitly requested; the current workflow runs locally. Maintain frequent verified commits and pushes when authorized by the task. Update the relevant guide, README/roadmap and verification boundaries as behavior changes.

# EtherCAT Workbench roadmap

## One-device bench acceptance

- Record device model and revision, ESI hash, NIC and driver version, bench wiring, selected input and an independent way to vary or observe it.
- Use read-only discovery to confirm a single SubDevice. Review and approve the ESC setup and INIT teardown scope before starting the GUI SAFEOP run.
- Confirm exact identity, AL state and status code, device-reported image lengths and sync settings. Verify PDO offsets and values against the device documentation and an independently observed input change.
- Run deadline and relative schedules at 1,000 µs with the GUI and the same CSV settings active. Use repeated runs, retain the JSON reports and compare WKC, elapsed timestamps, missed slots, losses and send/receive gap percentiles. If wire timing is needed, compare with an external capture.
- If SAFEOP requires vendor configuration or the device only provides valid input in OP, review the needed operations with the user before any writes. Compare SOEM if the issue is a material EtherCrab gap for this device.

## Extend bench coverage

- Extend the virtual ESC fixture to segmented CoE transfers, enabled DC synchronization, physical driver disconnect/reconnect behavior and device-specific recovery. Timeout bursts, sustained reply loss and injected transport errors now have offline coverage. The current DC model covers disabled SYNC startup and register readback. Add licensed, sanitized fixtures for the selected physical device.
- Qualify the CoE and SII mapping readback on the selected physical device. Expand ESI module, slot, dynamic/virtual PDO and device-specific synchronization support from device examples. Retained PDO catalogs, offline choices and full assignment comparison now have authored-fixture coverage. Structured ESI DC modes, staged timing previews and register comparisons now have offline coverage; mode-specific mapping and timing annotations still require implementation and bench qualification.
- Support device-specific approved DC mode configuration, cyclic reference-clock distribution and qualification of clock alignment and frame timing separately. Current diagnostics retain raw DC registers and reject unexpected active SYNC settings.
- Allocate logical input ranges and expected WKC by group for multiple SubDevices. Add identity-bound profiles per position and topology-change handling.
- Design separately approved mapping writes, OP entry and output publishing with an explicit output contract and a bench teardown procedure.

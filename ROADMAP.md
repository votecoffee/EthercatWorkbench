# EtherCAT Workbench roadmap

## One-device bench acceptance

- Record device model and revision, ESI hash, NIC and driver version, bench wiring, selected input and an independent way to vary or observe it.
- Use read-only discovery to confirm a single SubDevice. Review and approve the ESC setup and INIT teardown scope before starting the GUI SAFEOP run.
- Confirm exact identity, AL state and status code, device-reported image lengths and sync settings. Verify PDO offsets and values against the device documentation and an independently observed input change.
- Run deadline and relative schedules at 1,000 µs with the GUI and the same CSV settings active. Use repeated runs, retain the JSON reports and compare WKC, elapsed timestamps, missed slots, losses and send/receive gap percentiles. If wire timing is needed, compare with an external capture.
- If SAFEOP requires vendor configuration or the device only provides valid input in OP, review the needed operations with the user before any writes. Compare SOEM if the issue is a material EtherCrab gap for this device.

## Extend bench coverage

- Extend the authored LRD/AL packet replay to SII, CoE, state transitions and FMMU setup. Add licensed, sanitized fixtures for any selected device.
- Qualify the CoE assignment readback on the selected device and extend verification to SII-only mappings. Expand ESI module, slot, selectable mapping and synchronization support from device examples.
- Support approved DC configuration and qualify synchronization and timing separately.
- Allocate logical input ranges and expected WKC by group for multiple SubDevices. Add identity-bound profiles per position and topology-change handling.
- Design separately approved mapping writes, OP entry and output publishing with an explicit output contract and a bench teardown procedure.

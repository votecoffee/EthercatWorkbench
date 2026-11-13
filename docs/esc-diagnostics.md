# ESC discovery snapshots

Read-only discovery retains the full ESC data-link status, controller information and error counters alongside bus position, station address, alias and AL state/code. These readings are taken before any approved initialization. They are not refreshed during cyclic input and do not add work to the 1 ms cycle path.

The core scan still requires one responding device per auto-increment position and Working Counter 1 for each address, DL and AL read. Missing core replies or ambiguous Working Counters fail discovery. The additional information/counter reads are optional: a failed read retains an unavailable reason rather than fabricating zero values or discarding the core result. Each snapshot records a UTC start anchor and elapsed host microseconds across its sequential reads. It is not an atomic register image.

## Register interpretation

| Range | Interpretation |
| --- | --- |
| `0x0000–0x000F` | Controller type, revision/build, FMMU/SM counts, RAM capacity, port descriptors and raw feature bits |
| `0x0110–0x0111` | Physical links, loop state and received-signal flags for ESC ports 0–3, plus raw PDI/watchdog flags |
| `0x0130–0x0135` | Raw AL state/error indication and status code, with common descriptions |
| `0x0300–0x0313` | Invalid/RX/forwarded/lost-link counters, processing/PDI counters and raw controller-dependent PDI code |

The bit and counter layouts follow the [Beckhoff ESC register reference](https://download.beckhoff.com/download/document/io/ethercat-development-products/ethercat_esc_datasheet_sec2_registers_3i0.pdf), with DL decoding also checked against the [pinned EtherCrab layout](https://github.com/ethercrab-rs/ethercrab/blob/fec2730823ce1eb62425f83d5df49d678f03b104/src/dl_status.rs). Common AL descriptions follow the [pinned AL-code table](https://github.com/ethercrab-rs/ethercrab/blob/fec2730823ce1eb62425f83d5df49d678f03b104/src/al_status_code.rs). Unknown states, extra flags and unlisted/vendor codes retain their numeric values. No automatic recovery follows a decoded description.

Controller type/revision/build is separate from the SubDevice's vendor/product/revision identity. Workbench obtains that identity through its existing, approved SII initialization path. A read-only scan does not use EEPROM commands. Port numbers are ESC numbers, not physical socket labels; consult device documentation for the socket mapping. Port states and bus order do not reconstruct a branch topology or establish input-data validity.

Counter support and PDI-code meaning vary by controller. Counts can predate the session, and another controller or initialization phase may change them. Values of 255 are flagged as byte maxima; consult the ESC's saturation rules before calculating increments or rates. Discovery reads do not clear counters, acknowledge AL errors, change state, configure mappings or transmit RxPDOs.

## CLI and desktop

```powershell
.\ethercat-workbench-cli.exe scan --nic '\Device\NPF_{your-nic-guid}'
.\ethercat-workbench-cli.exe scan-virtual --model coe --case normal
.\ethercat-workbench-cli.exe scan-virtual --case port-errors
.\ethercat-workbench-cli.exe decode-esc samples/esc-diagnostics.json
```

`scan --nic` opens only the explicitly selected adapter under the installed Npcap policy. `scan-virtual` uses memory and never opens a NIC. Its scenarios are `normal`, `port-errors`, `counters-unavailable`, `information-unavailable`, `core-wkc`, `core-timeout` and `diagnostics-timeout`. Output includes a write audit and preserves core failure details. The fixture rejects register writes, making accidental initialization visible in headless checks. These modeled results do not qualify a physical NIC or controller.

In the desktop, **Read-only scan** displays the snapshot under each device. **Preview virtual discovery** uses the selected virtual model. Expand **ESC discovery snapshot** for port states, controller information, counters and source/time notes. Current AL status remains separate from the discovery-time AL values. No diagnostic counter-reset or state-control action is offered.

`decode-esc` accepts a raw snapshot object, such as the nested `diagnostics.snapshot` in a scan or run report. The bundled example is authored data. The decoder checks schema 1, UTC, exact byte-array sizes and explicit value-or-unavailable records. Files must be UTF-8 JSON, optionally with a BOM, and no larger than 64 KiB. Saved source labels are editable evidence, not signed hardware attestation. Native GUI interaction, physical raw-Ethernet exchange and device-specific interpretation remain bench qualification work.

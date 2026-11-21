# Offline ESI PDO selection

The profile retains a catalog of direct device TxPDO and RxPDO candidates. It stores their indexes, labels, default SyncManagers, entries, padding, types, fixed/mandatory flags and exclusions. Candidates without `Sm`, or with `Sm="-1"`, remain available for explicit choices. ESI filename, SHA-256 and exact identity remain the source baseline. Older profiles without a catalog continue to load; reimport their ESI to use the selector.

## Select an exact ESI device

Version 0.30 supports exact headless selection by the imported vendor/product/revision values. Either an index or an identity is required; supplying both checks the index against that identity before building or saving a profile:

```powershell
.\ethercat-workbench-cli.exe esi-list samples/mode-pdo-staging.esi.xml
.\ethercat-workbench-cli.exe esi-import samples/mode-pdo-staging.esi.xml --identity '0x00FF1000/3/1' --out .local/exact-device.json
.\ethercat-workbench-cli.exe esi-import samples/mode-pdo-staging.esi.xml --device 0 --identity '0x00FF1000/3/1' --out .local/guarded-device.json
```

The three slash-separated components accept decimal, `0x` or `#x` hexadecimal integers, each within unsigned 32-bit range. Zero is literal, with no wildcard, revision mask, newest-revision choice or product-only fallback. The complete selector is bounded to 128 UTF-8 bytes. A unique identity remains selectable when entries move within an ESI. If an exact identity appears more than once, inspect `esi-list` and explicitly supply both `--device` and `--identity` to choose an entry. The original index-only option remains supported.

An unknown identity, ambiguous match, out-of-range index, identity/index mismatch or invalid selector fails before creating a profile. Existing destinations remain protected. Mode staging, cycle assumptions and explicit PDO choices work with either selector. The profile retains the selected entry's catalog, labels, imported identity and the complete ESI file's basename/hash; reordering the XML therefore changes source provenance even when the selected configuration is otherwise unchanged. Selector checks use imported values, so warnings about an absent revision still apply. They do not discover a bus or establish physical identity, device compatibility, ESI authenticity or hardware permission.

## Review modular device declarations

For ESI devices with a `Slots` declaration, **Device → ESI modules and slots** shows slot declarations and local module descriptions in a collapsed panel. Each slot shows its name, group and instance limits when present, plus its declared module identities or vendor-qualified class choices. Expand a choice's slot to see how many definitions in the same file match it. Zero means this file supplies no matching definition. Multiple definitions remain visible. A default instance count of zero is distinct from an unspecified default.

```powershell
.\ethercat-workbench-cli.exe esi-list samples/modular-device.esi.xml
.\ethercat-workbench-cli.exe esi-import samples/modular-device.esi.xml --identity '0x00FF1000/10/1' --out .local/modular.json
.\ethercat-workbench-cli.exe validate .local/modular.json
```

The CLI shows the inventory under `source.modular` in `esi-list` and `esi.modular` in a saved profile. Module templates show declared TxPDO or RxPDO indexes, total declared bits including padding, and whether any indexes depend on a slot or slot group. Slot attributes such as index increments are retained as ESI text. Group and preset declarations such as `SlotGroupData` and `SlotSelections` are flagged for separate review.

The profile's image lengths and fields come from the device-level PDOs. The sample's modular revision therefore produces only the one-byte base status input, even though it declares additional module data. An installed module list, resolved index offsets, and the composed PDO mapping require separate evidence. Source references and module-list download hints are descriptive. [Beckhoff's module and slot overview](https://infosys.beckhoff.com/content/1033/ep8601-0022/17946536971.html)

## Preview PDO indexes for fixed module slots

Use `preview-modular-pdos` with the original ESI and an exact device identity or list index. Supply both selectors to guard the index. For manual placement, supply one module identity per slot, using zero for an empty optional position. Slot numbers are zero-based in declaration order. A complete saved detected list can also supply the choices. The same module identity can occupy multiple slots if each slot allows it.

```powershell
.\ethercat-workbench-cli.exe esi-list samples/fixed-slot-pdos.esi.xml
.\ethercat-workbench-cli.exe preview-modular-pdos samples/fixed-slot-pdos.esi.xml --identity '0x00FF1000/11/1' --slot '0=0x400' --slot '1=0x400' --out .local/module-pdo-preview.json
```

The JSON records the exact ESI identity and SHA-256, manual slot choices, and each candidate's declared SyncManager hint. Each mapping index, excluded mapping index, and entry object index shows its declared and resolved values. At a flagged index, the preview adds the slot number multiplied by the relevant increment. A per-slot value takes precedence over the device-wide value. PDO mappings and exclusions use `SlotPdoIncrement`. Entry objects use `SlotIndexIncrement`. Unflagged indexes, widths, subindexes, and padding are preserved. In the sample, the second slot resolves TxPDO `0x1A00` to `0x1A10` and its status object `0x6041` to `0x6841`. [HPMicro CiA 402 example](https://kb.hpmicro.com/2026/06/04/ethercat%E4%BB%A5cia402%E4%BE%8B%E7%A8%8B%E4%BB%8B%E7%BB%8Dmdp%E8%AE%BE%E5%A4%87%E7%9A%84od%E5%A4%84%E7%90%86/)

This preview covers ungrouped slots with `MaxInstances="1"` and a declared minimum of zero or one. Each declaration has a position in the preview. It needs one local module definition per chosen identity and checks each choice against that slot's declarations. Duplicate resolved mapping indexes among the chosen modules, out-of-range results, and unsupported slot group or oversampling dependencies stop the preview. A `device_level_index_match` marks an index also present in the device-level catalog for separate review. The preview describes candidates. A composed process image still requires confirmed PDO assignments, SyncManager placement, and offsets. Existing profiles use their device-level PDO layouts.

## Compare module candidates with saved PDO readback

Add `--run-report` to the fixed-slot preview. It checks the saved report for exactly one device with the selected ESI identity, then compares each resolved PDO with the reported assignment in the same direction. The report records the input file's SHA-256 and reported backend. The bundled readback example is authored for the fixed-slot sample.

```powershell
.\ethercat-workbench-cli.exe preview-modular-pdos samples/fixed-slot-pdos.esi.xml --device 0 --slot '0=0x400' --slot '1=0x400' --run-report samples/fixed-slot-pdo-readback.json --out .local/module-readback-review.json
```

A candidate marked `matched` has the same ordered entry descriptors, including padding. `descriptor_mismatch` lists zero-based entry positions with expected and observed object index, subindex, and width. `unassigned` means the index was absent from an available layout. `unavailable` means the saved report supplied no layout for that direction. The recorded SyncManager and direction-relative bit position come from the saved layout. `sm_hint_matches` separately compares the reported SyncManager with the ESI hint. Read `assigned_exclusions` for conflicting indexes and `other_assignments` for reported PDOs outside the chosen module candidates.

A valid comparison returns JSON even when the results differ. A wrong device identity, ambiguous assignments, or invalid layout stops before JSON creation. CoE and SII sources remain visible, including SII layout evidence from EEPROM. An older layout with no source declaration keeps that provenance unavailable. Matching descriptors alone leave module occupancy and the complete expected process image unresolved.

## Decode a modular payload from saved placement

Use `--tx-hex` or `--rx-hex` with the fixed-slot preview and `--run-report`. Supply the complete image for each direction. The saved layout determines the image length, including bytes assigned to PDOs outside the selected modules.

```powershell
.\ethercat-workbench-cli.exe preview-modular-pdos samples/fixed-slot-pdos.esi.xml --device 0 --slot '0=0x400' --slot '1=0x400' --run-report samples/fixed-slot-pdo-readback.json --tx-hex '34 12 01 CD AB FE A5' --rx-hex 'EF BE 02 80' --out .local/module-payload-review.json
```

The decoder reports only fields from candidates with matching ordered descriptors. `decoded_tx` and `decoded_rx` show the supplied bytes, fields in saved bit order, and withheld PDO indexes. The saved layout supplies each field's SyncManager and direction-relative bit position, even if the ESI hint differed. The ESI supplies names and datatype hints. Numeric values use the existing little-endian PDO decoder. Other byte-aligned values wider than 64 bits are shown as raw hex, and unsupported widths or alignments have an unavailable reason.

The example decodes the two Tx status words as 4660 and 43981. Their Boolean fields are true and false. Padding and PDOs outside the chosen module candidates remain visible in the raw image. An unavailable layout, malformed hex, or incorrect length rejects the requested decode before creating its JSON receipt. The report records an interpretation of user-supplied bytes from the saved layout. Profiles and physical commissioning follow their existing workflows.

## Export a reusable modular decoder profile

Use `export-modular-profile` with the same fixed-slot ESI choices and saved run report. The operation creates a standard profile with the saved directional image lengths and the fields whose module PDO descriptors match.

```powershell
.\ethercat-workbench-cli.exe export-modular-profile samples/fixed-slot-pdos.esi.xml --device 0 --slot '0=0x400' --slot '1=0x400' --run-report samples/fixed-slot-pdo-readback.json --out .local/module-decoder.json
.\ethercat-workbench-cli.exe decode .local/module-decoder.json '34 12 01 CD AB FE A5'
```

In the desktop, load the file through **Profiles…** and open **Inputs → Offline decoder…**. **Device → Saved modular layout** shows the report hash and the saved image lengths alongside the ESI baseline. The profile also retains the slot choices, reported mapping sources, withheld PDOs and fields with unsupported widths or alignments. Supported Rx fields are available for offline output staging. Offline and synthetic capture workflows use the same profile.

Export requires a saved length for both directions, including an explicitly observed zero-length image. It preserves complete image lengths when some fields are withheld and creates a new file. The exported decoder is scoped to offline use. A hardware session uses a separately configured commissioning profile and the normal approvals.

## Review saved module identities

Use `--module-inventory` to compare fixed-slot choices with saved CoE values. The configured list at `0xF030` and detected list at `0xF050` are reviewed independently. Keep `--slot` to test explicit choices, or omit it to choose modules from a complete detected list. Automatic placement requires the same number of positions as the fixed-slot ESI. Each occupied position requires a supported identity. A zero is accepted where the ESI permits an empty slot. [ETG module-list diagnostics](https://prelive.ethercat.org/technology/knowledge-base/esm-ethercat-state-machine/)

```powershell
.\ethercat-workbench-cli.exe preview-modular-pdos samples/fixed-slot-pdos.esi.xml --device 0 --module-inventory samples/fixed-slot-module-inventory.json
.\ethercat-workbench-cli.exe export-modular-profile samples/fixed-slot-pdos.esi.xml --device 0 --module-inventory samples/fixed-slot-module-inventory.json --run-report samples/fixed-slot-pdo-readback.json --out .local/detected-decoder.json
```

The authored inventory illustrates the schema. Supply schema 1, the exact device identity, an optional serial, and an `objects` array keyed by numeric CoE index. Store the raw value of each upload in `data_hex` beside its numeric `subindex`. Subindex zero is a one-byte count and entries are four-byte little-endian module identities. Use `unavailable` for a reason when a list has no saved values. Unavailable and zero-count lists are distinct. The reader checks the declared count, unique contiguous subindexes, widths and identity. [Beckhoff object dictionary example](https://infosys.beckhoff.com/content/1033/ep8601-0022/16625888779.html)

The preview records the evidence hash, the source of the chosen placements, and differences by zero-based slot. A reported zero and an absent position appear separately. If both the inventory and PDO run report include a serial, they must agree. Offline profile export preserves the comparison and stops if the detected list conflicts with the requested placements. Physical collection requires a separate session.

## Collect module inventory in the simulator

`read-virtual-module-inventory` initializes the in-memory fixed-slot SubDevice to PREOP, reads the two lists through the CoE upload client and confirms INIT on exit. EtherCrab's initialization includes modeled register writes for the address, SyncManager and FMMU setup. Standard output contains the state observations, wire counters and inventory. The optional `--out` writes a new schema-1 inventory file. The snapshot carries `source: virtual_coe` into comparisons and offline profiles.

```powershell
.\ethercat-workbench-cli.exe read-virtual-module-inventory --out .local/virtual-modules.json --pdo-report .local/virtual-pdos.json
.\ethercat-workbench-cli.exe preview-modular-pdos samples/fixed-slot-pdos.esi.xml --device 0 --module-inventory .local/virtual-modules.json --run-report .local/virtual-pdos.json
.\ethercat-workbench-cli.exe export-modular-profile samples/fixed-slot-pdos.esi.xml --device 0 --module-inventory .local/virtual-modules.json --run-report .local/virtual-pdos.json --out .local/virtual-module-decoder.json
```

Use `--scenario detected-differs` to compare a different detected module with manual slots. `configured-unavailable` tests an SDO abort before the detected list. `detected-entry-abort` exercises a failure after part of that list was read. A failed list records the reason and omits incomplete values. `malformed-count` stops uploads on the affected mailbox, and `empty-detected` returns a valid count of zero. With `--pdo-report`, EtherCrab configures the modeled process-data SyncManagers and FMMUs in PREOP. The shared CoE client then reads the assignment lists and mapping descriptors, and the report includes the observed SyncManager lengths. Both files carry the same SubDevice identity and serial. Use `--scenario pdo-entry-differs` with `--pdo-report` to see a descriptor mismatch at an unchanged image size. The offline export withholds the affected PDO's fields. If a malformed reply invalidates the mailbox, the report records both PDO directions as unavailable. Physical module inventory and PDO readback on the selected hardware remain pending.

## Review an empty optional slot

An ungrouped fixed slot with `MinInstances="0"` and `MaxInstances="1"` accepts an explicit `--slot INDEX=0` or a zero at that position in the complete detected list. CLI slot positions start at zero. Workbench keeps the vacant position in the preview and saved profile. Later modules use their original position to resolve the ESI indexes and the saved PDO readback to locate their values in the process image. Required slots reject zero. Short detected lists cannot supply automatic placements. [ETG.2000, ModuleIdent and slot instance limits](https://jianwei.fun/wp-content/uploads/2023/11/ETG2000_S_R_V1i0i7_EtherCATSlaveInformationSpecification.pdf)

```powershell
.\ethercat-workbench-cli.exe read-virtual-module-inventory --scenario vacant-middle-slot --out .local/optional-modules.json --pdo-report .local/optional-pdos.json
.\ethercat-workbench-cli.exe export-modular-profile samples/optional-fixed-slot-pdos.esi.xml --device 0 --module-inventory .local/optional-modules.json --run-report .local/optional-pdos.json --out .local/optional-decoder.json
```

The simulator reports an axis on either side of the empty middle slot. The third slot resolves to PDOs `0x1620` and `0x1A20`. Their offsets come from the actual simulated assignments. The desktop shows vacant positions by declaration number in the offline profile's **Device → Saved modular layout** panel.

## Catalog choices

The [pinned ESI base schema](https://github.com/synapticon/siitool/blob/c46570adb1228eada44ae1f38bd61a81fab99c98/examples/ModulesSlots_DS402_Simple/EtherCATBase.xsd) distinguishes fixed entry mapping from mandatory assignment and describes the default `Sm` and exclusion list. Workbench preserves fixed entries while allowing assignment choices. Mandatory PDOs must be selected. Exclusions are conservatively checked across all chosen PDOs. Duplicate indexes in a direction, duplicate choices, unknown candidates, out-of-range SyncManagers and sharing one SyncManager between Tx and Rx are rejected.

The chosen order is stable within each SyncManager; SyncManagers are sorted ascending. Padding entries remain in the expected descriptors, and each SyncManager ends on a byte boundary. Generated fields include the ESI object references. A direction whose selection differs from ESI defaults is marked as an override. These are offline decoding expectations. Building a profile never writes assignments, PDO entries, outputs or device state. The general catalog rebuild clears staged RxPDO data so bytes from an earlier image are not retained accidentally. The explicit mode staging workflow below preserves them only when the complete Rx layout is unchanged.

An attached selection is validated when saving or running the profile. Profile image lengths must agree with it. Decoder field interpretation can still be edited. Detaching the selection keeps those fields and removes the complete assignment expectation; normal field and image checks remain. Rebuilding from a retained catalog requires the exact ESI identity baseline. Failed builds leave the existing profile unchanged, and CLI saves use a new file path.

Readback verification compares the entire selected SyncManager/PDO order and mapping descriptors, in addition to named fields and byte lengths. A known mismatch stops the setup before SAFEOP and requests INIT cleanup. Missing readback stays explicitly unavailable. A saved expected layout is not evidence of current hardware configuration. The runtime configures ESC buffers from discovered device mapping and never downloads the offline selection.

The profile catalog builds assignments from direct device PDOs. Use the fixed-slot preview above to resolve module candidate indexes. The importer keeps other supported attributes and extensions as notes. Scaling and swaps use explicit decoder settings. This subset does not expand modules, execute mode-specific mapping commands or prove full ESI XSD validity. Catalog limits are 512 candidates and 8,192 entries; selected images retain the 1,024-byte/128-field limits, and selected mapping descriptor widths are 1–255 bits. Vendor ESI files and bench reports belong in ignored `.local/`.

`samples/pdo-choices.esi.xml` is authored for the CoE virtual device. Its default mapping matches that model. The alternative is also eight bytes long and demonstrates why lengths alone do not validate a mapping. Public authored ESI fixtures use LF checkout rules so their linked sample-profile hashes remain stable.

## Stage PDO choices from an ESI mode

Version 0.28 adds a CLI shortcut for plain operating-mode PDO hints. First select the exact device/revision and mode during ESI import, or select the mode in a saved GUI profile. Mode selection itself still changes no assignments. Preview the explicit staging action, then save a new profile:

```powershell
.\ethercat-workbench-cli.exe esi-import samples/mode-pdo-staging.esi.xml --device 0 --dc-mode 1 --out .local/mode-source.json
.\ethercat-workbench-cli.exe stage-mode-pdos .local/mode-source.json
.\ethercat-workbench-cli.exe stage-mode-pdos .local/mode-source.json --out .local/mode-candidate.json
.\ethercat-workbench-cli.exe review-pdos .local/mode-candidate.json
.\ethercat-workbench-cli.exe review-sync .local/mode-candidate.json
```

The command requires an attached catalog selection and exact ESI identity. Each nonempty hint list replaces the entire specified process SyncManager (2–15), in its declared order. A listed PDO moves from its previous position; unmentioned SyncManagers and lists with no PDO hints preserve existing choices. Candidates must resolve uniquely across both directions. Mixed directions, duplicate use across SyncManagers, unknown candidates, unsupported mode/SM annotations, mandatory omissions, exclusions and existing catalog/image limits reject the whole operation. Empty hints do not mean an empty assignment. This supports the importer's plain `Device/Dc/OpMode/Sm/Pdo` subset; it does not interpret vendor extensions.

The JSON preview includes the complete before/after selection and decoder fields, image lengths, staged bytes, ESI provenance, selected mode and hashes of both profiles. Changes use the full SM/PDO/entry layout, including padding, rather than comparing byte lengths alone. Changed directions rebuild fields from the catalog, so review names, logging flags and transforms before saving. Directions with an identical layout preserve all decoder edits. Staged Rx bytes survive a Tx-only change; an Rx layout change clears them. If staged bytes were present, saving requires `--clear-staged-rx`. Previewing always leaves the source unchanged, and saving refuses an existing destination. The library also rejects applying a preview after any source-profile change.

Load a CLI-saved candidate in the GUI to review or customize it, or use the direct desktop workflow below. Host scheduling, cycle assumptions, identity/NIC, SyncType and runtime DC policy are preserved. No bus operation occurs. A candidate whose hints match offline can still disagree with the actual device mapping; normal setup verification remains required and stops before SAFEOP on a known mismatch. The authored fixture includes defaults, a same-size alternative Tx image, a larger Rx image and unsupported oversampling. XML well-formedness and Workbench consumer acceptance are covered; full XSD and hardware acceptance are unqualified.

### Desktop preview and apply

Version 0.29 exposes the same staging plan in **Mappings → ESI synchronization**. Load/import an exact ESI device and select its mode, then expand **Stage PDO choices from the selected ESI mode**. Choose **Preview mode PDO choices**. Review before/after selections, image lengths, decoder fields (including provenance, logging and transforms), staged Rx bytes and profile/ESI hashes. This preview changes no profile settings.

For an Rx layout change with existing staged bytes, **Apply mode PDO preview offline** remains disabled until you select **Discard staged Rx bytes for this changed layout**. Each new preview resets that choice. Applying updates the in-memory offline profile; enter a new profile path and use **Profiles… → Save new** to retain it. Existing source files remain protected by create-new saving. **Discard mode PDO preview** abandons only the preview.

Editing any profile setting invalidates the frozen preview and its clear choice. Acquisition, discovery and saved-file review block this staging workflow and discard any pending preview. Applying also resets the editable catalog draft, pending typed-output preview, old run display and local ESC approval checkbox so they cannot describe an earlier mapping. It preserves the candidate's unchanged decoder directions and staged bytes under the same CLI rules. It does not select a NIC, start a session, configure synchronization, enter OP or send any live output/configuration writes.

The panel's controller and pure egui layout have headless coverage. No native window, desktop input, GPU/rendering acceptance or physical device behavior is established by these checks.

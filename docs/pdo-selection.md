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

Use `preview-modular-pdos` with the original ESI and an exact device identity or list index. Supply both selectors to guard the index. For manual placement, supply one module identity per slot, using zero for an empty optional position. Slot numbers are zero-based after expanding declarations in order. A complete saved detected list can also supply the choices. The same module identity can occupy multiple slots if each slot allows it.

```powershell
.\ethercat-workbench-cli.exe esi-list samples/fixed-slot-pdos.esi.xml
.\ethercat-workbench-cli.exe preview-modular-pdos samples/fixed-slot-pdos.esi.xml --identity '0x00FF1000/11/1' --slot '0=0x400' --slot '1=0x400' --out .local/module-pdo-preview.json
```

The JSON records the exact ESI identity and SHA-256, manual slot choices, and each candidate's declared SyncManager hint. Each mapping index, excluded mapping index, and entry object index shows its declared and resolved values. At a flagged index, the preview adds the slot number multiplied by the relevant increment. A per-slot value takes precedence over the device-wide value. PDO mappings and exclusions use `SlotPdoIncrement`. Entry objects use `SlotIndexIncrement`. Unflagged indexes, widths, subindexes, and padding are preserved. In the sample, the second slot resolves TxPDO `0x1A00` to `0x1A10` and its status object `0x6041` to `0x6841`. [HPMicro CiA 402 example](https://kb.hpmicro.com/2026/06/04/ethercat%E4%BB%A5cia402%E4%BE%8B%E7%A8%8B%E4%BB%8B%E7%BB%8Dmdp%E8%AE%BE%E5%A4%87%E7%9A%84od%E5%A4%84%E7%90%86/)

A single-slot declaration has a minimum of zero or one and a maximum of one. A repeated declaration with equal positive minimum and maximum values contributes one position per instance. It needs one local module definition per chosen identity and checks each choice against that slot's declarations. Duplicate resolved mapping indexes among the chosen modules, out-of-range indexes and oversampled templates stop the preview. A `device_level_index_match` marks an index also present in the device-level catalog for separate review. The preview describes candidates. A composed process image still requires confirmed PDO assignments, SyncManager placement, and offsets. Existing profiles use their device-level PDO layouts.

## Expand fixed-count slot declarations

A declaration with equal `MinInstances` and `MaxInstances` greater than one contributes that many consecutive positions. In the sample, declaration 0 contributes positions 0 and 1, and declaration 1 starts at position 2. Each position inherits its declaration's module choices. Use one `--slot` per expanded position or a complete detected list with the expanded count. The preview retains the zero-based declaration and instance indexes for each slot. The preview accepts up to 512 manual positions and checks the ESI's `MaxSlotCount` when expanding repeated declarations. The saved detected-list format has a one-byte count and can supply up to 255 positions. [ETG.2000, SlotType instance limits](https://jianwei.fun/wp-content/uploads/2023/11/ETG2000_S_R_V1i0i7_EtherCATSlaveInformationSpecification.pdf)

```powershell
.\ethercat-workbench-cli.exe read-virtual-module-inventory --scenario repeated-fixed-slots --out .local/repeated-modules.json --pdo-report .local/repeated-pdos.json
.\ethercat-workbench-cli.exe export-modular-profile samples/repeated-fixed-slot-pdos.esi.xml --device 0 --module-inventory .local/repeated-modules.json --run-report .local/repeated-pdos.json --out .local/repeated-decoder.json
```

The following axis resolves to TxPDO `0x1A20` at bit 48 in the simulator's saved process image. Indexes follow the expanded slot positions. Payload offsets come from PDO readback.

## Choose variable slot counts

For a repeatable declaration whose `MinInstances` differs from `MaxInstances`, supply `--slot-count DECLARATION=COUNT` within those limits. Declaration indexes are zero-based and come from the ESI's `Slots` list. The count of zero omits a declaration when its minimum allows it. An optional singleton keeps its existing reserved position by default and can also be omitted with an explicit count of zero.

The CLI expands the counts in declaration order before applying `--slot` choices or a saved detected list. The flat list confirms the IDs and length for the selected layout. It leaves the declaration boundaries to the supplied counts. The preview and offline profile preserve those counts, including zeros. The desktop's **Saved modular layout** panel shows the selected counts by declaration number.

```powershell
.\ethercat-workbench-cli.exe read-virtual-module-inventory --scenario variable-slot-counts --out .local/variable-modules.json --pdo-report .local/variable-pdos.json
.\ethercat-workbench-cli.exe export-modular-profile samples/variable-slot-pdos.esi.xml --device 0 --slot-count 0=0 --slot-count 1=2 --module-inventory .local/variable-modules.json --run-report .local/variable-pdos.json --out .local/variable-decoder.json
```

The first declaration contributes no positions. The second supplies two axes and the final fixed declaration supplies the third. The sample also illustrates why the layout is explicit. Counts `0=1` and `1=1` yield the same flat list and PDO descriptors with different declaration boundaries.

## Resolve fixed slot groups

Declare a `SlotGroup` on every fixed slot. The preview supports consecutive groups starting at 0 or 1 and keeps the declaration order. Each group has a zero-based position. Indexes marked `DependOnSlotGroup` use that position multiplied by `SlotGroupPdoIncrement` for PDO mappings and exclusions or by `SlotGroupIndexIncrement` for entry objects. A per-slot increment overrides the matching device-wide value. The JSON keeps the group number, position and both effective increments. [ETG.2000, slot and PDO index attributes](https://jianwei.fun/wp-content/uploads/2023/11/ETG2000_S_R_V1i0i7_EtherCATSlaveInformationSpecification.pdf)

```powershell
.\ethercat-workbench-cli.exe read-virtual-module-inventory --scenario grouped-fixed-slots --out .local/grouped-modules.json --pdo-report .local/grouped-pdos.json
.\ethercat-workbench-cli.exe export-modular-profile samples/grouped-fixed-slot-pdos.esi.xml --device 0 --module-inventory .local/grouped-modules.json --run-report .local/grouped-pdos.json --out .local/grouped-decoder.json
```

The sample's two groups occupy three slot positions. The second position is vacant. The third position uses group position 1 and its per-slot overrides, resolving TxPDO `0x1A00` to `0x1A30` and entry object `0x6041` to `0x6841`. The exported profile uses bit offsets from the saved PDO readback. The group offset calculation uses `SlotGroup`. The separate `ModulePdoGroup` declarations describe ordering and padding in the PDO image.

## Mix slot and group indexes in a PDO template

Workbench resolves each mapping index, exclusion and PDO entry independently. `DependOnSlot` uses the absolute zero-based slot position after expansion. `DependOnSlotGroup` uses the zero-based group position. This supports forms such as a slot-dependent mapping with group-dependent entry objects. An individual index has one offset basis. Workbench rejects declarations with both flags enabled on that index. [ETG.2000, PDO index attributes](https://jianwei.fun/wp-content/uploads/2023/11/ETG2000_S_R_V1i0i7_EtherCATSlaveInformationSpecification.pdf)

```powershell
.\ethercat-workbench-cli.exe read-virtual-module-inventory --scenario mixed-slot-group-indexes --out .local/mixed-modules.json --pdo-report .local/mixed-pdos.json
.\ethercat-workbench-cli.exe export-modular-profile samples/mixed-slot-group-pdos.esi.xml --device 0 --module-inventory .local/mixed-modules.json --run-report .local/mixed-pdos.json --out .local/mixed-decoder.json
```

In the fixture, the final module is at slot position 2 and group position 1. Its TxPDO resolves to `0x1A20`, its group-dependent exclusion resolves to `0x1A35`, and its group- and slot-dependent entry objects resolve to `0x6841` and `0x2300`. The saved offsets come from the simulated PDO readback.

## Review module PDO groups and padding

The ESI importer retains group numbers from the device and module `Type` declarations, alongside each group's alignment and padding PDO indexes. The review checks group order within each saved SyncManager assignment. `group_order` summarizes known groups in direction-relative bit order, including sequences that restart at a separate SyncManager. `device_pdos` lists assigned device-level PDO indexes, SyncManagers and bit positions counted in the declared device group. It uses concrete ESI definitions with observed bit positions. An assigned index with competing device and module group membership produces a conflict. [ETG.2000, Tables 23, 57 and 72](https://www.jianwei.fun/wp-content/uploads/2023/11/ETG2000_S_R_V1i0i7_EtherCATSlaveInformationSpecification.pdf)

For each declared padding PDO, the review reports assignment, bit position and width. Assigned padding must contain padding entries. Its position must agree with the group order within its SyncManager and its end must meet the declared direction-relative boundary. When readback identifies group members, assigned padding must share a SyncManager with at least one known member of that group. An absent padding PDO appears as unassigned. The expected-layout preview calculates padding for whole groups explicitly assigned across SyncManagers. [Beckhoff alignment example](https://infosys.beckhoff.com/content/1033/bk11x0_bk1250/2199024779.html)

```powershell
.\ethercat-workbench-cli.exe read-virtual-module-inventory --scenario pdo-group-alignment --out .local/pdo-group-modules.json --pdo-report .local/pdo-group-readback.json
.\ethercat-workbench-cli.exe export-modular-profile samples/module-pdo-group-alignment.esi.xml --device 0 --module-inventory .local/pdo-group-modules.json --run-report .local/pdo-group-readback.json --out .local/pdo-group-decoder.json
```

The sample assigns the second slot's PDOs first because they belong to group 0. Two Tx padding PDOs end at bits 32 and 64. The device-level TxPDO `0x1A40` begins at bit 64, and the device-level RxPDO `0x1640` begins at bit 32. Both belong to group 2. The exported profile keeps both device fields alongside the matched module fields, with the original bit positions and group audit. A reported membership, order or padding conflict blocks export.

## Compose an expected modular PDO image

Add `--expect-layout FILE` to the modular preview. The schema-1 JSON request supplies an exact `identity` and explicit `tx` and `rx` arrays of `{ "index": NUMBER, "sm": NUMBER }` assignments. An empty array requests a zero-byte direction. Use the resolved module indexes from the slot preview and the device-level indexes from the ESI catalog. Order choices by SyncManager and then in assignment order within each SyncManager. Mandatory PDOs use their declared SyncManagers. The preview rejects unknown or repeated indexes, assigned exclusions and unsupported definitions such as oversampled PDOs. A chosen slot's definition takes precedence at a shared device/module index. [Bundled assignment request](../samples/module-pdo-expected.json)

```powershell
.\ethercat-workbench-cli.exe preview-modular-pdos samples/module-pdo-group-alignment.esi.xml --device 0 --slot 0=0x400 --slot 1=0x402 --expect-layout samples/module-pdo-expected.json --out .local/expected-layout.json
```

Grouped composition requires an explicit group for each selected PDO. Keep groups in ascending order within each SyncManager. When a whole group uses one SyncManager, Workbench applies the ESI alignment to the direction-relative offset at the end of the group and inserts its declared padding PDO when needed. Padding uses zero-index entries up to 255 bits each. Each SyncManager segment rounds to a whole byte before the next starts. [ETG.2000, Tables 23 and 57](https://jianwei.fun/wp-content/uploads/2023/11/ETG2000_S_R_V1i0i7_EtherCATSlaveInformationSpecification.pdf) · [Beckhoff group alignment example](https://infosys.beckhoff.com/content/1033/bk11x0_bk1250/2199024779.html)

The result includes the request SHA-256, computed byte counts, CoE-style descriptors, bit offsets and device, module or padding provenance. The bundled request produces 9 Tx bytes and 6 Rx bytes. The computed Tx padding PDOs start at bits 24 and 56. Add `--run-report` to compare exact SyncManagers, PDO order and every descriptor with saved readback for the same device. `assignments_match` is `null` for a direction with unavailable readback. Payload decoding and offline profile export continue to use the observed layout.

The alternate virtual scenario places the device's group 2 first on its own SyncManagers. The module groups follow on other SyncManagers. The request yields 8 bytes in each direction, with an 8-bit Tx pad on SM4 and a 16-bit Rx pad on SM5. The virtual report covers assignment and descriptor readback in PREOP.

```powershell
.\ethercat-workbench-cli.exe read-virtual-module-inventory --scenario pdo-group-multiple-sync-managers --out .local/grouped-multi-sm-inventory.json --pdo-report .local/grouped-multi-sm-readback.json
.\ethercat-workbench-cli.exe preview-modular-pdos samples/module-pdo-group-alignment.esi.xml --device 0 --module-inventory .local/grouped-multi-sm-inventory.json --expect-layout samples/module-pdo-expected-multi-sm.json --run-report .local/grouped-multi-sm-readback.json --out .local/grouped-multi-sm-review.json
```

### Specify padding for a split group

When a group uses multiple SyncManagers in one direction, supply one choice for the group in `tx_split_groups` or `rx_split_groups`. Use `{ "group": 1, "kind": "assigned", "sm": 4, "widths": [8] }` for one 8-bit padding entry on SM4. Use `{ "group": 1, "kind": "unassigned" }` for explicit absence. The assigned SyncManager must contain a PDO from the group. Workbench uses the padding index declared in the ESI and appends the specified entries after that group's last PDO on the selected SyncManager. Their end must meet the group's alignment in the direction image. The `split_groups` receipt records these choices alongside the expected descriptors.

Use `samples/module-pdo-split-group.esi.xml` and `samples/module-pdo-expected-split.json` with the same preview workflow. Supply slots `0=0x400` and `1=0x402`, or use the saved inventory from the `pdo-group-split-across-sync-managers` virtual scenario. Its PDO report supplies `--run-report` evidence. The sample places the Tx padding on SM4 and the Rx padding on SM5. [Split-group request](../samples/module-pdo-expected-split.json) · [ETG.2000, Table 57](https://jianwei.fun/wp-content/uploads/2023/11/ETG2000_S_R_V1i0i7_EtherCATSlaveInformationSpecification.pdf)

## Preview an entryless virtual PDO template

ETG.2000 permits an ESI to declare an entryless virtual PDO for configuration tools to populate. It also uses the virtual attribute for ESC register projections. Workbench composes the entryless, non-fixed device template when the request supplies its complete descriptor list. Virtual register projections have a separate [offline review](#review-virtual-txpdos-backed-by-esc-registers). The template workflow excludes selected or default virtual SyncManagers, vendor-dependent definitions and module-level virtual templates. [ETG.2000, Table 81](https://jianwei.fun/wp-content/uploads/2023/11/ETG2000_S_R_V1i0i7_EtherCATSlaveInformationSpecification.pdf)

For a device without slots, run `preview-pdo-layout`. Use `preview-modular-pdos --expect-layout` when the ESI declares slots. Include the exact identity and both direction arrays from the expected-layout format above. For a selected template, add an ordered `entries` array to its assignment. Use decimal `object_index`, `subindex` and `width` for each entry. Supply 1 to 255 entries with widths of 1 to 255 bits. Describe padding explicitly with object index and subindex zero. The request defines geometry and leaves datatype, object access and device write eligibility to separate review.

```powershell
.\ethercat-workbench-cli.exe read-virtual-module-inventory --scenario dynamic-pdo-layout --pdo-report .local/template-readback.json
.\ethercat-workbench-cli.exe preview-pdo-layout samples/virtual-pdo-template.esi.xml --device 0 --expect-layout samples/virtual-pdo-expected.json --run-report .local/template-readback.json --out .local/template-review.json
```

The expected layout identifies `device_virtual_template` as the PDO origin and `esi_with_manual_entries` as the directional mapping source. The sample places manual object `0x2200:01` at Tx bit 0, followed by the ESI's status PDO. The 4-byte Tx and 2-byte Rx expectations match the fixture. A comparison for a direction with manual entries requires an explicitly reported CoE layout. Workbench compares SyncManager, PDO order and every descriptor and reports unavailable when the source is SII or unspecified. The command previews an offline layout and can save a review receipt. [Authored ESI](../samples/virtual-pdo-template.esi.xml) · [Assignment request](../samples/virtual-pdo-expected.json)

## Review virtual TxPDOs backed by ESC registers

Run `preview-register-pdos` with an ESI and an exact identity or device index. The review lists device-level virtual TxPDOs with declared entries. The supported geometry uses a virtual `Inputs` SyncManager with an explicit `StartAddress` and one default PDO. Each entry must describe consecutive nonzero ESC register addresses, beginning at that start, with zero or omitted subindex and a whole-byte bit length. The entire range must stay within `0x0000–0x0EFF`. Unsupported geometry stays visible with the reason and the original declarations. [ETG.2000, Tables 29 and 81](https://jianwei.fun/wp-content/uploads/2023/11/ETG2000_S_R_V1i0i7_EtherCATSlaveInformationSpecification.pdf)

```powershell
.\ethercat-workbench-cli.exe preview-register-pdos samples/register-pdos.esi.xml --device 0 --snapshot samples/esc-diagnostics.json --out .local/register-pdo-review.json
```

Omit `--snapshot` for an ESI-only review. A snapshot supplies raw bytes per entry when its saved register block covers the whole entry. The bundled sample reports the two DL status bytes as `B6` and `9E`, the first two port counters as `0102`, and the AL code as `1D00`. The same report leaves the unrecorded `0x0132–0x0133` entry unavailable. The JSON preserves the source hashes, snapshot label, station and UTC anchor. The snapshot format has no device identity, so confirm it came from the intended SubDevice before using the sampled bytes. This workflow covers offline inspection of raw values. Live FMMU setup and register access remain separate. [Authored ESI](../samples/register-pdos.esi.xml) · [ESC snapshot format](esc-diagnostics.md)

### Locate a projection in saved FMMU evidence

Add `--fmmu FILE --station ADDRESS` to `preview-register-pdos`. Use the schema-1 [saved FMMU table](input-group.md#check-a-saved-fmmu-snapshot) with a count and raw 16-byte slot reads per station. The station address is required even for a one-station file. The review records the selected station and position, table hash, reported and captured slot counts and any issues. An optional ESC snapshot must report the same station address. The source formats do not bind those station addresses to a device identity or connection generation.

```powershell
.\ethercat-workbench-cli.exe preview-register-pdos samples/register-pdos.esi.xml --device 0 --fmmu samples/register-pdos-fmmu.json --station 0x1000 --snapshot samples/esc-diagnostics.json --out .local/register-fmmu-review.json
```

A match requires one active, byte-aligned, read-only FMMU to cover the whole projected register range. The matched logical address includes the offset of the projection within that FMMU. The sample maps register `0x0300` at logical address `0x10200011` because its FMMU starts at register `0x02FF`. An overlapping physical mapping or another read FMMU in the matched logical span at the selected station produces a conflict. Partial, bit-aligned and write-enabled covering FMMUs also produce conflicts. A bad Working Counter, inconsistent slot count or invalid active range makes the selected station's comparison unavailable. The optional historical sample bytes keep their own availability even when an FMMU maps the range. [Bundled FMMU table](../samples/register-pdos-fmmu.json) · [Beckhoff FMMU reference](https://download.beckhoff.com/download/Document/io/ethercat-development-products/ethercat_esc_datasheet_sec1_technology_v2.5.pdf)

## Inspect saved dynamic PDO readback

The ESI import retains three independent CoE attributes. `upload` records `PdoUpload`, which describes whether to upload the device's PDO configuration and assignment. `assign` and `configure` record `PdoAssign` and `PdoConfig`, the startup download declarations for assignments and mappings. An omitted declaration stays unknown. [ETG.2000, CoE mailbox attributes](https://jianwei.fun/wp-content/uploads/2023/11/ETG2000_S_R_V1i0i7_EtherCATSlaveInformationSpecification.pdf)

`inspect-pdo-readback PROFILE RUN_REPORT` requires the saved run to identify exactly one device matching the profile. An attached ESI must match that identity too. It lists the observed SyncManagers, assignments, bit offsets and widths. `expected_selection_matches` compares the entire observed assignment and descriptors when the profile carries an offline ESI selection. A missing direction or expectation yields `null`. Older reports can also have an unknown mapping source.

Use `--tx-hex` and `--rx-hex` to supply optional complete images at their observed lengths. Each non-padding entry is packed into raw hex with its first mapped bit at bit zero of the first byte. ESI name and datatype hints appear when concrete catalog entries agree on the same directional object, subindex and width. Entries with absent or conflicting hints still show their offsets and raw bytes.

```powershell
.\ethercat-workbench-cli.exe esi-import samples/dynamic-pdo.esi.xml --device 0 --out .local/dynamic-profile.json
.\ethercat-workbench-cli.exe read-virtual-module-inventory --scenario dynamic-pdo-layout --pdo-report .local/dynamic-readback.json
.\ethercat-workbench-cli.exe inspect-pdo-readback .local/dynamic-profile.json .local/dynamic-readback.json --tx-hex 'A5 34 12 01' --rx-hex '78 56'
```

The sample shows a 4-byte observed Tx image against the ESI's 3-byte Tx selection. Rx still matches. The first Tx value carries the diagnostic-byte hint even though its PDO index moved, and object `0x6042` appears with its raw value and no ESI hint. [Authored dynamic PDO ESI](../samples/dynamic-pdo.esi.xml)

### Export an offline decoder from observed PDOs

Use `export-observed-pdo-profile PROFILE RUN_REPORT --out NEW.json` to create a profile using the observed PDO descriptors, bit offsets and directional lengths. The export requires known lengths in both directions, including an explicitly empty layout. It uses matching ESI hints for supported scalar types. Padding and entries without a supported type are omitted from the typed fields. The profile retains the saved descriptors and offsets withheld at export.

Use repeatable `--tx-kind BIT=KIND` and `--rx-kind BIT=KIND` options to supply explicit types at observed entry starts. Supported kinds are `bool`, `unsigned`, `signed`, `f32`, `f64` and `raw`. Use decimal direction-relative bit offsets from `inspect-pdo-readback`. The export checks each choice against the observed entry's width and alignment. Explicit choices that replace a recognized ESI type are recorded as overrides. Explicit choices for unknown entries are recorded as manual.

```powershell
.\ethercat-workbench-cli.exe export-observed-pdo-profile .local/dynamic-profile.json .local/dynamic-readback.json --tx-kind 8=signed --rx-kind 0=raw --out .local/dynamic-decoder.json
.\ethercat-workbench-cli.exe decode .local/dynamic-decoder.json 'A5 34 F2 01'
```

The sample decodes the explicitly typed object at Tx bit 8 as −3532. The profile keeps the source report's SHA-256, mapping source and assignments separately from its ESI baseline. Reload validates identity, image lengths and field geometry against the retained descriptors. Load it in **Profiles…** to use **Inputs → Offline decoder…** or offline Rx staging. **Device → Saved PDO readback** shows its provenance. These decoder profiles have an offline scope.

## Compare module candidates with saved PDO readback

Add `--run-report` to the fixed-slot preview. It checks the saved report for exactly one device with the selected ESI identity, then compares each resolved PDO with the reported assignment in the same direction. The report records the input file's SHA-256 and reported backend. The bundled readback example is authored for the fixed-slot sample.

```powershell
.\ethercat-workbench-cli.exe preview-modular-pdos samples/fixed-slot-pdos.esi.xml --device 0 --slot '0=0x400' --slot '1=0x400' --run-report samples/fixed-slot-pdo-readback.json --out .local/module-readback-review.json
```

A candidate marked `matched` has the same ordered entry descriptors, including padding. `descriptor_mismatch` lists zero-based entry positions with expected and observed object index, subindex, and width. `unassigned` means the index was absent from an available layout. `unavailable` means the saved report supplied no layout for that direction. The recorded SyncManager and direction-relative bit position come from the saved layout. `sm_hint_matches` separately compares the reported SyncManager with the ESI hint. Read `assigned_exclusions` for conflicting indexes and `other_assignments` for reported PDOs outside the chosen module candidates. The directional `device_pdos` list compares assigned indexes against the device-level ESI catalog. An index shared with a chosen module is reviewed under that module's `device_level_index_match`. Declared group padding stays in the padding audit. Device-level PDOs marked virtual or requiring module/vendor interpretation appear as `unsupported`. [ETG PDO mapping and configuration](https://prelive.ethercat.org/technology/knowledge-base/pdo-mapping-and-configuration/)

A valid comparison returns JSON even when the results differ. A wrong device identity, ambiguous assignments, or invalid layout stops before JSON creation. CoE and SII sources remain visible, including SII layout evidence from EEPROM. An older layout with no source declaration keeps that provenance unavailable. Matching descriptors alone leave module occupancy and the complete expected process image unresolved.

## Decode a modular payload from saved placement

Use `--tx-hex` or `--rx-hex` with the fixed-slot preview and `--run-report`. Supply the complete image for each direction. The saved layout determines the image length, including bytes assigned to PDOs outside the selected modules.

```powershell
.\ethercat-workbench-cli.exe preview-modular-pdos samples/fixed-slot-pdos.esi.xml --device 0 --slot '0=0x400' --slot '1=0x400' --run-report samples/fixed-slot-pdo-readback.json --tx-hex '34 12 01 CD AB FE A5' --rx-hex 'EF BE 02 80' --out .local/module-payload-review.json
```

The decoder reports fields from device and module candidates with matching ordered descriptors. An assigned exclusion withholds the affected device PDO. `decoded_tx` and `decoded_rx` show the supplied bytes, fields in saved bit order, and indexes under `withheld_pdos` for module candidates or `withheld_device_pdos` for device candidates. Module rows identify a slot and module identity, and device rows use the device-level ESI labels. The saved layout supplies each field's SyncManager and direction-relative bit position, even if the ESI hint differed. The ESI supplies names and datatype hints. Numeric values use the existing little-endian PDO decoder. Other byte-aligned values wider than 64 bits are shown as raw hex, and unsupported widths or alignments have an unavailable reason.

The example decodes the two Tx status words as 4660 and 43981. Their Boolean fields are true and false. Padding and unrecognized PDO bytes remain visible in the raw image. An unavailable layout, malformed hex, or incorrect length rejects the requested decode before creating its JSON receipt. The report records an interpretation of user-supplied bytes from the saved layout. Profiles and physical commissioning follow their existing workflows.

## Export a reusable modular decoder profile

Use `export-modular-profile` with the same fixed-slot ESI choices and saved run report. The operation creates a standard profile with the saved directional image lengths and matched device and module fields.

```powershell
.\ethercat-workbench-cli.exe export-modular-profile samples/fixed-slot-pdos.esi.xml --device 0 --slot '0=0x400' --slot '1=0x400' --run-report samples/fixed-slot-pdo-readback.json --out .local/module-decoder.json
.\ethercat-workbench-cli.exe decode .local/module-decoder.json '34 12 01 CD AB FE A5'
```

In the desktop, load the file through **Profiles…** and open **Inputs → Offline decoder…**. **Device → Saved modular layout** shows the report hash and the saved image lengths alongside the ESI baseline. The profile retains slot choices, reported mapping sources, matched device PDO positions, withheld PDOs and fields with unsupported widths or alignments. Exported names start with `Device` or the corresponding `Slot`. Supported Rx fields are available for offline output staging. Offline and synthetic capture workflows use the same profile.

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

A fixed slot with `MinInstances="0"` and `MaxInstances="1"` accepts an explicit `--slot INDEX=0` or a zero at that position in the complete detected list. CLI slot positions start at zero. Workbench keeps the vacant position in the preview and saved profile. Later modules use their original position to resolve the ESI indexes and the saved PDO readback to locate their values in the process image. Required slots reject zero. Short detected lists cannot supply automatic placements. [ETG.2000, ModuleIdent and slot instance limits](https://jianwei.fun/wp-content/uploads/2023/11/ETG2000_S_R_V1i0i7_EtherCATSlaveInformationSpecification.pdf)

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

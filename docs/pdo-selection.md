# Offline ESI PDO selection

The profile retains a catalog of direct device TxPDO and RxPDO candidates. It stores their indexes, labels, default SyncManagers, entries, padding, types, fixed/mandatory flags and exclusions. Candidates without `Sm`, or with `Sm="-1"`, remain available for explicit choices. ESI filename, SHA-256 and exact identity remain the source baseline. Older profiles without a catalog continue to load; reimport their ESI to use the selector.

The [pinned ESI base schema](https://github.com/synapticon/siitool/blob/c46570adb1228eada44ae1f38bd61a81fab99c98/examples/ModulesSlots_DS402_Simple/EtherCATBase.xsd) distinguishes fixed entry mapping from mandatory assignment and describes the default `Sm` and exclusion list. Workbench preserves fixed entries while allowing assignment choices. Mandatory PDOs must be selected. Exclusions are conservatively checked across all chosen PDOs. Duplicate indexes in a direction, duplicate choices, unknown candidates, out-of-range SyncManagers and sharing one SyncManager between Tx and Rx are rejected.

The chosen order is stable within each SyncManager; SyncManagers are sorted ascending. Padding entries remain in the expected descriptors, and each SyncManager ends on a byte boundary. Generated fields include the ESI object references. A direction whose selection differs from ESI defaults is marked as an override. These are offline decoding expectations. Building a profile never writes assignments, PDO entries, outputs or device state. The general catalog rebuild clears staged RxPDO data so bytes from an earlier image are not retained accidentally. The explicit mode staging workflow below preserves them only when the complete Rx layout is unchanged.

An attached selection is validated when saving or running the profile. Profile image lengths must agree with it. Decoder field interpretation can still be edited. Detaching the selection keeps those fields and removes the complete assignment expectation; normal field and image checks remain. Rebuilding from a retained catalog requires the exact ESI identity baseline. Failed builds leave the existing profile unchanged, and CLI saves use a new file path.

Readback verification compares the entire selected SyncManager/PDO order and mapping descriptors, in addition to named fields and byte lengths. A known mismatch stops the setup before SAFEOP and requests INIT cleanup. Missing readback stays explicitly unavailable. A saved expected layout is not evidence of current hardware configuration. The runtime configures ESC buffers from discovered device mapping and never downloads the offline selection.

Virtual PDOs and slot/module-dependent indexes are not materialized. Other attributes and extensions are retained as notes when supported by the importer; datatype annotations are not automatically applied as scaling or swaps. The decoder's explicit transforms are separate settings. This subset does not expand modules, execute mode-specific mapping commands or prove full ESI XSD validity. Catalog limits are 512 candidates and 8,192 entries; selected images retain the 1,024-byte/128-field limits, and selected mapping descriptor widths are 1–255 bits. Vendor ESI files and bench reports belong in ignored `.local/`.

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

Load the saved candidate in the GUI to review or customize it. Host scheduling, cycle assumptions, identity/NIC, SyncType and runtime DC policy are preserved. No bus operation occurs. A candidate whose hints match offline can still disagree with the actual device mapping; normal setup verification remains required and stops before SAFEOP on a known mismatch. The authored fixture includes defaults, a same-size alternative Tx image, a larger Rx image and unsupported oversampling. XML well-formedness and Workbench consumer acceptance are covered; full XSD and hardware acceptance are unqualified.

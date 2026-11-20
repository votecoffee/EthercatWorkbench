# Typed offline RxPDO staging

Version 0.17 adds typed editing of a profile's offline RxPDO image. It uses the existing field definitions and their inverse endian/word transforms. It does not open a NIC, enter OP, send RxPDO bytes, change PDO mappings or write device configuration. Saved staged bytes remain offline settings; they grant no permission for live outputs.

## Desktop

Configure the RxPDO length and fields in **Mappings → Output fields**, then use **Outputs → Stage typed RxPDO values offline**. Add assignments, choose each zero-based field and enter its typed value. Existing raw staging and decoding remain available.

Choose **Preview typed staging** to prepare a frozen result without changing the current profile. Review before/after bytes, requested values, changed-bit count and decoded impacts. The impact table includes changed overlapping views that were not selected. Mapping source describes the field definition (manual, ESI or override); all values entered here are manual offline values. An expected identity is copied from the profile and is not bus discovery evidence.

Choose **Apply preview to offline image** to update only the staged hex string in memory. Save the profile through **Profiles…** to a new path to retain it. Apply rechecks a hash of the entire effective profile, including identity, mapping and existing staged text. Changing any setting after preview requires another preview. Editing the typed assignments invalidates the pending preview. Loading a profile resets the typed editor. Profile controls remain disabled during a bus session or saved-file review.

An empty staged image requires **Initialize from zero only when the staged image is empty**. Its before bytes are an explicit zero-filled assumption, not values read from a device. Unassigned bits then start at zero. This option rejects an existing image instead of clearing its bytes. Clear raw staging deliberately before choosing zero initialization if that is the intended offline operation.

## CLI

`stage-rx` prints the review JSON without saving unless `--out` is supplied. Repeat `--set INDEX=VALUE` in any order; indexes refer to the profile's RxPDO field array. An output path saves a complete new profile through the existing create-new, UTF-8 and flush workflow. Existing profiles/files are preserved. A validation, range or conflicting-assignment error creates no output profile. A disk write failure may leave an incomplete new file and must be handled explicitly.

```powershell
# Preview only; the source profile is unchanged.
.\ethercat-workbench-cli.exe stage-rx samples/output-staging.json --set '0=true' --set '1=5' --set '2=-1234'

# Save offline staged bytes in a new profile.
.\ethercat-workbench-cli.exe stage-rx samples/output-staging.json --set '3=1.5' --set '4=0x11223344' --set '5=CA FE BA BE' --out .local/staged.json

# For a profile whose staged image is empty, explicitly start from zero.
.\ethercat-workbench-cli.exe stage-rx .local/blank-staging.json --zero --set '0=true' --out .local/zero-based-staged.json
```

The schema-1 review includes application version, `offline_rxpdo_only` scope, canonical effective-profile SHA-256, profile name/expected identity, RxPDO length, `manual_offline` value source, the zero-initialization flag, raw before/after bytes, assignments and affected fields. It is a preview record, not a run report or a live-output approval. Saved review JSON is not accepted as an executable plan; prepare a new preview against the current profile.

## Value and overlap rules

| Field kind | Input |
| --- | --- |
| Unsigned | Decimal or `0x`/`0X` hexadecimal, without a sign, within the mapped width |
| Signed | Decimal `i64`, within the mapped two's-complement width |
| Bool | `true`, `false` (case insensitive), `1` or `0` |
| F32 / F64 | Finite decimal/exponent notation parsed at the field's precision; inspect the decoded result for rounding, including underflow to zero |
| Raw | Exactly the field's number of hex bytes, with optional ASCII whitespace |

Assignments are bounded to 1–128 fields and 3,072 input bytes per value. Numeric fields retain the profile's existing validation rules: bit fields can be unaligned; byte/word transforms require their specified alignment and widths. The encoder reverses the decoder's transformations. Explicit raw hex staging can still represent arbitrary patterns; the finite-value rule applies to typed float entries.

Only selected bits are replaced in an existing image. Padding and unrelated bytes remain intact. Simultaneous overlapping assignments are accepted when every shared bit agrees and rejected when any shared bit conflicts. Duplicate field indexes are rejected even when their requested values agree. Each prepare operation is atomic: failures do not change the source profile. Applying a stale preview also leaves the profile intact.

The bundled fixture has bit fields, a signed setpoint, a big-endian float, a word-byte-swapped counter, raw bytes, an overlapping control-byte view and an F64 ratio. Its bytes and device-independent fields are authored examples, not vendor data or a physical output contract. Native GUI interaction and separately approved physical output work remain pending.

## Rehearse an RxPDO write

```powershell
.\ethercat-workbench-cli.exe stage-rx samples/virtual.json --set '0=4660' --out .local/rehearsal-profile.json
.\ethercat-workbench-cli.exe rehearse-output .local/rehearsal-profile.json --out .local/write-rehearsal.json
```

The command uses one in-memory CoE device and an explicit two-byte staged image. EtherCrab verifies the modeled identity, image sizes and PDO mapping during setup. The rehearsal requires the entire RxPDO image to match the single mapped field, then reads clean SAFEOP, preloads the two bytes with LWR, requests and confirms OP, and sends the same two bytes once more in OP. Each write expects WKC 1. INIT cleanup reads the AL state separately from the state-write acknowledgement. This is a one-shot sequence. Device-specific watchdogs and cyclic output timing require separate bench work. [Beckhoff state machine](https://infosys.beckhoff.com/content/1033/el6688/1036980875.html), [Beckhoff ESC command reference](https://download.beckhoff.com/download/document/io/ethercat-development-products/ethercat_esc_datasheet_sec1_technology_v2.5.pdf)

| Scenario | Evidence to check |
| --- | --- |
| `normal` | Both LWRs acknowledge WKC 1, the model applies the staged bytes and INIT is confirmed. |
| `preload-wkc` | WKC 0 stops OP entry and the output exchange. |
| `op-reject` | The state write acknowledges, but AL reports an error and the post-OP LWR is skipped. |
| `write-reply-lost` | The post-OP LWR is attempted once. Its missing reply leaves the sender's outcome unknown. The separate model audit records application, then INIT is confirmed. |
| `init-reject` | The INIT request acknowledges, but AL still reports OP. The model retains active outputs and the rehearsal fails. |

Supply `--scenario CASE` to select a fault. Faults return a nonzero exit and still produce a JSON report when the rehearsal started. The report binds the effective profile hash and staged bytes to the PDO verification, per-step WKC and AL readback. A null step means the operation was skipped. An attempted write with null `actual_wkc` means the matching acknowledgement was unavailable. `modeled_outputs.last_applied` is historical simulation evidence and `outputs_active` is its final state. Existing report destinations and the staged profile are preserved.

Physical output work requires the selected device's output meaning, safe image and watchdog behavior, a reviewed INIT or other approved stop procedure, and separate approval for the exact OP and write scope. SAFEOP output behavior depends on the device and its configuration. [Beckhoff SAFEOP conditions](https://infosys.beckhoff.com/content/1033/el6688/1036980875.html)

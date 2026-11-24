//! Resolve PDO template indexes for ESI slot placements.
mod decode;
mod expected;
pub mod inventory;
pub mod profile;
mod readback;

use super::{
    bool_attr, child, dc_text, default_sm, label, modular, named, node_number, number, read_file,
    select_device, unique_child, with_description,
};
use crate::{
    model::{EsiSource, Identity, Profile},
    pdo_catalog::Direction,
};
use anyhow::{Context, Result, ensure};
use roxmltree::Node;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Clone, Debug)]
pub struct Placement {
    slot: usize,
    module_ident: u32,
}

pub fn placement(text: &str) -> Result<Placement> {
    ensure!(text.len() <= 64, "ESI slot placement exceeds 64 bytes");
    let (slot, ident) = text
        .split_once('=')
        .context("expected zero-based SLOT=MODULE_IDENT")?;
    Ok(Placement {
        slot: usize::try_from(number(slot).context("invalid slot position")?)?,
        module_ident: number(ident).context("invalid module identity")?,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotCount {
    pub declaration_index: usize,
    pub count: u32,
}

pub fn slot_count(text: &str) -> Result<SlotCount> {
    ensure!(text.len() <= 64, "ESI slot count argument exceeds 64 bytes");
    let (declaration, count) = text
        .split_once('=')
        .context("expected zero-based DECLARATION=COUNT")?;
    Ok(SlotCount {
        declaration_index: usize::try_from(
            number(declaration).context("invalid declaration index")?,
        )?,
        count: number(count).context("invalid slot instance count")?,
    })
}

#[derive(Debug, Serialize)]
pub struct Preview {
    schema: u32,
    scope: &'static str,
    esi_file_name: String,
    esi_sha256: String,
    identity: Identity,
    slots: Vec<SlotPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_pdo_group: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    module_pdo_groups: Vec<modular::ModulePdoGroup>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    slot_counts: Vec<SlotCount>,
    #[serde(skip)]
    esi: EsiSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    module_inventory: Option<inventory::Comparison>,
    #[serde(skip_serializing_if = "Option::is_none")]
    saved_readback: Option<readback::Comparison>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_layout: Option<expected::ExpectedLayout>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decoded_tx: Option<decode::DecodedPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decoded_rx: Option<decode::DecodedPayload>,
}

impl Preview {
    pub fn offline_profile(self) -> Result<Profile> {
        let readback = self
            .saved_readback
            .as_ref()
            .context("profile export requires saved PDO readback")?;
        ensure!(
            self.module_inventory
                .as_ref()
                .is_none_or(|report| report.detected.state != inventory::State::Mismatch),
            "saved detected module list differs from the requested slot placements"
        );
        profile::build(
            self.esi,
            readback,
            &self.slots,
            self.slot_counts,
            self.module_inventory,
        )
    }

    pub fn compare_saved_run(&mut self, path: &Path) -> Result<()> {
        let serial = self
            .module_inventory
            .as_ref()
            .and_then(|report| report.reported_serial);
        let readback = readback::compare(path, &self.esi, serial, &mut self.slots)?;
        if let Some(expected) = &mut self.expected_layout {
            expected.compare_saved(&readback);
        }
        self.saved_readback = Some(readback);
        self.decoded_tx = None;
        self.decoded_rx = None;
        Ok(())
    }

    pub fn compose_expected_layout(&mut self, path: &Path) -> Result<()> {
        let mut expected =
            expected::compose(path, &self.esi, &self.slots, &self.module_pdo_groups)?;
        if let Some(readback) = &self.saved_readback {
            expected.compare_saved(readback);
        }
        self.expected_layout = Some(expected);
        Ok(())
    }

    pub fn decode_saved_payload(&mut self, direction: Direction, bytes: &[u8]) -> Result<()> {
        let readback = self
            .saved_readback
            .as_ref()
            .context("payload decoding requires saved PDO readback")?;
        let decoded = decode::payload(direction, bytes, readback, &self.slots, &self.esi)?;
        match direction {
            Direction::Tx => self.decoded_tx = Some(decoded),
            Direction::Rx => self.decoded_rx = Some(decoded),
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct SlotPreview {
    slot: usize,
    name: Option<String>,
    module_ident: u32,
    module_name: String,
    slot_pdo_increment: Option<u32>,
    slot_index_increment: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slot_instance: Option<SlotInstance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<GroupPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    module_pdo_group: Option<u32>,
    pdos: Vec<PdoPreview>,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct SlotInstance {
    declaration_index: usize,
    instance_index: usize,
}

#[derive(Debug, Serialize)]
struct GroupPreview {
    number: u32,
    position: u32,
    pdo_increment: Option<u32>,
    index_increment: Option<u32>,
}

#[derive(Clone, Copy)]
struct Offset {
    position: u32,
    increment: Option<u32>,
    attribute: &'static str,
}

#[derive(Clone, Copy)]
struct IndexOffsets {
    slot: Offset,
    group: Option<Offset>,
}

#[derive(Debug, Serialize)]
struct PdoPreview {
    direction: Direction,
    name: Option<String>,
    declared_sm: Option<u8>,
    #[serde(skip)]
    mandatory: bool,
    mapping: Index,
    entries: Vec<Entry>,
    excludes: Vec<Index>,
    device_level_index_match: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    saved_readback: Option<readback::Candidate>,
}

#[derive(Debug, Serialize)]
struct Entry {
    object: Index,
    subindex: u8,
    width: u8,
    name: Option<String>,
    #[serde(skip)]
    data_type: Option<String>,
}

#[derive(Debug, Serialize)]
struct Index {
    declared: u16,
    resolved: u16,
}

#[derive(Debug, Serialize)]
pub struct DeviceLayoutReview {
    schema: u32,
    scope: &'static str,
    esi_file_name: String,
    esi_sha256: String,
    identity: Identity,
    expected_layout: expected::ExpectedLayout,
    #[serde(skip_serializing_if = "Option::is_none")]
    saved_readback: Option<readback::Comparison>,
}

pub fn preview_device_layout(
    path: &Path,
    device: Option<usize>,
    identity: Option<&Identity>,
    request: &Path,
    run_report: Option<&Path>,
) -> Result<DeviceLayoutReview> {
    let devices = super::load(path)?;
    let source = &select_device(&devices, device, identity)?.source;
    ensure!(
        source.modular.is_none(),
        "use preview-modular-pdos for ESI devices with slot declarations"
    );
    let mut expected_layout = expected::compose(request, source, &[], &[])?;
    let saved_readback = run_report
        .map(|path| readback::compare(path, source, None, &mut []))
        .transpose()?;
    if let Some(saved) = &saved_readback {
        expected_layout.compare_saved(saved);
    }
    Ok(DeviceLayoutReview {
        schema: 1,
        scope: "offline_esi_device_pdo_layout",
        esi_file_name: source.file_name.clone(),
        esi_sha256: source.sha256.clone(),
        identity: source.identity.clone(),
        expected_layout,
        saved_readback,
    })
}

pub fn preview(
    path: &Path,
    device: Option<usize>,
    identity: Option<&Identity>,
    placements: &[Placement],
) -> Result<Preview> {
    preview_with_inventory(path, device, identity, placements, None)
}

pub fn preview_with_inventory(
    path: &Path,
    device: Option<usize>,
    identity: Option<&Identity>,
    placements: &[Placement],
    saved_inventory: Option<&Path>,
) -> Result<Preview> {
    preview_with_slot_counts(path, device, identity, placements, saved_inventory, &[])
}

pub fn preview_with_slot_counts(
    path: &Path,
    device: Option<usize>,
    identity: Option<&Identity>,
    placements: &[Placement],
    saved_inventory: Option<&Path>,
    slot_counts: &[SlotCount],
) -> Result<Preview> {
    let (file, bytes) = read_file(path)?;
    with_description(&file, &bytes, |descriptions, devices| {
        let selected = select_device(&devices, device, identity)?;
        let inventory = saved_inventory
            .map(|path| inventory::Inventory::load(path, &selected.source.identity))
            .transpose()?;
        preview_device(
            &selected.source,
            descriptions,
            placements,
            inventory,
            slot_counts,
        )
    })
}

fn preview_device(
    source: &EsiSource,
    descriptions: Node<'_, '_>,
    placements: &[Placement],
    inventory: Option<inventory::Inventory>,
    slot_counts: &[SlotCount],
) -> Result<Preview> {
    let modular = source
        .modular
        .as_ref()
        .context("selected ESI device has no slot declarations")?;
    let positions = slot_positions(modular, slot_counts)?;
    let record_instances = !slot_counts.is_empty() || positions.len() != modular.slots.len();
    let mut slot_counts = slot_counts.to_vec();
    slot_counts.sort_unstable_by_key(|count| count.declaration_index);
    ensure!(
        modular
            .additional_elements
            .iter()
            .all(|item| matches!(item.as_str(), "SlotSelections" | "SlotGroupData")),
        "PDO index preview does not support the declared slot extensions"
    );
    let group_base = group_base(modular)?;
    let detected;
    let (placements, placement_source) = if placements.is_empty() {
        let inventory = inventory
            .as_ref()
            .context("supply fixed slot choices or a saved module inventory")?;
        detected = inventory.detected_placements()?;
        ensure!(
            detected.len() == positions.len(),
            "detected module count differs from the ESI fixed slot count"
        );
        (
            detected.as_slice(),
            inventory::PlacementSource::SavedDetected,
        )
    } else {
        (placements, inventory::PlacementSource::Manual)
    };
    let mut by_slot = BTreeMap::new();
    for selection in placements {
        ensure!(
            selection.slot < positions.len(),
            "slot {} is out of range",
            selection.slot
        );
        ensure!(
            by_slot
                .insert(selection.slot, selection.module_ident)
                .is_none(),
            "duplicate placement for slot {}",
            selection.slot
        );
    }
    ensure!(
        by_slot.len() == positions.len(),
        "supply one explicit placement for every slot"
    );

    let mut definitions = BTreeMap::new();
    if let Some(modules) = unique_child(descriptions, "Modules")? {
        for node in modules.children().filter(|node| named(*node, "Module")) {
            if let Some((ident, ty)) = modular::module_type(node) {
                definitions
                    .entry(ident)
                    .and_modify(|value| *value = None)
                    .or_insert(Some((node, ty)));
            }
        }
    }
    let padding_pdos: BTreeSet<_> = modular
        .pdo_groups
        .iter()
        .flat_map(|group| [group.rx_pdo, group.tx_pdo])
        .flatten()
        .collect();
    let mut seen = BTreeSet::new();
    let mut slots = Vec::with_capacity(by_slot.len());
    for (position, ident) in by_slot {
        let instance = positions[position];
        let slot = &modular.slots[instance.declaration_index];
        let pdo_increment = increment(&modular.slot_attributes, slot, "SlotPdoIncrement")?;
        let index_increment = increment(&modular.slot_attributes, slot, "SlotIndexIncrement")?;
        let group = if let Some((number, base)) = slot.group.zip(group_base) {
            Some(GroupPreview {
                number,
                position: number - base,
                pdo_increment: increment(&modular.slot_attributes, slot, "SlotGroupPdoIncrement")?,
                index_increment: increment(
                    &modular.slot_attributes,
                    slot,
                    "SlotGroupIndexIncrement",
                )?,
            })
        } else {
            None
        };
        let slot_position = u32::try_from(position)?;
        let pdo_offsets = IndexOffsets {
            slot: Offset {
                position: slot_position,
                increment: pdo_increment,
                attribute: "SlotPdoIncrement",
            },
            group: group.as_ref().map(|group| Offset {
                position: group.position,
                increment: group.pdo_increment,
                attribute: "SlotGroupPdoIncrement",
            }),
        };
        let entry_offsets = IndexOffsets {
            slot: Offset {
                position: slot_position,
                increment: index_increment,
                attribute: "SlotIndexIncrement",
            },
            group: group.as_ref().map(|group| Offset {
                position: group.position,
                increment: group.index_increment,
                attribute: "SlotGroupIndexIncrement",
            }),
        };
        let mut preview = SlotPreview {
            slot: position,
            name: slot.name.clone(),
            module_ident: ident,
            module_name: "Empty slot".into(),
            slot_pdo_increment: pdo_increment,
            slot_index_increment: index_increment,
            slot_instance: record_instances.then_some(instance),
            group,
            module_pdo_group: None,
            pdos: Vec::new(),
        };
        if ident == 0 {
            ensure!(
                slot.min_instances == Some(0) && slot.max_instances == Some(1),
                "empty required slot {position}"
            );
            slots.push(preview);
            continue;
        }
        let (node, ty) = definitions
            .get(&ident)
            .with_context(|| {
                format!("no local module definition for {ident:#010x} at slot {position}")
            })?
            .with_context(|| {
                format!("multiple local module definitions for {ident:#010x} at slot {position}")
            })?;
        let class = ty.attribute("ModuleClass").map(str::trim);
        ensure!(
            slot.choices
                .iter()
                .any(|choice| choice.matches(ident, class, source.identity.vendor)),
            "module {ident:#010x} is not allowed in slot {position}"
        );
        preview.module_pdo_group = modular::module_pdo_group(ty)?;
        preview.module_name = label(node, "Name")
            .or_else(|| ty.text())
            .unwrap_or("Unnamed module")
            .into();
        for pdo in modular::pdo_nodes(node) {
            let resolved =
                resolve_pdo(pdo, pdo_offsets, entry_offsets, source).with_context(|| {
                    format!("resolve PDO indexes for slot {position}, module {ident:#010x}")
                })?;
            ensure!(
                !padding_pdos.contains(&resolved.mapping.resolved),
                "resolved module PDO {:#06x} collides with a ModulePdoGroup padding PDO",
                resolved.mapping.resolved
            );
            ensure!(
                seen.insert(resolved.mapping.resolved),
                "resolved PDO index {:#06x} is used more than once among the chosen modules",
                resolved.mapping.resolved
            );
            preview.pdos.push(resolved);
        }
        slots.push(preview);
    }
    Ok(Preview {
        schema: 1,
        scope: "offline_esi_module_pdo_candidates",
        esi_file_name: source.file_name.clone(),
        esi_sha256: source.sha256.clone(),
        identity: source.identity.clone(),
        module_inventory: inventory.map(|inventory| inventory.compare(&slots, placement_source)),
        slots,
        device_pdo_group: source.device_pdo_group,
        module_pdo_groups: modular.pdo_groups.clone(),
        slot_counts,
        esi: source.clone(),
        saved_readback: None,
        expected_layout: None,
        decoded_tx: None,
        decoded_rx: None,
    })
}

fn slot_positions(
    modular: &modular::Description,
    counts: &[SlotCount],
) -> Result<Vec<SlotInstance>> {
    let mut requested_counts = BTreeMap::new();
    for &SlotCount {
        declaration_index,
        count,
    } in counts
    {
        ensure!(
            declaration_index < modular.slots.len(),
            "slot declaration {declaration_index} is out of range"
        );
        ensure!(
            requested_counts.insert(declaration_index, count).is_none(),
            "duplicate count for slot declaration {declaration_index}"
        );
    }

    let mut positions = Vec::new();
    for (declaration_index, slot) in modular.slots.iter().enumerate() {
        let (min, max) = slot
            .min_instances
            .zip(slot.max_instances)
            .context("slot declaration requires MinInstances and MaxInstances")?;
        ensure!(
            min <= max && max > 0,
            "invalid instance limits {min}..={max} for slot declaration {declaration_index}"
        );
        let count = match requested_counts.get(&declaration_index).copied() {
            Some(count) => {
                ensure!(
                    (min..=max).contains(&count),
                    "count {count} for slot declaration {declaration_index} is outside {min}..={max}"
                );
                count
            }
            None if min == max || max == 1 => max,
            None => anyhow::bail!(
                "slot declaration {declaration_index} requires --slot-count {declaration_index}=COUNT ({min}..={max})"
            ),
        };
        let count = usize::try_from(count)?;
        ensure!(
            count <= modular::MAX_DECLARATIONS - positions.len(),
            "ESI expands to more than {} slot positions",
            modular::MAX_DECLARATIONS
        );
        positions.extend((0..count).map(|instance_index| SlotInstance {
            declaration_index,
            instance_index,
        }));
    }
    ensure!(
        !positions.is_empty(),
        "ESI has no slot positions to preview"
    );
    if (positions.len() > modular.slots.len() || !counts.is_empty())
        && let Some(max) = modular.slot_attributes.get("MaxSlotCount")
    {
        let max = usize::try_from(number(max).context("invalid MaxSlotCount")?)?;
        ensure!(
            positions.len() <= max,
            "ESI expands to {} slot positions, exceeding MaxSlotCount {max}",
            positions.len()
        );
    }
    Ok(positions)
}

fn group_base(modular: &modular::Description) -> Result<Option<u32>> {
    if let Some(base) = modular.slots[0].group {
        ensure!(base <= 1, "fixed SlotGroup numbering must start at 0 or 1");
        let mut previous = base;
        for slot in &modular.slots {
            let group = slot
                .group
                .context("grouped preview requires a SlotGroup for every slot")?;
            ensure!(
                group == previous || group == previous + 1,
                "fixed SlotGroup numbers must be consecutive in declaration order"
            );
            previous = group;
        }
        return Ok(Some(base));
    }
    ensure!(
        !has_group_increment(&modular.slot_attributes)
            && modular
                .slots
                .iter()
                .all(|slot| slot.group.is_none() && !has_group_increment(&slot.attributes)),
        "group increments require explicit SlotGroup declarations for every slot"
    );
    Ok(None)
}

fn has_group_increment(attributes: &BTreeMap<String, String>) -> bool {
    attributes.keys().any(|name| name.starts_with("SlotGroup"))
}

fn increment(
    common: &BTreeMap<String, String>,
    slot: &modular::Slot,
    name: &str,
) -> Result<Option<u32>> {
    slot.attributes
        .get(name)
        .or_else(|| common.get(name))
        .map(|value| number(value).with_context(|| format!("invalid {name}")))
        .transpose()
}

fn resolve_pdo(
    pdo: Node<'_, '_>,
    pdo_offsets: IndexOffsets,
    entry_offsets: IndexOffsets,
    source: &EsiSource,
) -> Result<PdoPreview> {
    ensure!(
        !bool_attr(pdo, "Virtual")?
            && !bool_attr(pdo, "OverwrittenByModule")?
            && pdo
                .attributes()
                .all(|attribute| !attribute.name().starts_with("OS")),
        "virtual, replaced or oversampled PDO templates require separate interpretation"
    );
    let direction = if named(pdo, "TxPdo") {
        Direction::Tx
    } else {
        Direction::Rx
    };
    let index_node = unique_child(pdo, "Index")?.context("ESI module PDO Index missing")?;
    let mapping = resolve_index(index_node, pdo_offsets)?;
    let range = match direction {
        Direction::Rx => 0x1600..=0x17ff,
        Direction::Tx => 0x1a00..=0x1bff,
    };
    ensure!(
        range.contains(&mapping.declared) && range.contains(&mapping.resolved),
        "PDO index {:#06x} resolves to {:#06x} outside the {:?} mapping range",
        mapping.declared,
        mapping.resolved,
        direction
    );
    let excludes = pdo
        .children()
        .filter(|entry| named(*entry, "Exclude"))
        .map(|exclude| resolve_index(exclude, pdo_offsets))
        .collect::<Result<Vec<_>>>()?;
    let entries = pdo
        .children()
        .filter(|entry| named(*entry, "Entry"))
        .map(|entry| resolve_entry(entry, entry_offsets))
        .collect::<Result<Vec<_>>>()?;
    Ok(PdoPreview {
        direction,
        name: label(pdo, "Name").map(str::to_owned),
        declared_sm: default_sm(pdo)?,
        mandatory: bool_attr(pdo, "Mandatory")?,
        device_level_index_match: source.pdo_catalog.iter().any(|definition| {
            definition.direction == direction && definition.index == mapping.resolved
        }),
        mapping,
        entries,
        excludes,
        saved_readback: None,
    })
}

fn resolve_entry(entry: Node<'_, '_>, offsets: IndexOffsets) -> Result<Entry> {
    let object = resolve_index(
        unique_child(entry, "Index")?.context("ESI PDO entry Index missing")?,
        offsets,
    )?;
    let subindex = unique_child(entry, "SubIndex")?
        .map(|node| number(&dc_text(node)))
        .transpose()?
        .unwrap_or(0);
    let subindex = u8::try_from(subindex).context("ESI PDO entry SubIndex exceeds 255")?;
    let width =
        u8::try_from(node_number(entry, "BitLen")?).context("ESI PDO entry BitLen exceeds 255")?;
    ensure!(width > 0, "ESI PDO entry BitLen is zero");
    ensure!(
        object.declared != 0 || (subindex == 0 && object.resolved == 0),
        "invalid PDO padding entry"
    );
    Ok(Entry {
        object,
        subindex,
        width,
        name: label(entry, "Name").map(str::to_owned),
        data_type: child(entry, "DataType").map(|node| dc_text(node).trim().to_owned()),
    })
}

fn resolve_index(node: Node<'_, '_>, offsets: IndexOffsets) -> Result<Index> {
    let slot_dependent = bool_attr(node, "DependOnSlot")?;
    let group_dependent = bool_attr(node, "DependOnSlotGroup")?;
    ensure!(
        !(slot_dependent && group_dependent),
        "a single index declares both DependOnSlot and DependOnSlotGroup"
    );
    let offset = if group_dependent {
        Some(
            offsets
                .group
                .context("slot-group-dependent indexes require explicit SlotGroup declarations")?,
        )
    } else {
        slot_dependent.then_some(offsets.slot)
    };
    let declared = u16::try_from(number(&dc_text(node))?).context("ESI index exceeds 16 bits")?;
    let Some(Offset {
        position,
        increment,
        attribute,
    }) = offset
    else {
        return Ok(Index {
            declared,
            resolved: declared,
        });
    };
    ensure!(declared != 0, "PDO padding cannot depend on a slot");
    let resolved = if position == 0 {
        declared
    } else {
        let increment =
            increment.with_context(|| format!("missing {attribute} for a dependent index"))?;
        let offset = position
            .checked_mul(increment)
            .context("slot index offset overflow")?;
        let index = u32::from(declared)
            .checked_add(offset)
            .context("resolved slot index overflow")?;
        u16::try_from(index).context("resolved slot index exceeds 16 bits")?
    };
    Ok(Index { declared, resolved })
}

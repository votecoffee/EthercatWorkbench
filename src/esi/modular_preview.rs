//! Resolve PDO template indexes for explicit placements in fixed, ungrouped ESI slots.
mod decode;
mod readback;

use super::{
    bool_attr, child, dc_text, default_sm, label, modular, named, node_number, number, read_file,
    select_device, unique_child, with_description,
};
use crate::{
    model::{EsiSource, Identity},
    pdo_catalog::Direction,
};
use anyhow::{Context, Result, ensure};
use roxmltree::Node;
use serde::Serialize;
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

#[derive(Debug, Serialize)]
pub struct Preview {
    schema: u32,
    scope: &'static str,
    esi_file_name: String,
    esi_sha256: String,
    identity: Identity,
    slots: Vec<SlotPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    saved_readback: Option<readback::Comparison>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decoded_tx: Option<decode::DecodedPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decoded_rx: Option<decode::DecodedPayload>,
}

impl Preview {
    pub fn compare_saved_run(&mut self, path: &Path) -> Result<()> {
        self.saved_readback = Some(readback::compare(path, &self.identity, &mut self.slots)?);
        self.decoded_tx = None;
        self.decoded_rx = None;
        Ok(())
    }

    pub fn decode_saved_payload(&mut self, direction: Direction, bytes: &[u8]) -> Result<()> {
        let readback = self
            .saved_readback
            .as_ref()
            .context("payload decoding requires saved PDO readback")?;
        let decoded = decode::payload(direction, bytes, readback, &self.slots)?;
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
    pdos: Vec<PdoPreview>,
}

#[derive(Debug, Serialize)]
struct PdoPreview {
    direction: Direction,
    name: Option<String>,
    declared_sm: Option<u8>,
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

pub fn preview(
    path: &Path,
    device: Option<usize>,
    identity: Option<&Identity>,
    placements: &[Placement],
) -> Result<Preview> {
    let (file, bytes) = read_file(path)?;
    with_description(&file, &bytes, |descriptions, devices| {
        let selected = select_device(&devices, device, identity)?;
        preview_device(&selected.source, descriptions, placements)
    })
}

fn preview_device(
    source: &EsiSource,
    descriptions: Node<'_, '_>,
    placements: &[Placement],
) -> Result<Preview> {
    let modular = source
        .modular
        .as_ref()
        .context("selected ESI device has no slot declarations")?;
    ensure!(
        !modular.slots.is_empty()
            && modular
                .slots
                .iter()
                .all(|slot| { slot.min_instances == Some(1) && slot.max_instances == Some(1) }),
        "PDO index preview requires fixed slots with exactly one instance each"
    );
    ensure!(
        !has_group_increment(&modular.slot_attributes)
            && modular
                .additional_elements
                .iter()
                .all(|item| item == "SlotSelections")
            && modular
                .slots
                .iter()
                .all(|slot| slot.group.is_none() && !has_group_increment(&slot.attributes)),
        "PDO index preview requires ungrouped slots without PDO grouping"
    );
    let mut by_slot = BTreeMap::new();
    for selection in placements {
        ensure!(
            selection.slot < modular.slots.len(),
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
        by_slot.len() == modular.slots.len(),
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
    let mut seen = BTreeSet::new();
    let mut slots = Vec::with_capacity(by_slot.len());
    for (position, ident) in by_slot {
        let slot = &modular.slots[position];
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
        ensure!(
            ty.attribute("ModulePdoGroup").is_none(),
            "module {ident:#010x} uses PDO grouping"
        );
        let pdo_increment = increment(&modular.slot_attributes, slot, "SlotPdoIncrement")?;
        let index_increment = increment(&modular.slot_attributes, slot, "SlotIndexIncrement")?;
        let mut pdos = Vec::new();
        for pdo in modular::pdo_nodes(node) {
            let resolved = resolve_pdo(pdo, pdo_increment, index_increment, position, source)
                .with_context(|| {
                    format!("resolve PDO indexes for slot {position}, module {ident:#010x}")
                })?;
            ensure!(
                seen.insert(resolved.mapping.resolved),
                "resolved PDO index {:#06x} is used more than once among the chosen modules",
                resolved.mapping.resolved
            );
            pdos.push(resolved);
        }
        slots.push(SlotPreview {
            slot: position,
            name: slot.name.clone(),
            module_ident: ident,
            module_name: label(node, "Name")
                .or_else(|| ty.text())
                .unwrap_or("Unnamed module")
                .into(),
            slot_pdo_increment: pdo_increment,
            slot_index_increment: index_increment,
            pdos,
        });
    }
    Ok(Preview {
        schema: 1,
        scope: "offline_esi_module_pdo_candidates",
        esi_file_name: source.file_name.clone(),
        esi_sha256: source.sha256.clone(),
        identity: source.identity.clone(),
        slots,
        saved_readback: None,
        decoded_tx: None,
        decoded_rx: None,
    })
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
    pdo_increment: Option<u32>,
    index_increment: Option<u32>,
    position: usize,
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
    let mapping = resolve_index(index_node, pdo_increment, "SlotPdoIncrement", position)?;
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
        .map(|exclude| resolve_index(exclude, pdo_increment, "SlotPdoIncrement", position))
        .collect::<Result<Vec<_>>>()?;
    let entries = pdo
        .children()
        .filter(|entry| named(*entry, "Entry"))
        .map(|entry| resolve_entry(entry, index_increment, position))
        .collect::<Result<Vec<_>>>()?;
    Ok(PdoPreview {
        direction,
        name: label(pdo, "Name").map(str::to_owned),
        declared_sm: default_sm(pdo)?,
        device_level_index_match: source.pdo_catalog.iter().any(|definition| {
            definition.direction == direction && definition.index == mapping.resolved
        }),
        mapping,
        entries,
        excludes,
        saved_readback: None,
    })
}

fn resolve_entry(entry: Node<'_, '_>, increment: Option<u32>, position: usize) -> Result<Entry> {
    let object = resolve_index(
        unique_child(entry, "Index")?.context("ESI PDO entry Index missing")?,
        increment,
        "SlotIndexIncrement",
        position,
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

fn resolve_index(
    node: Node<'_, '_>,
    increment: Option<u32>,
    name: &str,
    position: usize,
) -> Result<Index> {
    ensure!(
        !bool_attr(node, "DependOnSlotGroup")?,
        "slot-group-dependent indexes require separate interpretation"
    );
    let declared = u16::try_from(number(&dc_text(node))?).context("ESI index exceeds 16 bits")?;
    let resolved = if bool_attr(node, "DependOnSlot")? {
        ensure!(declared != 0, "PDO padding cannot depend on a slot");
        if position == 0 {
            declared
        } else {
            let increment =
                increment.with_context(|| format!("missing {name} for a slot-dependent index"))?;
            let offset = (position as u32)
                .checked_mul(increment)
                .context("slot index offset overflow")?;
            let index = u32::from(declared)
                .checked_add(offset)
                .context("resolved slot index overflow")?;
            u16::try_from(index).context("resolved slot index exceeds 16 bits")?
        }
    } else {
        declared
    };
    Ok(Index { declared, resolved })
}

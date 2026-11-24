//! Decode supplied bytes with matched PDO descriptors and locations from a saved layout.
use super::{
    SlotPreview,
    readback::{Candidate, Comparison},
};
use crate::{
    model::{EsiSource, Field, Kind, Source},
    pdo_catalog::{Direction, esi_entry_kind},
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(super) struct DecodedPayload {
    payload_hex: String,
    image_bytes: usize,
    fields: Vec<Value>,
    withheld_pdos: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    withheld_device_pdos: Vec<u16>,
}

#[derive(Debug, Serialize)]
struct Value {
    #[serde(skip_serializing_if = "Option::is_none")]
    slot: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    module_ident: Option<u32>,
    sync_manager: u8,
    pdo_index: u16,
    object_index: u16,
    subindex: u8,
    name: Option<String>,
    data_type: Option<String>,
    bit: usize,
    width: usize,
    kind: Kind,
    value: Option<String>,
    unavailable: Option<String>,
}

pub(super) struct PositionedField<'a> {
    slot: Option<&'a SlotPreview>,
    pdo_index: u16,
    object_index: u16,
    subindex: u8,
    name: Option<&'a str>,
    data_type: Option<&'a str>,
    bit: usize,
    width: usize,
    sync_manager: u8,
}

impl PositionedField<'_> {
    pub(super) fn definition(&self, direction: Direction) -> Field {
        let kind = esi_entry_kind(self.data_type.unwrap_or_default(), self.width, self.bit);
        let label = self
            .name
            .unwrap_or("Entry")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let owner = self
            .slot
            .map_or_else(|| "Device".into(), |slot| format!("Slot {}", slot.slot));
        let name = format!(
            "{owner} {label} [{:04X}/{:04X}:{:02X} @{}]",
            self.pdo_index, self.object_index, self.subindex, self.bit
        );
        Field {
            name,
            bit: self.bit,
            width: self.width,
            kind,
            log: direction == Direction::Tx,
            source: Source::Esi,
            pdo_index: Some(self.pdo_index),
            object_index: Some(self.object_index),
            subindex: Some(self.subindex),
            ..Field::default()
        }
    }

    fn decode(&self, direction: Direction, bytes: &[u8]) -> Value {
        let field = self.definition(direction);
        let result = field.validate().and_then(|()| {
            field
                .decode(bytes)
                .context("entry is outside the supplied PDO image")
        });
        let (value, unavailable) = match result {
            Ok(value) => (Some(value), None),
            Err(error) => (None, Some(error.to_string())),
        };
        Value {
            slot: self.slot.map(|slot| slot.slot),
            module_ident: self.slot.map(|slot| slot.module_ident),
            sync_manager: self.sync_manager,
            pdo_index: self.pdo_index,
            object_index: self.object_index,
            subindex: self.subindex,
            name: self.name.map(str::to_owned),
            data_type: self.data_type.map(str::to_owned),
            bit: self.bit,
            width: field.width,
            kind: field.kind,
            value,
            unavailable,
        }
    }
}

pub(super) fn field_positions<'a>(
    direction: Direction,
    slots: &'a [SlotPreview],
    esi: &'a EsiSource,
    readback: &Comparison,
) -> (Vec<PositionedField<'a>>, Vec<u16>) {
    let mut fields = Vec::new();
    let mut withheld_pdos = Vec::new();
    for slot in slots {
        for pdo in slot.pdos.iter().filter(|pdo| pdo.direction == direction) {
            let location = pdo
                .saved_readback
                .as_ref()
                .and_then(Candidate::matched_location);
            let Some((mut bit, sync_manager)) = location else {
                if pdo.virtual_template
                    || pdo.entries.iter().any(|entry| entry.object.resolved != 0)
                {
                    withheld_pdos.push(pdo.mapping.resolved);
                }
                continue;
            };
            for entry in &pdo.entries {
                let width = usize::from(entry.width);
                if entry.object.resolved != 0 {
                    fields.push(PositionedField {
                        slot: Some(slot),
                        pdo_index: pdo.mapping.resolved,
                        object_index: entry.object.resolved,
                        subindex: entry.subindex,
                        name: entry.name.as_deref(),
                        data_type: entry.data_type.as_deref(),
                        bit,
                        width,
                        sync_manager,
                    });
                }
                bit += width;
            }
        }
    }
    for pdo in esi
        .pdo_catalog
        .iter()
        .filter(|pdo| pdo.direction == direction)
    {
        let location = readback
            .device_pdos(direction)
            .iter()
            .find(|assignment| assignment.pdo_index == pdo.index)
            .and_then(|assignment| assignment.matched_location());
        let Some((mut bit, sync_manager)) = location else {
            continue;
        };
        for entry in &pdo.entries {
            if entry.index != 0 {
                fields.push(PositionedField {
                    slot: None,
                    pdo_index: pdo.index,
                    object_index: entry.index,
                    subindex: entry.subindex,
                    name: Some(&entry.name),
                    data_type: Some(&entry.data_type),
                    bit,
                    width: entry.width,
                    sync_manager,
                });
            }
            bit += entry.width;
        }
    }
    fields.sort_by_key(|field| field.bit);
    (fields, withheld_pdos)
}

pub(super) fn payload(
    direction: Direction,
    bytes: &[u8],
    readback: &Comparison,
    slots: &[SlotPreview],
    esi: &EsiSource,
) -> Result<DecodedPayload> {
    let image_bytes = readback.image_bytes(direction)?;
    ensure!(
        bytes.len() == image_bytes,
        "saved {:?} PDO image requires {image_bytes} bytes, got {}",
        direction,
        bytes.len()
    );
    let (fields, withheld_pdos) = field_positions(direction, slots, esi, readback);
    Ok(DecodedPayload {
        payload_hex: hex::encode_upper(bytes),
        image_bytes,
        fields: fields
            .iter()
            .map(|field| field.decode(direction, bytes))
            .collect(),
        withheld_pdos,
        withheld_device_pdos: readback.withheld_device_pdos(direction),
    })
}

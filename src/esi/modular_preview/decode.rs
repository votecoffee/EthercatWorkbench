//! Decode supplied bytes with matched PDO descriptors and locations from a saved layout.
use super::{
    Entry, PdoPreview, SlotPreview,
    readback::{Candidate, Comparison},
};
use crate::{
    model::{Field, Kind, Source},
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
}

#[derive(Debug, Serialize)]
struct Value {
    slot: usize,
    module_ident: u32,
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
    slot: &'a SlotPreview,
    pdo: &'a PdoPreview,
    entry: &'a Entry,
    bit: usize,
    sync_manager: u8,
}

impl PositionedField<'_> {
    pub(super) fn definition(&self) -> Field {
        let width = usize::from(self.entry.width);
        let kind = esi_entry_kind(
            self.entry.data_type.as_deref().unwrap_or_default(),
            width,
            self.bit,
        );
        let label = self
            .entry
            .name
            .as_deref()
            .unwrap_or("Entry")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let name = format!(
            "Slot {} {} [{:04X}/{:04X}:{:02X} @{}]",
            self.slot.slot,
            label,
            self.pdo.mapping.resolved,
            self.entry.object.resolved,
            self.entry.subindex,
            self.bit
        );
        Field {
            name,
            bit: self.bit,
            width,
            kind,
            log: self.pdo.direction == Direction::Tx,
            source: Source::Esi,
            pdo_index: Some(self.pdo.mapping.resolved),
            object_index: Some(self.entry.object.resolved),
            subindex: Some(self.entry.subindex),
            ..Field::default()
        }
    }

    fn decode(&self, bytes: &[u8]) -> Value {
        let field = self.definition();
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
            slot: self.slot.slot,
            module_ident: self.slot.module_ident,
            sync_manager: self.sync_manager,
            pdo_index: self.pdo.mapping.resolved,
            object_index: self.entry.object.resolved,
            subindex: self.entry.subindex,
            name: self.entry.name.clone(),
            data_type: self.entry.data_type.clone(),
            bit: self.bit,
            width: field.width,
            kind: field.kind,
            value,
            unavailable,
        }
    }
}

pub(super) fn field_positions(
    direction: Direction,
    slots: &[SlotPreview],
) -> (Vec<PositionedField<'_>>, Vec<u16>) {
    let mut fields = Vec::new();
    let mut withheld_pdos = Vec::new();
    for slot in slots {
        for pdo in slot.pdos.iter().filter(|pdo| pdo.direction == direction) {
            let location = pdo
                .saved_readback
                .as_ref()
                .and_then(Candidate::matched_location);
            let Some((mut bit, sync_manager)) = location else {
                if pdo.entries.iter().any(|entry| entry.object.resolved != 0) {
                    withheld_pdos.push(pdo.mapping.resolved);
                }
                continue;
            };
            for entry in &pdo.entries {
                if entry.object.resolved != 0 {
                    fields.push(PositionedField {
                        slot,
                        pdo,
                        entry,
                        bit,
                        sync_manager,
                    });
                }
                bit += usize::from(entry.width);
            }
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
) -> Result<DecodedPayload> {
    let image_bytes = readback.image_bytes(direction)?;
    ensure!(
        bytes.len() == image_bytes,
        "saved {:?} PDO image requires {image_bytes} bytes, got {}",
        direction,
        bytes.len()
    );
    let (fields, withheld_pdos) = field_positions(direction, slots);
    Ok(DecodedPayload {
        payload_hex: hex::encode_upper(bytes),
        image_bytes,
        fields: fields.iter().map(|field| field.decode(bytes)).collect(),
        withheld_pdos,
    })
}

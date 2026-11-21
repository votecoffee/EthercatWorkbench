//! Decode supplied bytes with matched PDO descriptors and locations from a saved layout.
use super::{
    Entry, PdoPreview, SlotPreview,
    readback::{Candidate, Comparison},
};
use crate::{
    model::{Field, Kind},
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
                    fields.push(decode_entry(slot, pdo, entry, bit, sync_manager, bytes));
                }
                bit += usize::from(entry.width);
            }
        }
    }
    fields.sort_by_key(|field| field.bit);
    Ok(DecodedPayload {
        payload_hex: hex::encode_upper(bytes),
        image_bytes,
        fields,
        withheld_pdos,
    })
}

fn decode_entry(
    slot: &SlotPreview,
    pdo: &PdoPreview,
    entry: &Entry,
    bit: usize,
    sync_manager: u8,
    bytes: &[u8],
) -> Value {
    let width = usize::from(entry.width);
    let kind = esi_entry_kind(entry.data_type.as_deref().unwrap_or_default(), width, bit);
    let field = Field {
        name: format!(
            "Object {:#06x}:{:02x}",
            entry.object.resolved, entry.subindex
        ),
        bit,
        width,
        kind,
        ..Field::default()
    };
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
        slot: slot.slot,
        module_ident: slot.module_ident,
        sync_manager,
        pdo_index: pdo.mapping.resolved,
        object_index: entry.object.resolved,
        subindex: entry.subindex,
        name: entry.name.clone(),
        data_type: entry.data_type.clone(),
        bit,
        width,
        kind,
        value,
        unavailable,
    }
}

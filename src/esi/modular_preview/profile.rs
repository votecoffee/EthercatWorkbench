//! Build standard offline profiles from ESI labels and matched saved PDO positions.
use super::{
    SlotCount, SlotPreview, decode::field_positions, readback::Comparison, slot_positions,
};
use crate::{
    model::{EsiSource, Field, Profile},
    pdo::MappingSource,
    pdo_catalog::Direction,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub report_file_name: String,
    pub report_sha256: String,
    pub reported_backend: String,
    pub slots: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub slot_counts: Vec<SlotCount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_inventory: Option<super::inventory::Comparison>,
    pub tx: ImageSource,
    pub rx: ImageSource,
}

impl Provenance {
    pub(crate) fn validate_slot_counts(&self, esi: &EsiSource) -> Result<()> {
        if !self.slot_counts.is_empty() {
            let modular = esi
                .modular
                .as_ref()
                .context("saved slot counts require ESI slot declarations")?;
            let positions = slot_positions(modular, &self.slot_counts)?;
            ensure!(
                positions.len() == self.slots.len(),
                "saved slot counts expand to {} positions, but the decoder has {}",
                positions.len(),
                self.slots.len()
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageSource {
    pub image_bytes: usize,
    pub mapping_source: Option<MappingSource>,
    pub withheld_pdos: Vec<u16>,
    pub unavailable_fields: Vec<UnavailableField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_pdos: Vec<DevicePdoMember>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withheld_device_pdos: Vec<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_pdo_groups: Option<PdoGroupAudit>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdoGroupAudit {
    pub group_order: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_pdos: Vec<DevicePdoMember>,
    pub padding: Vec<PdoGroupPadding>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePdoMember {
    pub pdo_index: u16,
    pub sync_manager: u8,
    pub bit: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdoGroupPadding {
    pub group: usize,
    pub pdo_index: u16,
    pub alignment_bytes: Option<u32>,
    pub assigned: bool,
    pub bit: Option<usize>,
    pub width_bits: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnavailableField {
    pub name: String,
    pub reason: String,
}

pub(super) fn build(
    mut esi: EsiSource,
    readback: &Comparison,
    slots: &[SlotPreview],
    slot_counts: Vec<SlotCount>,
    module_inventory: Option<super::inventory::Comparison>,
) -> Result<Profile> {
    readback.require_group_agreement()?;
    let (tx_source, tx) = image(Direction::Tx, readback, slots, &esi)?;
    let (rx_source, rx) = image(Direction::Rx, readback, slots, &esi)?;
    ensure!(
        !tx.is_empty() || !rx.is_empty(),
        "saved PDO layouts have no decodable device or module fields"
    );
    esi.default_tx_bytes = None;
    esi.default_rx_bytes = None;
    esi.pdo_catalog.clear();
    esi.dc_modes.clear();
    esi.notes.clear();

    let profile = Profile {
        name: format!("{} · Modular offline decoder", esi.device),
        expected_identity: Some(esi.identity.clone()),
        esi: Some(esi),
        tx_bytes: tx_source.image_bytes,
        rx_bytes: rx_source.image_bytes,
        tx,
        rx,
        modular_decoder: Some(Provenance {
            report_file_name: readback.file_name.clone(),
            report_sha256: readback.sha256.clone(),
            reported_backend: readback.reported_backend.clone(),
            slots: slots.iter().map(|slot| slot.module_ident).collect(),
            slot_counts,
            module_inventory,
            tx: tx_source,
            rx: rx_source,
        }),
        ..Profile::default()
    };
    profile.validate()?;
    Ok(profile)
}

fn image(
    direction: Direction,
    readback: &Comparison,
    slots: &[SlotPreview],
    esi: &EsiSource,
) -> Result<(ImageSource, Vec<Field>)> {
    let image_bytes = readback.image_bytes(direction)?;
    let (positions, withheld_pdos) = field_positions(direction, slots, esi, readback);
    let mut fields = Vec::new();
    let mut unavailable_fields = Vec::new();
    for position in positions {
        let field = position.definition(direction);
        match field.validate() {
            Ok(()) => fields.push(field),
            Err(error) => unavailable_fields.push(UnavailableField {
                name: field.name,
                reason: error.to_string(),
            }),
        }
    }
    Ok((
        ImageSource {
            image_bytes,
            mapping_source: readback.mapping_source(direction),
            withheld_pdos,
            unavailable_fields,
            device_pdos: readback
                .device_pdos(direction)
                .iter()
                .filter_map(|pdo| {
                    let (bit, sync_manager) = pdo.matched_location()?;
                    Some(DevicePdoMember {
                        pdo_index: pdo.pdo_index,
                        sync_manager,
                        bit,
                    })
                })
                .collect(),
            withheld_device_pdos: readback.withheld_device_pdos(direction),
            module_pdo_groups: readback.module_pdo_groups(direction).cloned(),
        },
        fields,
    ))
}

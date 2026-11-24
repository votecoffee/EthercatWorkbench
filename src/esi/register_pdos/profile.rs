//! Export reconstructed register bytes for the ordinary offline decoder.
use super::{Review, Sample};
use crate::{
    model::{Field, Kind, MAX_PAYLOAD, Profile, Source, payload_hex},
    pdo::inspect::profile::scalar_kind,
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdo_index: Option<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pdos: Vec<PdoSource>,
    pub station_address: u16,
    pub packed_bits: usize,
    pub packed_hex: String,
    pub reply_file_name: String,
    pub reply_sha256: String,
    pub fmmu_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_start_bit: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_layout_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withheld_bits: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdoSource {
    pub pdo_index: u16,
    pub bit_offset: usize,
    pub width_bits: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_start_bit: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_layout_sha256: Option<String>,
}

fn validate_manual_source(bit: Option<u8>, sha256: Option<&str>) -> Result<()> {
    ensure!(
        bit.is_none_or(|value| value < 8 && sha256.is_none()),
        "register decoder has invalid manual bit provenance"
    );
    if let Some(digest) = sha256 {
        validate_digest(digest)?;
    }
    Ok(())
}

fn validate_digest(digest: &str) -> Result<()> {
    ensure!(
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "register decoder has an invalid SHA-256 digest"
    );
    Ok(())
}

fn validate_unused_bits(data: &[u8], width: usize) -> Result<()> {
    let used = width % 8;
    ensure!(
        used == 0 || data.last().is_some_and(|last| last >> used == 0),
        "saved register payload has nonzero unused bits"
    );
    Ok(())
}

impl Provenance {
    pub(crate) fn validate(&self, profile: &Profile) -> Result<()> {
        let esi = profile
            .esi
            .as_ref()
            .context("register decoder requires ESI provenance")?;
        ensure!(
            profile.expected_identity.as_ref() == Some(&esi.identity),
            "register decoder requires the exact ESI identity"
        );
        ensure!(
            profile.modular_decoder.is_none()
                && profile.observed_decoder.is_none()
                && profile.esi_pdo_selection.is_none(),
            "register decoder cannot be combined with another PDO profile source"
        );
        ensure!(
            profile.rx_bytes == 0
                && profile.rx.is_empty()
                && profile.tx_bytes == self.packed_bits.div_ceil(8)
                && (1..=MAX_PAYLOAD * 8).contains(&self.packed_bits),
            "register decoder image lengths differ from its packed projection"
        );
        ensure!(
            self.packed_hex.len() == profile.tx_bytes * 2,
            "saved register payload has an invalid packed length"
        );
        let data = payload_hex(&self.packed_hex)?;
        ensure!(
            data.len() == profile.tx_bytes,
            "saved register payload has an invalid packed length"
        );
        for digest in [&esi.sha256, &self.reply_sha256, &self.fmmu_sha256] {
            validate_digest(digest)?;
        }
        ensure!(
            self.station_address != 0 && !self.reply_file_name.trim().is_empty(),
            "register decoder needs a saved reply file and station address"
        );
        if self.pdos.is_empty() {
            ensure!(
                self.pdo_index.is_some(),
                "register decoder needs a PDO index"
            );
            validate_manual_source(self.manual_start_bit, self.manual_layout_sha256.as_deref())?;
            validate_unused_bits(&data, self.packed_bits)?;
            ensure!(
                profile.tx.iter().all(|field| field
                    .bit
                    .checked_add(field.width)
                    .is_some_and(|end| end <= self.packed_bits)),
                "register decoder field extends beyond the packed projection"
            );
        } else {
            self.validate_pdos(profile, &data)?;
        }
        Ok(())
    }

    fn validate_pdos(&self, profile: &Profile, data: &[u8]) -> Result<()> {
        ensure!(
            self.pdos.len() >= 2
                && self.pdo_index.is_none()
                && self.manual_start_bit.is_none()
                && self.manual_layout_sha256.is_none(),
            "register decoder must use one PDO index or an ordered set of PDO sources"
        );
        let mut indexes = HashSet::new();
        let mut next_byte = 0;
        let mut packed_end = 0;
        for pdo in &self.pdos {
            ensure!(
                indexes.insert(pdo.pdo_index),
                "duplicate register decoder PDO {:#06x}",
                pdo.pdo_index
            );
            ensure!(
                pdo.bit_offset == next_byte * 8 && (1..=MAX_PAYLOAD * 8).contains(&pdo.width_bits),
                "invalid packed range for register decoder PDO {:#06x}",
                pdo.pdo_index
            );
            validate_manual_source(pdo.manual_start_bit, pdo.manual_layout_sha256.as_deref())?;
            packed_end = pdo.bit_offset + pdo.width_bits;
            let end = packed_end.div_ceil(8);
            let block = data
                .get(next_byte..end)
                .context("register decoder PDO exceeds the packed payload")?;
            validate_unused_bits(block, pdo.width_bits)?;
            next_byte = end;
        }
        ensure!(
            packed_end == self.packed_bits && next_byte == data.len(),
            "register decoder PDO ranges do not cover the packed payload"
        );
        for field in &profile.tx {
            ensure!(
                self.pdos.iter().any(|pdo| field.bit >= pdo.bit_offset
                    && field
                        .bit
                        .checked_add(field.width)
                        .is_some_and(|end| end <= pdo.bit_offset + pdo.width_bits)
                    && field.pdo_index.is_none_or(|index| index == pdo.pdo_index)),
                "register decoder field {} extends beyond its PDO's packed range",
                field.name
            );
        }
        Ok(())
    }
}

impl Review {
    pub fn offline_profile(&self, pdo_index: u16) -> Result<Profile> {
        self.offline_profile_for_pdos(&[pdo_index])
    }

    pub fn offline_profile_for_pdos(&self, pdo_indexes: &[u16]) -> Result<Profile> {
        let (file, sha256, station_address) = self
            .logical_payload
            .as_ref()
            .and_then(super::payload::Evidence::verified_reply)
            .context("register decoder export requires a fully verified schema 4 LRD reply")?;
        ensure!(!pdo_indexes.is_empty(), "select at least one register PDO");
        let multiple = pdo_indexes.len() > 1;
        let mut indexes = HashSet::new();
        let mut tx = Vec::new();
        let mut withheld_bits = Vec::new();
        let mut packed = Vec::new();
        let mut pdos = Vec::new();
        for &pdo_index in pdo_indexes {
            ensure!(
                indexes.insert(pdo_index),
                "duplicate decoder PDO {pdo_index:#06x}"
            );
            let projection = self
                .projections
                .iter()
                .find(|projection| projection.pdo_index == pdo_index)
                .with_context(|| format!("no register projection for PDO {pdo_index:#06x}"))?;
            pdos.push(self.append_projection(
                projection,
                multiple,
                &mut packed,
                &mut tx,
                &mut withheld_bits,
            )?);
        }
        ensure!(
            !tx.is_empty(),
            "register projection has no supported decoder fields"
        );
        let last = pdos.last().context("register decoder has no PDO source")?;
        let packed_bits = last.bit_offset + last.width_bits;
        let single = (!multiple).then_some(last);
        let mut esi = self.esi_source.clone();
        esi.default_tx_bytes = None;
        esi.default_rx_bytes = None;
        esi.pdo_catalog.clear();
        esi.dc_modes.clear();
        esi.notes.clear();
        let profile = Profile {
            name: match single {
                Some(pdo) => format!("{} · Register PDO {:#06x}", esi.device, pdo.pdo_index),
                None => format!("{} · Register PDO decoder", esi.device),
            },
            expected_identity: Some(self.identity.clone()),
            esi: Some(esi),
            tx_bytes: packed.len(),
            tx,
            register_decoder: Some(Provenance {
                pdo_index: single.map(|pdo| pdo.pdo_index),
                station_address,
                packed_bits,
                packed_hex: hex::encode_upper(packed),
                reply_file_name: file.into(),
                reply_sha256: sha256.into(),
                fmmu_sha256: self
                    .fmmu
                    .as_ref()
                    .context("register decoder requires FMMU evidence")?
                    .sha256
                    .clone(),
                manual_start_bit: single.and_then(|pdo| pdo.manual_start_bit),
                manual_layout_sha256: single.and_then(|pdo| pdo.manual_layout_sha256.clone()),
                pdos: if multiple { pdos } else { Vec::new() },
                withheld_bits,
            }),
            ..Profile::default()
        };
        profile.validate()?;
        Ok(profile)
    }

    fn append_projection(
        &self,
        projection: &super::Projection,
        multiple: bool,
        packed: &mut Vec<u8>,
        tx: &mut Vec<Field>,
        withheld_bits: &mut Vec<usize>,
    ) -> Result<PdoSource> {
        let pdo_index = projection.pdo_index;
        let packed_hex = match &projection.logical_sample {
            Some(Sample::Available { raw_hex }) => raw_hex,
            Some(Sample::Unavailable { reason }) => {
                bail!("register projection for PDO {pdo_index:#06x} is unavailable ({reason})")
            }
            None => bail!("register projection has no saved logical sample"),
        };
        let bytes = payload_hex(packed_hex)?;
        ensure!(
            packed.len() + bytes.len() <= MAX_PAYLOAD,
            "register decoder packed payload exceeds {MAX_PAYLOAD} bytes"
        );
        let start = packed.len() * 8;
        let mut bit = start;
        for entry in &projection.entries {
            let offset = bit;
            bit += entry.width_bits;
            if entry.padding.is_some() {
                continue;
            }
            let data_type = entry.data_type.to_ascii_uppercase();
            let kind = scalar_kind(&data_type, entry.width_bits).or_else(|| {
                let width = data_type.strip_prefix("BIT")?.parse::<usize>().ok()?;
                (width == entry.width_bits && (2..=64).contains(&width)).then_some(Kind::Unsigned)
            });
            let Some(kind) = kind else {
                withheld_bits.push(offset);
                continue;
            };
            let name = entry.name.trim();
            let name = if projection
                .entries
                .iter()
                .filter(|entry| entry.name.trim() == name)
                .count()
                > 1
            {
                format!("{name} · bit {offset}")
            } else {
                name.into()
            };
            let field = Field {
                name: if multiple {
                    format!("{pdo_index:#06x} · {name}")
                } else {
                    name
                },
                bit: offset,
                width: entry.width_bits,
                kind,
                log: false,
                source: Source::Esi,
                pdo_index: Some(pdo_index),
                object_index: Some(entry.declared_index),
                subindex: Some(entry.declared_subindex),
                ..Field::default()
            };
            if field.validate().is_ok() {
                tx.push(field);
            } else {
                withheld_bits.push(offset);
            }
        }
        let width_bits = bit - start;
        ensure!(
            width_bits.div_ceil(8) == bytes.len(),
            "register sample length differs from PDO {pdo_index:#06x} geometry"
        );
        packed.extend(bytes);
        Ok(PdoSource {
            pdo_index,
            bit_offset: start,
            width_bits,
            manual_start_bit: projection.manual_start_bit,
            manual_layout_sha256: self
                .manual_register_layout
                .as_ref()
                .filter(|_| {
                    projection
                        .entries
                        .iter()
                        .any(|entry| entry.physical_start_bit.is_some())
                })
                .map(|layout| layout.sha256.clone()),
        })
    }
}

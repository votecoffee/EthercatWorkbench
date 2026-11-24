//! Export reconstructed register bytes for the ordinary offline decoder.
use super::{Review, Sample};
use crate::{
    model::{Field, Kind, MAX_PAYLOAD, Profile, Source, payload_hex},
    pdo::inspect::profile::scalar_kind,
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub pdo_index: u16,
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
        let used = self.packed_bits % 8;
        ensure!(
            used == 0 || data.last().is_some_and(|last| last >> used == 0),
            "saved register payload has nonzero unused bits"
        );
        ensure!(
            profile.tx.iter().all(|field| field
                .bit
                .checked_add(field.width)
                .is_some_and(|end| end <= self.packed_bits)),
            "register decoder field extends beyond the packed projection"
        );
        for digest in [
            Some(esi.sha256.as_str()),
            Some(&self.reply_sha256),
            Some(&self.fmmu_sha256),
            self.manual_layout_sha256.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            ensure!(
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "register decoder has an invalid SHA-256 digest"
            );
        }
        ensure!(
            self.station_address != 0 && !self.reply_file_name.trim().is_empty(),
            "register decoder needs a saved reply file and station address"
        );
        ensure!(
            self.manual_start_bit
                .is_none_or(|bit| bit < 8 && self.manual_layout_sha256.is_none()),
            "register decoder has invalid manual bit provenance"
        );
        Ok(())
    }
}

impl Review {
    pub fn offline_profile(&self, pdo_index: u16) -> Result<Profile> {
        let (file, sha256, station_address) = self
            .logical_payload
            .as_ref()
            .and_then(super::payload::Evidence::verified_reply)
            .context("register decoder export requires a fully verified schema 4 LRD reply")?;
        let projection = self
            .projections
            .iter()
            .find(|projection| projection.pdo_index == pdo_index)
            .with_context(|| format!("no register projection for PDO {pdo_index:#06x}"))?;
        let packed_hex = match &projection.logical_sample {
            Some(Sample::Available { raw_hex }) => raw_hex,
            Some(Sample::Unavailable { reason }) => {
                bail!("register projection is unavailable ({reason})")
            }
            None => bail!("register projection has no saved logical sample"),
        };
        let mut bit = 0;
        let mut tx = Vec::new();
        let mut withheld_bits = Vec::new();
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
                name,
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
        ensure!(
            !tx.is_empty(),
            "register projection has no supported decoder fields"
        );
        let mut esi = self.esi_source.clone();
        esi.default_tx_bytes = None;
        esi.default_rx_bytes = None;
        esi.pdo_catalog.clear();
        esi.dc_modes.clear();
        esi.notes.clear();
        let profile = Profile {
            name: format!("{} · Register PDO {pdo_index:#06x}", esi.device),
            expected_identity: Some(self.identity.clone()),
            esi: Some(esi),
            tx_bytes: bit.div_ceil(8),
            tx,
            register_decoder: Some(Provenance {
                pdo_index,
                station_address,
                packed_bits: bit,
                packed_hex: packed_hex.clone(),
                reply_file_name: file.into(),
                reply_sha256: sha256.into(),
                fmmu_sha256: self
                    .fmmu
                    .as_ref()
                    .context("register decoder requires FMMU evidence")?
                    .sha256
                    .clone(),
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
                withheld_bits,
            }),
            ..Profile::default()
        };
        profile.validate()?;
        Ok(profile)
    }
}

use crate::model::{Field, MAX_PAYLOAD, Profile};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// CoE assignments in ascending SyncManager order, with entries in device order.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layout {
    pub sync_managers: Vec<SyncManager>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncManager {
    pub index: u8,
    #[serde(default)]
    pub configured_bytes: Option<usize>,
    pub pdos: Vec<Pdo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pdo {
    pub index: u16,
    /// CoE mapping values, object index in bits 31..16, subindex in 15..8, width in 7..0.
    pub entries: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Entry {
    pub sync_manager: u8,
    pub pdo_index: u16,
    pub object_index: u16,
    pub subindex: u8,
    pub bit: usize,
    pub width: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Readback {
    pub tx: Option<Layout>,
    pub rx: Option<Layout>,
    #[serde(default)]
    pub tx_unavailable: Option<String>,
    #[serde(default)]
    pub rx_unavailable: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldState {
    Matched,
    Manual,
    Unavailable,
    Mismatch,
}

#[derive(Clone, Debug, Serialize)]
pub struct FieldCheck {
    pub name: String,
    pub state: FieldState,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DirectionCheck {
    pub image_bytes: Option<usize>,
    pub entries: Vec<Entry>,
    pub fields: Vec<FieldCheck>,
    pub errors: Vec<String>,
    pub unavailable: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Verification {
    pub source: String,
    pub readback: Readback,
    pub tx: DirectionCheck,
    pub rx: DirectionCheck,
}

impl Layout {
    pub fn entries(&self) -> Result<(Vec<Entry>, usize)> {
        ensure!(self.sync_managers.len() <= 16, "too many SyncManagers");
        let mut previous = None;
        let mut bit = 0usize;
        let mut entries = Vec::new();
        for sm in &self.sync_managers {
            ensure!(
                sm.index < 16 && previous.is_none_or(|previous| previous < sm.index),
                "SyncManagers must have unique ascending indexes below 16"
            );
            previous = Some(sm.index);
            ensure!(sm.pdos.len() <= 255, "too many PDO assignments");
            let start_bit = bit;
            let mut pdos = HashSet::new();
            for pdo in &sm.pdos {
                ensure!(
                    (0x1600..=0x1bff).contains(&pdo.index) && pdos.insert(pdo.index),
                    "invalid or repeated PDO {:#06x} in SM{}",
                    pdo.index,
                    sm.index
                );
                ensure!(pdo.entries.len() <= 255, "too many PDO entries");
                for value in &pdo.entries {
                    let width = (*value & 0xff) as usize;
                    ensure!(width > 0, "zero-width PDO mapping in {:#06x}", pdo.index);
                    let object_index = (value >> 16) as u16;
                    let subindex = (value >> 8) as u8;
                    ensure!(
                        object_index != 0 || subindex == 0,
                        "invalid PDO padding descriptor"
                    );
                    entries.push(Entry {
                        sync_manager: sm.index,
                        pdo_index: pdo.index,
                        object_index,
                        subindex,
                        bit,
                        width,
                    });
                    bit = bit.checked_add(width).context("PDO bit offset overflow")?;
                    ensure!(
                        bit <= MAX_PAYLOAD * 8,
                        "PDO readback exceeds {MAX_PAYLOAD} bytes"
                    );
                }
            }
            bit = bit.div_ceil(8) * 8;
            if let Some(configured) = sm.configured_bytes {
                ensure!(
                    (bit - start_bit) / 8 == configured,
                    "SM{} register length {configured} differs from its CoE mapping length {}",
                    sm.index,
                    (bit - start_bit) / 8
                );
            }
        }
        Ok((entries, bit / 8))
    }
}

impl Readback {
    pub fn verify(self, profile: &Profile, source: &str) -> Verification {
        let tx = compare(
            self.tx.as_ref(),
            self.tx_unavailable.as_deref(),
            profile.tx_bytes,
            &profile.tx,
        );
        let rx = compare(
            self.rx.as_ref(),
            self.rx_unavailable.as_deref(),
            profile.rx_bytes,
            &profile.rx,
        );
        Verification {
            source: source.into(),
            readback: self,
            tx,
            rx,
        }
    }
}

impl Verification {
    pub fn compatible(&self) -> bool {
        self.tx.errors.is_empty() && self.rx.errors.is_empty()
    }

    pub fn matched_fields(&self) -> usize {
        self.tx
            .fields
            .iter()
            .chain(&self.rx.fields)
            .filter(|f| matches!(f.state, FieldState::Matched))
            .count()
    }
}

fn compare(
    layout: Option<&Layout>,
    unavailable: Option<&str>,
    bytes: usize,
    fields: &[Field],
) -> DirectionCheck {
    let parsed = layout.map(Layout::entries).transpose();
    let (entries, image_bytes, mut errors) = match parsed {
        Ok(Some((entries, len))) => (entries, Some(len), Vec::new()),
        Ok(None) => (Vec::new(), None, Vec::new()),
        Err(error) => (Vec::new(), None, vec![format!("{error:#}")]),
    };
    if let Some(observed) = image_bytes
        && observed != bytes
    {
        errors.push(format!(
            "device mapping spans {observed} bytes, profile expects {bytes}"
        ));
    }
    let unavailable = (layout.is_none() && bytes != 0).then(|| {
        unavailable
            .unwrap_or("CoE PDO mapping readback unavailable")
            .to_owned()
    });
    let checked = fields.iter().map(|field| {
        let (state, detail) = match (field.pdo_index, field.object_index, field.subindex) {
            (Some(pdo), Some(object), Some(sub)) if image_bytes.is_some() => {
                let found = entries.iter().find(|entry| entry.pdo_index == pdo
                    && entry.object_index == object && entry.subindex == sub
                    && entry.bit == field.bit && entry.width == field.width);
                if let Some(entry) = found {
                    (FieldState::Matched, format!("CoE SM{} {pdo:#06x}/{object:#06x}:{sub:02x}, bit {} width {}",
                        entry.sync_manager, entry.bit, entry.width))
                } else {
                    let detail = format!("{}: no device entry for {pdo:#06x}/{object:#06x}:{sub:02x} at bit {} width {}",
                        field.name, field.bit, field.width);
                    errors.push(detail.clone());
                    (FieldState::Mismatch, detail)
                }
            }
            (Some(_), Some(_), Some(_)) => (FieldState::Unavailable, "device entry order has not been verified".into()),
            (None, None, None) => (FieldState::Manual, "manual bit/byte interpretation".into()),
            _ => {
                let detail = format!("{}: PDO, object and subindex must be supplied together", field.name);
                errors.push(detail.clone());
                (FieldState::Mismatch, detail)
            }
        };
        FieldCheck { name: field.name.clone(), state, detail }
    }).collect();
    DirectionCheck {
        image_bytes,
        entries,
        fields: checked,
        errors,
        unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{esi, model::Source};

    fn fixture() -> (Profile, Readback) {
        let devices = esi::parse(
            "synthetic.esi.xml",
            include_bytes!("../samples/synthetic.esi.xml"),
        )
        .unwrap();
        let mut profile = Profile::default();
        devices[0].apply(&mut profile);
        let readback = serde_json::from_str(include_str!("../samples/synthetic-pdo.json")).unwrap();
        (profile, readback)
    }

    #[test]
    fn checks_order_padding_and_manual_interpretation() {
        let (mut profile, readback) = fixture();
        let verified = readback.clone().verify(&profile, "fixture");
        assert!(verified.compatible());
        assert_eq!(verified.matched_fields(), 4);
        assert_eq!(verified.tx.entries[2].object_index, 0);
        profile.tx[0].source = Source::Override;
        profile.tx[0].bit = 16;
        assert!(!readback.clone().verify(&profile, "fixture").compatible());
        profile.tx[0] = Field {
            width: 8,
            ..Field::default()
        };
        let verified = readback.verify(&profile, "fixture");
        assert!(verified.compatible());
        assert!(matches!(verified.tx.fields[0].state, FieldState::Manual));
    }

    #[test]
    fn pads_each_sync_manager_and_rejects_invalid_or_partial_data() {
        let layout = Layout {
            sync_managers: vec![
                SyncManager {
                    index: 3,
                    configured_bytes: None,
                    pdos: vec![Pdo {
                        index: 0x1a00,
                        entries: vec![0x60000101],
                    }],
                },
                SyncManager {
                    index: 4,
                    configured_bytes: None,
                    pdos: vec![Pdo {
                        index: 0x1a01,
                        entries: vec![0x60010110],
                    }],
                },
            ],
        };
        let (entries, bytes) = layout.entries().unwrap();
        assert_eq!((entries[1].bit, bytes), (8, 3));
        let (profile, mut readback) = fixture();
        readback.tx.as_mut().unwrap().sync_managers[0].pdos[0]
            .entries
            .swap(0, 3);
        assert!(!readback.verify(&profile, "fixture").compatible());
        let (_, mut readback) = fixture();
        readback.tx = None;
        let check = readback.verify(&profile, "fixture");
        assert!(check.compatible());
        assert!(matches!(check.tx.fields[0].state, FieldState::Unavailable));
        let mut malformed = layout;
        malformed.sync_managers[0].pdos[0].entries[0] = 0x60000100;
        assert!(malformed.entries().is_err());
    }
}

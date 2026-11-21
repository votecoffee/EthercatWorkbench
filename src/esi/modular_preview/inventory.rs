//! Read fixed-slot module identity evidence from saved CoE object values.
use super::{Placement, SlotPreview};
use crate::{benchmark::read_report_bytes_with_stop, model::Identity};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

pub(crate) const CONFIGURED: u16 = 0xf030;
pub(crate) const DETECTED: u16 = 0xf050;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub(crate) schema: u32,
    pub(crate) identity: Identity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) serial: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) source: Option<Source>,
    pub(crate) objects: Vec<Object>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    VirtualCoe,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Object {
    pub(crate) index: u16,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) uploads: Vec<Upload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) unavailable: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Upload {
    pub(crate) subindex: u8,
    pub(crate) data_hex: String,
}

enum List {
    Available(Vec<u32>),
    Unavailable(String),
}

pub(super) struct Inventory {
    file_name: String,
    sha256: String,
    serial: Option<u32>,
    source: Option<Source>,
    configured: Option<List>,
    detected: Option<List>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Comparison {
    pub file_name: String,
    pub sha256: String,
    pub reported_serial: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    pub placement_source: PlacementSource,
    pub configured: ListComparison,
    pub detected: ListComparison,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementSource {
    Manual,
    SavedDetected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListComparison {
    pub index: u16,
    pub state: State,
    pub reported_count: Option<usize>,
    pub differences: Vec<SlotDifference>,
    pub unavailable: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Matched,
    Mismatch,
    Unavailable,
}

impl State {
    pub fn label(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::Mismatch => "differs",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotDifference {
    pub slot: usize,
    pub expected: Option<u32>,
    pub reported: Option<u32>,
}

impl Inventory {
    pub(super) fn load(path: &Path, identity: &Identity) -> Result<Self> {
        let bytes = read_report_bytes_with_stop(path, None)?;
        let snapshot: Snapshot =
            serde_json::from_slice(&bytes).context("parse saved module inventory")?;
        ensure!(
            snapshot.schema == 1,
            "unsupported module inventory schema {}",
            snapshot.schema
        );
        ensure!(
            &snapshot.identity == identity,
            "saved module inventory identity differs from the ESI selection"
        );
        let mut inventory = Self {
            file_name: path
                .file_name()
                .context("saved module inventory path has no file name")?
                .to_string_lossy()
                .into_owned(),
            sha256: hex::encode(Sha256::digest(&bytes)),
            serial: snapshot.serial,
            source: snapshot.source,
            configured: None,
            detected: None,
        };
        for object in snapshot.objects {
            let index = object.index;
            let list = match index {
                CONFIGURED => &mut inventory.configured,
                DETECTED => &mut inventory.detected,
                _ => bail!("unsupported module inventory object {index:#06x}"),
            };
            ensure!(
                list.is_none(),
                "duplicate module inventory object {index:#06x}"
            );
            *list = Some(
                object
                    .decode()
                    .with_context(|| format!("decode saved module object {index:#06x}"))?,
            );
        }
        Ok(inventory)
    }

    pub(super) fn detected_placements(&self) -> Result<Vec<Placement>> {
        let Some(List::Available(values)) = &self.detected else {
            bail!("automatic placement requires an available detected module list at 0xf050");
        };
        Ok(values
            .iter()
            .copied()
            .enumerate()
            .map(|(slot, module_ident)| Placement { slot, module_ident })
            .collect())
    }

    pub(super) fn compare(
        self,
        slots: &[SlotPreview],
        placement_source: PlacementSource,
    ) -> Comparison {
        let expected: Vec<_> = slots.iter().map(|slot| slot.module_ident).collect();
        Comparison {
            file_name: self.file_name,
            sha256: self.sha256,
            reported_serial: self.serial,
            source: self.source,
            placement_source,
            configured: compare_list(CONFIGURED, self.configured, &expected),
            detected: compare_list(DETECTED, self.detected, &expected),
        }
    }
}

impl Object {
    fn decode(mut self) -> Result<List> {
        if let Some(reason) = self.unavailable {
            ensure!(
                !reason.trim().is_empty() && self.uploads.is_empty(),
                "an unavailable list requires a reason and no upload values"
            );
            return Ok(List::Unavailable(reason));
        }
        ensure!(
            self.uploads.len() <= 256,
            "module list exceeds 255 subentries"
        );
        self.uploads.sort_by_key(|upload| upload.subindex);
        let (count, entries) = self
            .uploads
            .split_first()
            .context("module list is missing subindex zero")?;
        ensure!(count.subindex == 0, "module list is missing subindex zero");
        let [count] = count.decode()?;
        ensure!(
            entries.len() == usize::from(count),
            "module list count differs from the saved number of uploads"
        );
        let mut values = Vec::with_capacity(entries.len());
        for (zero_based, entry) in entries.iter().enumerate() {
            ensure!(
                usize::from(entry.subindex) == zero_based + 1,
                "module list subindexes must be unique and contiguous from one"
            );
            values.push(u32::from_le_bytes(entry.decode()?));
        }
        Ok(List::Available(values))
    }
}

impl Upload {
    fn decode<const N: usize>(&self) -> Result<[u8; N]> {
        let mut bytes = [0; N];
        hex::decode_to_slice(&self.data_hex, &mut bytes).with_context(|| {
            format!(
                "subindex {} requires {N} raw bytes as hexadecimal",
                self.subindex
            )
        })?;
        Ok(bytes)
    }
}

fn compare_list(index: u16, list: Option<List>, expected: &[u32]) -> ListComparison {
    let observed = match list {
        Some(List::Available(observed)) => observed,
        unavailable => {
            let reason = match unavailable {
                Some(List::Unavailable(reason)) => reason,
                _ => "object absent from saved module inventory".into(),
            };
            return ListComparison {
                index,
                state: State::Unavailable,
                reported_count: None,
                differences: Vec::new(),
                unavailable: Some(reason),
            };
        }
    };
    let differences: Vec<_> = (0..expected.len().max(observed.len()))
        .filter_map(|slot| {
            let expected = expected.get(slot).copied();
            let reported = observed.get(slot).copied();
            (expected != reported).then_some(SlotDifference {
                slot,
                expected,
                reported,
            })
        })
        .collect();
    ListComparison {
        index,
        state: if differences.is_empty() {
            State::Matched
        } else {
            State::Mismatch
        },
        reported_count: Some(observed.len()),
        differences,
        unavailable: None,
    }
}

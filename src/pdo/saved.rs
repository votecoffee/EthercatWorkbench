//! Identity-bound PDO evidence shared by saved-run inspectors.
use super::{Entry, Layout, MappingSource, SyncManager};
use crate::{benchmark::read_report_bytes_with_stop, model::Identity, pdo_catalog::Direction};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path};

#[derive(Deserialize)]
struct SavedReport {
    backend: String,
    devices: Vec<SavedDevice>,
    pdo_verification: Option<SavedVerification>,
}

#[derive(Deserialize)]
struct SavedDevice {
    identity: Option<Identity>,
    serial: Option<u32>,
}

#[derive(Deserialize)]
struct SavedVerification {
    readback: SavedReadback,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedReadback {
    tx: Option<ReportedLayout>,
    rx: Option<ReportedLayout>,
    tx_unavailable: Option<String>,
    rx_unavailable: Option<String>,
}

// Keep the presence of the source declaration. Older readbacks may omit it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedLayout {
    mapping_source: Option<MappingSource>,
    sync_managers: Vec<SyncManager>,
}

#[derive(Deserialize)]
#[serde(from = "SavedLayout")]
pub(crate) struct ReportedLayout {
    pub(crate) source: Option<MappingSource>,
    pub(crate) layout: Layout,
}

impl From<SavedLayout> for ReportedLayout {
    fn from(saved: SavedLayout) -> Self {
        Self {
            source: saved.mapping_source,
            layout: Layout {
                mapping_source: saved.mapping_source.unwrap_or_default(),
                sync_managers: saved.sync_managers,
            },
        }
    }
}

impl ReportedLayout {
    pub(crate) fn checked_entries(
        &self,
        direction: Direction,
        unavailable: Option<&str>,
    ) -> Result<(Vec<Entry>, usize)> {
        ensure!(
            unavailable.is_none(),
            "saved {direction:?} layout also declares unavailable readback"
        );
        ensure!(
            self.source != Some(MappingSource::Esi),
            "saved {direction:?} layout is an ESI expectation"
        );
        let parsed = self
            .layout
            .entries()
            .with_context(|| format!("check saved {direction:?} PDO layout"))?;
        let range = match direction {
            Direction::Tx => 0x1a00..=0x1bff,
            Direction::Rx => 0x1600..=0x17ff,
        };
        let mut assigned = BTreeSet::new();
        for pdo in self.layout.sync_managers.iter().flat_map(|sm| &sm.pdos) {
            ensure!(
                range.contains(&pdo.index),
                "saved PDO {:#06x} is outside the {direction:?} mapping range",
                pdo.index
            );
            ensure!(
                assigned.insert(pdo.index),
                "saved {direction:?} PDO {:#06x} is assigned to more than one SyncManager",
                pdo.index
            );
        }
        Ok(parsed)
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct Evidence {
    pub(crate) file_name: String,
    pub(crate) sha256: String,
    pub(crate) reported_backend: String,
    pub(crate) reported_serial: Option<u32>,
}

pub(crate) struct Run {
    pub(crate) evidence: Evidence,
    readback: Option<SavedReadback>,
}

impl Run {
    pub(crate) fn load(path: &Path, identity: &Identity) -> Result<Self> {
        let bytes = read_report_bytes_with_stop(path, None)?;
        let report: SavedReport =
            serde_json::from_slice(&bytes).context("parse saved run report for PDO comparison")?;
        let [device] = report.devices.as_slice() else {
            anyhow::bail!("saved run report must identify exactly one device");
        };
        ensure!(
            device.identity.as_ref() == Some(identity),
            "saved run device identity differs from the ESI selection or expected profile identity"
        );
        Ok(Self {
            evidence: Evidence {
                file_name: path
                    .file_name()
                    .context("saved run report path has no file name")?
                    .to_string_lossy()
                    .into_owned(),
                sha256: hex::encode(Sha256::digest(&bytes)),
                reported_backend: report.backend,
                reported_serial: device.serial,
            },
            readback: report.pdo_verification.map(|pdo| pdo.readback),
        })
    }

    pub(crate) fn direction(
        &self,
        direction: Direction,
    ) -> (Option<&ReportedLayout>, Option<&str>) {
        let Some(readback) = &self.readback else {
            return (None, None);
        };
        match direction {
            Direction::Tx => (readback.tx.as_ref(), readback.tx_unavailable.as_deref()),
            Direction::Rx => (readback.rx.as_ref(), readback.rx_unavailable.as_deref()),
        }
    }

    pub(crate) fn validate_sync_manager_separation(&self) -> Result<()> {
        if let Some(readback) = &self.readback
            && let Some((tx, rx)) = readback.tx.as_ref().zip(readback.rx.as_ref())
        {
            ensure!(
                !tx.layout.sync_managers.iter().any(|tx_sm| rx
                    .layout
                    .sync_managers
                    .iter()
                    .any(|rx_sm| tx_sm.index == rx_sm.index)),
                "saved Tx and Rx PDO layouts share a SyncManager"
            );
        }
        Ok(())
    }
}

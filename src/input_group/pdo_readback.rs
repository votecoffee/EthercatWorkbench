//! Review saved TxPDO descriptors and their placement in the planned logical input image.
use super::{
    Binding, InputGroup, fmmu, preflight::ReadbackReport, read_json, sync_manager,
    validate_stations,
};
use crate::{
    model::Identity,
    pdo::{DirectionCheck, Layout, MappingSource, Readback, SyncManager},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{ops::Range, path::Path, sync::atomic::AtomicBool};

const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {
    pub(super) schema: u32,
    pub(super) devices: Vec<Station>,
}

#[derive(Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Station {
    pub(super) station_address: u16,
    pub(super) identity: Identity,
    pub(super) tx: Option<TxLayout>,
    pub(super) tx_unavailable: Option<String>,
}

// Require the evidence source explicitly; generic Layout defaults it for legacy callers.
#[derive(Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TxLayout {
    pub(super) mapping_source: MappingSource,
    pub(super) sync_managers: Vec<SyncManager>,
}

#[derive(Deserialize)]
struct EvidenceHeader {
    schema: u32,
    source: Option<String>,
}

#[derive(Serialize)]
pub(super) struct Review {
    pub(super) source_sha256: String,
    pub(super) valid: bool,
    #[serde(skip)]
    pub(super) verified_exchanges: Option<usize>,
    devices: Vec<Device>,
}

#[derive(Serialize)]
struct Device {
    position: usize,
    station_address: u16,
    identity: Identity,
    readback: Option<Layout>,
    tx: DirectionCheck,
    placements: Vec<Placement>,
    issues: Vec<String>,
}

#[derive(Serialize)]
struct Placement {
    sync_manager: u8,
    logical_start: u64,
    bytes: usize,
    physical_range: Option<Range<u32>>,
    matches: bool,
}

impl Review {
    pub(super) fn require_valid(&self) -> Result<()> {
        for device in &self.devices {
            if let Some(issue) = device.issues.first().or_else(|| device.tx.errors.first()) {
                bail!(
                    "position {} at station {:#06x}: {issue}",
                    device.position,
                    device.station_address
                );
            }
        }
        Ok(())
    }
}

pub(super) struct Evidence {
    snapshot: Snapshot,
    source_sha256: String,
    verified_exchanges: Option<usize>,
}

impl Evidence {
    pub(super) fn load(path: &Path, group: &InputGroup, stop: Option<&AtomicBool>) -> Result<Self> {
        let (header, bytes) = read_json::<EvidenceHeader>(path, MAX_FILE_BYTES)?;
        let json = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
        let parse_context = || format!("parse {}", path.display());
        let (snapshot, verified_exchanges) = if let Some(source) = header.source {
            ensure!(
                header.schema == 1 && source == "virtual_group_pdo_reads",
                "expected a schema 1 virtual group PDO readback report"
            );
            let report: ReadbackReport =
                serde_json::from_slice(json).with_context(parse_context)?;
            let (snapshot, exchanges) = report.rebuild(group, stop)?;
            (snapshot, Some(exchanges))
        } else {
            (
                serde_json::from_slice(json).with_context(parse_context)?,
                None,
            )
        };
        Ok(Self {
            snapshot,
            source_sha256: hex::encode(Sha256::digest(&bytes)),
            verified_exchanges,
        })
    }

    pub(super) fn review(
        &self,
        group: &InputGroup,
        fmmu: &fmmu::Review,
        sync_managers: &sync_manager::Review,
    ) -> Result<Review> {
        let mut review = review_snapshot(
            self.snapshot.clone(),
            self.source_sha256.clone(),
            &group.bindings,
            fmmu,
            sync_managers,
        )?;
        review.verified_exchanges = self.verified_exchanges;
        Ok(review)
    }
}

pub(super) fn review_snapshot(
    snapshot: Snapshot,
    source_sha256: String,
    bindings: &[Binding],
    fmmu: &fmmu::Review,
    sync_managers: &sync_manager::Review,
) -> Result<Review> {
    ensure!(
        snapshot.schema == 1,
        "unsupported group PDO schema {}",
        snapshot.schema
    );
    let stations: Vec<_> = snapshot
        .devices
        .iter()
        .map(|device| device.station_address)
        .collect();
    validate_stations(&stations, bindings.len())?;
    let devices: Vec<_> = snapshot
        .devices
        .into_iter()
        .zip(bindings)
        .zip(fmmu.devices.iter().zip(&sync_managers.devices))
        .map(|((station, binding), (mapped, sm))| check(station, binding, mapped, sm))
        .collect();
    Ok(Review {
        source_sha256,
        verified_exchanges: None,
        valid: devices
            .iter()
            .all(|device| device.issues.is_empty() && device.tx.errors.is_empty()),
        devices,
    })
}

fn check(
    station: Station,
    binding: &Binding,
    fmmu: &fmmu::Device,
    sm: &sync_manager::Device,
) -> Device {
    let mut issues = Vec::new();
    if station.identity != binding.entry.identity {
        issues.push(format!(
            "PDO identity differs from the profile ({})",
            binding.entry.identity
        ));
    }
    if station.station_address != fmmu.station_address
        || station.station_address != sm.station_address
    {
        issues.push("PDO station address differs from the FMMU or SyncManager evidence".into());
    }
    if !sm.issues.is_empty() {
        issues.push("SyncManager physical coverage check did not pass".into());
    }
    let readback = station.tx.map(|tx| Layout {
        mapping_source: tx.mapping_source,
        sync_managers: tx.sync_managers,
    });
    if let Some(layout) = &readback {
        if layout.mapping_source == MappingSource::Esi {
            issues.push("ESI layout is an expectation; supply CoE or SII readback".into());
        }
        if station.tx_unavailable.is_some() {
            issues.push("snapshot declares both a TxPDO layout and an unavailable reason".into());
        }
        if layout
            .sync_managers
            .iter()
            .flat_map(|sm| &sm.pdos)
            .any(|pdo| !(0x1a00..=0x1bff).contains(&pdo.index))
        {
            issues.push("TxPDO assignments contain an index outside 0x1a00–0x1bff".into());
        }
    } else {
        issues.push("saved TxPDO layout is unavailable".into());
    }

    let verified = Readback {
        tx: readback,
        rx: None,
        tx_unavailable: station.tx_unavailable,
        rx_unavailable: None,
    }
    .verify(&binding.profile, "Saved group TxPDO readback");
    let readback = verified.readback.tx;
    let tx = verified.tx;
    let mut placements = Vec::new();
    if let Some(layout) = &readback
        && tx.image_bytes.is_some()
        && sm.issues.is_empty()
    {
        let buffers: Vec<_> = sm.input_buffers().collect();
        let mappings: Vec<_> = fmmu.read_mappings().collect();
        let mut bits = [0usize; 16];
        for entry in &tx.entries {
            bits[usize::from(entry.sync_manager)] += entry.width;
        }
        let mut logical = binding.offset.unwrap_or(0) as u64;
        for assigned in &layout.sync_managers {
            let index = assigned.index;
            let bytes = bits[usize::from(index)].div_ceil(8);
            if bytes == 0 {
                continue;
            }
            let physical = buffers
                .iter()
                .find(|(slot, _)| *slot == usize::from(index))
                .map(|(_, range)| range.clone());
            let matches = physical.as_ref().is_some_and(|physical| {
                physical.len() == bytes && projects(logical, physical, &mappings)
            });
            if !matches {
                issues.push(format!(
                    "SM{index} TxPDO bytes do not map to the planned logical range {logical}..{}",
                    logical + bytes as u64
                ));
            }
            placements.push(Placement {
                sync_manager: index,
                logical_start: logical,
                bytes,
                physical_range: physical,
                matches,
            });
            logical += bytes as u64;
        }
        for (slot, _) in buffers {
            if bits[slot] == 0 {
                issues.push(format!(
                    "enabled input SM{slot} has no TxPDO bytes in the saved layout"
                ));
            }
        }
    }
    Device {
        position: binding.entry.position,
        station_address: station.station_address,
        identity: station.identity,
        readback,
        tx,
        placements,
        issues,
    }
}

fn projects(
    logical: u64,
    physical: &Range<u32>,
    mappings: &[(usize, Range<u64>, Range<u32>)],
) -> bool {
    let mut covered = 0;
    for (_, target, source) in mappings {
        let start = physical.start.max(source.start);
        let end = physical.end.min(source.end);
        if start >= end {
            continue;
        }
        let expected = logical + u64::from(start - physical.start);
        let mapped = target.start + u64::from(start - source.start);
        if expected != mapped {
            return false;
        }
        covered += end - start;
    }
    covered == physical.end - physical.start
}

//! Offline review of device-level virtual TxPDOs that describe ESC register bytes.
use super::{Device, VirtualSyncManager, load, number, select_device};
use crate::{
    esc::{self, Snapshot},
    model::Identity,
    pdo_catalog::{Definition, Direction},
};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

mod fmmu;
mod payload;

const ESC_REGISTER_END: usize = 0x0f00;

#[derive(Serialize)]
pub struct Review {
    schema: u32,
    scope: &'static str,
    identity: Identity,
    esi_file_name: String,
    esi_sha256: String,
    snapshot: Option<SnapshotEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fmmu: Option<fmmu::Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logical_payload: Option<payload::Evidence>,
    projections: Vec<Projection>,
}

#[derive(Serialize)]
struct SnapshotEvidence {
    file_name: String,
    sha256: String,
    source: esc::Source,
    position: u16,
    station_address: u16,
    started_utc: String,
    elapsed_us: u64,
    identity_binding: &'static str,
}

#[derive(Serialize)]
struct Projection {
    pdo_index: u16,
    name: String,
    declared_sync_manager: Option<u8>,
    declared_start_address: Option<String>,
    byte_count: Option<usize>,
    unavailable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fmmu_check: Option<fmmu::Check>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logical_sample: Option<Sample>,
    entries: Vec<Entry>,
}

#[derive(Serialize)]
struct Entry {
    name: String,
    data_type: String,
    declared_index: u16,
    declared_subindex: u8,
    width_bits: usize,
    byte_offset: Option<usize>,
    sample: Option<Sample>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logical_sample: Option<Sample>,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Sample {
    Available { raw_hex: String },
    Unavailable { reason: String },
}

pub enum LogicalSource<'a> {
    Payload(&'a Path),
    LrdReply(&'a Path),
}

pub fn preview(
    esi: &Path,
    index: Option<usize>,
    identity: Option<&Identity>,
    snapshot: Option<&Path>,
    fmmu: Option<(&Path, u16)>,
    logical_payload: Option<LogicalSource<'_>>,
) -> Result<Review> {
    let devices = load(esi)?;
    let device = select_device(&devices, index, identity)?;
    let snapshot = snapshot.map(load_saved).transpose()?;
    let fmmu = fmmu
        .map(|(path, station)| fmmu::Table::load(path, station))
        .transpose()?;
    if let (Some((evidence, _)), Some(table)) = (&snapshot, &fmmu) {
        ensure!(
            evidence.station_address == table.evidence.station_address,
            "ESC snapshot station {:#06x} differs from selected FMMU station {:#06x}",
            evidence.station_address,
            table.evidence.station_address,
        );
    }
    let logical_payload = logical_payload
        .map(|source| {
            let table = fmmu
                .as_ref()
                .context("logical payload review requires a saved FMMU table")?;
            let station = table.evidence.station_address;
            match source {
                LogicalSource::Payload(path) => payload::Window::load(path, station),
                LogicalSource::LrdReply(path) => payload::Window::load_reply(path, station),
            }
        })
        .transpose()?;
    let projections = device
        .source
        .pdo_catalog
        .iter()
        .filter(|pdo| pdo.direction == Direction::Tx && pdo.virtual_pdo && !pdo.entries.is_empty())
        .map(|pdo| {
            projection(
                device,
                pdo,
                snapshot.as_ref().map(|(_, snapshot)| snapshot),
                fmmu.as_ref(),
                logical_payload.as_ref(),
            )
        })
        .collect();
    Ok(Review {
        schema: 1,
        scope: "offline_esi_register_pdos",
        identity: device.source.identity.clone(),
        esi_file_name: device.source.file_name.clone(),
        esi_sha256: device.source.sha256.clone(),
        snapshot: snapshot.map(|(evidence, _)| evidence),
        fmmu: fmmu.map(|table| table.evidence),
        logical_payload: logical_payload.map(|window| window.evidence),
        projections,
    })
}

fn load_saved(path: &Path) -> Result<(SnapshotEvidence, Snapshot)> {
    let bytes = esc::read_snapshot(path).context("read saved ESC snapshot")?;
    let snapshot = esc::decode_snapshot(&bytes)?.snapshot;
    let evidence = SnapshotEvidence {
        file_name: path
            .file_name()
            .context("ESC snapshot has no file name")?
            .to_string_lossy()
            .into_owned(),
        sha256: hex::encode(Sha256::digest(&bytes)),
        source: snapshot.source,
        position: snapshot.position,
        station_address: snapshot.station_address,
        started_utc: snapshot.started_utc.clone(),
        elapsed_us: snapshot.elapsed_us,
        identity_binding: "absent_from_snapshot",
    };
    Ok((evidence, snapshot))
}

fn projection(
    device: &Device,
    pdo: &Definition,
    snapshot: Option<&Snapshot>,
    fmmu: Option<&fmmu::Table>,
    logical_payload: Option<&payload::Window>,
) -> Projection {
    let sm = pdo
        .default_sm
        .and_then(|index| device.virtual_sync_managers.get(&index));
    let (byte_count, unavailable) = match geometry(device, pdo, sm) {
        Ok(bytes) => (Some(bytes), None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    let fmmu_check = fmmu.map(|table| match byte_count {
        Some(width) => table.compare(pdo.entries[0].index, width),
        None => fmmu::Check::Unavailable {
            reason: "ESI projection geometry is unavailable".into(),
        },
    });
    let logical = logical_payload.zip(fmmu_check.as_ref());
    let logical_sample =
        logical.map(|(window, check)| window.sample(check, 0..byte_count.unwrap_or_default()));
    let mut byte_offset = 0;
    let entries = pdo
        .entries
        .iter()
        .map(|entry| {
            let offset = byte_offset;
            let width = entry.width / 8;
            byte_offset += width;
            let sample = match (byte_count.is_some(), snapshot) {
                (true, Some(snapshot)) => Some(match saved_bytes(snapshot, entry.index, width) {
                    Ok(bytes) => Sample::Available {
                        raw_hex: hex::encode_upper(bytes),
                    },
                    Err(error) => Sample::Unavailable {
                        reason: error.to_string(),
                    },
                }),
                _ => None,
            };
            Entry {
                name: entry.name.clone(),
                data_type: entry.data_type.clone(),
                declared_index: entry.index,
                declared_subindex: entry.subindex,
                width_bits: entry.width,
                byte_offset: byte_count.is_some().then_some(offset),
                sample,
                logical_sample: logical
                    .map(|(window, check)| window.sample(check, offset..byte_offset)),
            }
        })
        .collect();
    Projection {
        pdo_index: pdo.index,
        name: pdo.name.clone(),
        declared_sync_manager: pdo.default_sm,
        declared_start_address: sm.and_then(|sm| sm.start_address.clone()),
        byte_count,
        unavailable,
        fmmu_check,
        logical_sample,
        entries,
    }
}

fn geometry(device: &Device, pdo: &Definition, sm: Option<&VirtualSyncManager>) -> Result<usize> {
    ensure!(
        !pdo.unsupported,
        "vendor-dependent PDO requires separate interpretation"
    );
    let sm = sm.context("PDO needs an explicit assignment to an ESI virtual SyncManager")?;
    ensure!(
        sm.name == "Inputs",
        "virtual SyncManager must declare Inputs"
    );
    ensure!(
        device
            .source
            .pdo_catalog
            .iter()
            .filter(|other| other.default_sm == pdo.default_sm)
            .count()
            == 1,
        "virtual SyncManager has multiple default PDO assignments"
    );
    let start = number(
        sm.start_address
            .as_deref()
            .context("virtual SyncManager needs StartAddress")?,
    )
    .context("invalid virtual SyncManager StartAddress")? as usize;
    ensure!(
        start < ESC_REGISTER_END,
        "StartAddress is outside the ESC register area"
    );
    let mut end = start;
    for entry in &pdo.entries {
        ensure!(entry.index != 0, "zero Index could describe padding");
        ensure!(
            entry.subindex == 0,
            "nonzero SubIndex needs separate interpretation"
        );
        ensure!(
            entry.width > 0 && entry.width.is_multiple_of(8),
            "register entry width must be a positive multiple of 8 bits"
        );
        ensure!(
            usize::from(entry.index) == end,
            "register indexes must be contiguous from StartAddress"
        );
        end += entry.width / 8;
        ensure!(
            end <= ESC_REGISTER_END,
            "entry extends outside the ESC register area"
        );
    }
    Ok(end - start)
}

fn saved_bytes(snapshot: &Snapshot, register: u16, width: usize) -> Result<Vec<u8>> {
    let (base, data): (u16, &[u8]) = match register {
        0x0000..=0x000f => (
            0x0000,
            snapshot.information.value.as_ref().with_context(|| {
                format!(
                    "ESC information unavailable: {}",
                    snapshot
                        .information
                        .unavailable
                        .as_deref()
                        .unwrap_or_default()
                )
            })?,
        ),
        0x0110..=0x0111 => (0x0110, &snapshot.dl_status.to_le_bytes()),
        0x0130..=0x0131 => (0x0130, &snapshot.al_status.to_le_bytes()),
        0x0134..=0x0135 => (0x0134, &snapshot.al_code.to_le_bytes()),
        0x0300..=0x0313 => (
            0x0300,
            snapshot.counters.value.as_ref().with_context(|| {
                format!(
                    "ESC counters unavailable: {}",
                    snapshot.counters.unavailable.as_deref().unwrap_or_default()
                )
            })?,
        ),
        _ => bail!("register range is absent from the ESC snapshot"),
    };
    let offset = usize::from(register - base);
    let bytes = data
        .get(offset..offset + width)
        .context("entry extends beyond the saved register block")?;
    Ok(bytes.to_vec())
}

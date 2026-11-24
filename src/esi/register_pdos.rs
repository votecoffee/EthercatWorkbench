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
use std::{collections::HashMap, ops::Range, path::Path};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    manual_start_bit: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    width_bits: Option<usize>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    bit_offset: Option<usize>,
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

pub fn start_bit(text: &str) -> Result<(u16, u8)> {
    let (pdo, bit) = text
        .split_once('=')
        .context("use PDO=BIT for a register start bit")?;
    let pdo = u16::try_from(number(pdo)?).context("PDO index exceeds 16 bits")?;
    let bit = number(bit)?;
    ensure!(bit < 8, "register start bit must be 0 through 7");
    Ok((pdo, bit as u8))
}

pub fn preview(
    esi: &Path,
    index: Option<usize>,
    identity: Option<&Identity>,
    snapshot: Option<&Path>,
    fmmu: Option<(&Path, u16)>,
    logical_payload: Option<LogicalSource<'_>>,
) -> Result<Review> {
    preview_with_start_bits(esi, index, identity, snapshot, fmmu, logical_payload, &[])
}

pub fn preview_with_start_bits(
    esi: &Path,
    index: Option<usize>,
    identity: Option<&Identity>,
    snapshot: Option<&Path>,
    fmmu: Option<(&Path, u16)>,
    logical_payload: Option<LogicalSource<'_>>,
    start_bits: &[(u16, u8)],
) -> Result<Review> {
    let devices = load(esi)?;
    let device = select_device(&devices, index, identity)?;
    let pdos: Vec<_> = device
        .source
        .pdo_catalog
        .iter()
        .filter(|pdo| pdo.direction == Direction::Tx && pdo.virtual_pdo && !pdo.entries.is_empty())
        .collect();
    let mut manual = HashMap::new();
    for &(index, bit) in start_bits {
        ensure!(bit < 8, "register start bit must be 0 through 7");
        ensure!(
            pdos.iter().filter(|pdo| pdo.index == index).count() == 1,
            "manual start bit needs a unique virtual TxPDO with entries at {index:#06x}"
        );
        ensure!(
            manual.insert(index, bit).is_none(),
            "duplicate manual register start bit for PDO {index:#06x}"
        );
    }
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
                LogicalSource::LrdReply(path) => payload::Window::load_reply(path, table),
            }
        })
        .transpose()?;
    let projections = pdos
        .into_iter()
        .map(|pdo| {
            projection(
                device,
                pdo,
                snapshot.as_ref().map(|(_, snapshot)| snapshot),
                fmmu.as_ref(),
                logical_payload.as_ref(),
                manual.get(&pdo.index).copied(),
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
    manual_start_bit: Option<u8>,
) -> Projection {
    let sm = pdo
        .default_sm
        .and_then(|index| device.virtual_sync_managers.get(&index));
    let (physical, unavailable) = match geometry(device, pdo, sm, manual_start_bit) {
        Ok(range) => (Some(range), None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    let width_bits = physical.as_ref().map(Range::len);
    let fmmu_check = fmmu.map(|table| match &physical {
        Some(range) => table.compare(range.clone()),
        None => fmmu::Check::Unavailable {
            reason: "ESI projection geometry is unavailable".into(),
        },
    });
    let logical = logical_payload.zip(fmmu_check.as_ref());
    let logical_sample =
        logical.map(|(window, check)| window.sample(check, 0..width_bits.unwrap_or_default()));
    let mut bit_offset = 0;
    let entries = pdo
        .entries
        .iter()
        .map(|entry| {
            let offset = bit_offset;
            bit_offset += entry.width;
            let sample = match (&physical, snapshot) {
                (Some(range), Some(snapshot)) => Some(
                    match saved_bits(snapshot, range.start + offset, entry.width) {
                        Ok(bytes) => Sample::Available {
                            raw_hex: hex::encode_upper(bytes),
                        },
                        Err(error) => Sample::Unavailable {
                            reason: error.to_string(),
                        },
                    },
                ),
                _ => None,
            };
            Entry {
                name: entry.name.clone(),
                data_type: entry.data_type.clone(),
                declared_index: entry.index,
                declared_subindex: entry.subindex,
                width_bits: entry.width,
                byte_offset: (physical.is_some()
                    && offset.is_multiple_of(8)
                    && entry.width.is_multiple_of(8))
                .then_some(offset / 8),
                bit_offset: (manual_start_bit.is_some() && physical.is_some()).then_some(offset),
                sample,
                logical_sample: logical
                    .map(|(window, check)| window.sample(check, offset..bit_offset)),
            }
        })
        .collect();
    Projection {
        pdo_index: pdo.index,
        name: pdo.name.clone(),
        declared_sync_manager: pdo.default_sm,
        declared_start_address: sm.and_then(|sm| sm.start_address.clone()),
        manual_start_bit,
        width_bits: manual_start_bit.and(width_bits),
        byte_count: width_bits.map(|bits| bits.div_ceil(8)),
        unavailable,
        fmmu_check,
        logical_sample,
        entries,
    }
}

fn geometry(
    device: &Device,
    pdo: &Definition,
    sm: Option<&VirtualSyncManager>,
    manual_start_bit: Option<u8>,
) -> Result<Range<usize>> {
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
    let start = start * 8 + usize::from(manual_start_bit.unwrap_or_default());
    let mut end = start;
    for entry in &pdo.entries {
        ensure!(entry.index != 0, "zero Index could describe padding");
        ensure!(
            manual_start_bit.is_some() || entry.subindex == 0,
            "nonzero SubIndex needs separate interpretation"
        );
        ensure!(entry.width > 0, "register entry width must be positive");
        ensure!(
            manual_start_bit.is_some() || entry.width.is_multiple_of(8),
            "a register entry with a non-byte width needs --register-start-bit PDO=BIT"
        );
        ensure!(
            usize::from(entry.index) == end / 8,
            "register indexes must be contiguous from StartAddress"
        );
        end += entry.width;
        ensure!(
            end <= ESC_REGISTER_END * 8,
            "entry extends outside the ESC register area"
        );
    }
    Ok(start..end)
}

fn saved_bits(snapshot: &Snapshot, start: usize, width: usize) -> Result<Vec<u8>> {
    let register = (start / 8) as u16;
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
    let offset = start - usize::from(base) * 8;
    ensure!(
        offset + width <= data.len() * 8,
        "entry extends beyond the saved register block"
    );
    let mut packed = vec![0; width.div_ceil(8)];
    copy_bits(data, offset, &mut packed, 0, width);
    Ok(packed)
}

fn copy_bits(source: &[u8], start: usize, destination: &mut [u8], offset: usize, width: usize) {
    for (source_bit, destination_bit) in (start..).zip(offset..offset + width) {
        let bit = (source[source_bit / 8] >> (source_bit % 8)) & 1;
        destination[destination_bit / 8] |= bit << (destination_bit % 8);
    }
}

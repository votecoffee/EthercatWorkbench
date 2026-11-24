//! Offline review of device-level virtual TxPDOs that describe ESC register bytes.
use super::{Device, VirtualSyncManager, load, number, select_device};
use crate::{
    esc::{self, Snapshot},
    model::{Identity, MAX_PAYLOAD},
    pdo_catalog::{Definition, Direction},
};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, ops::Range, path::Path};

mod fmmu;
mod layout;
mod payload;

const ESC_REGISTER_END: usize = 0x0f00;

#[derive(Serialize)]
pub struct Review {
    schema: u32,
    scope: &'static str,
    identity: Identity,
    esi_file_name: String,
    esi_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    manual_register_layout: Option<layout::Evidence>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    physical_start_bit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    padding: Option<&'static str>,
    sample: Option<Sample>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fmmu_check: Option<fmmu::Check>,
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

pub enum LayoutSource<'a> {
    StartBits(&'a [(u16, u8)]),
    File(&'a Path),
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
    preview_with_layout(
        esi,
        index,
        identity,
        snapshot,
        fmmu,
        logical_payload,
        LayoutSource::StartBits(start_bits),
    )
}

pub fn preview_with_layout(
    esi: &Path,
    index: Option<usize>,
    identity: Option<&Identity>,
    snapshot: Option<&Path>,
    fmmu: Option<(&Path, u16)>,
    logical_payload: Option<LogicalSource<'_>>,
    source: LayoutSource<'_>,
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
    let saved = match source {
        LayoutSource::StartBits(start_bits) => {
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
            None
        }
        LayoutSource::File(path) => Some(layout::load(
            path,
            &device.source.identity,
            &device.source.sha256,
            &pdos,
        )?),
    };
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
                saved
                    .as_ref()
                    .and_then(|(_, pdos)| pdos.get(&pdo.index))
                    .map(Vec::as_slice),
            )
        })
        .collect();
    Ok(Review {
        schema: 1,
        scope: "offline_esi_register_pdos",
        identity: device.source.identity.clone(),
        esi_file_name: device.source.file_name.clone(),
        esi_sha256: device.source.sha256.clone(),
        manual_register_layout: saved.map(|(evidence, _)| evidence),
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
    entry_start_bits: Option<&[Option<u8>]>,
) -> Projection {
    let sm = pdo
        .default_sm
        .and_then(|index| device.virtual_sync_managers.get(&index));
    let (physical, unavailable) =
        match geometry(device, pdo, sm, manual_start_bit, entry_start_bits) {
            Ok(ranges) => (Some(ranges), None),
            Err(error) => (None, Some(format!("{error:#}"))),
        };
    let width_bits = physical.as_ref().map(|geometry| geometry.width_bits);
    let entry_checks: Vec<_> = match (entry_start_bits, &physical, fmmu) {
        (Some(_), Some(geometry), Some(table)) => geometry
            .entries
            .iter()
            .map(|range| range.clone().map(|range| table.compare(range)))
            .collect(),
        _ => Vec::new(),
    };
    let fmmu_check = fmmu.map(|table| match &physical {
        Some(geometry) => match &geometry.contiguous {
            Some(range) => table.compare(range.clone()),
            None => fmmu::Check::combine(
                pdo.entries
                    .iter()
                    .zip(&entry_checks)
                    .map(|(entry, check)| (entry.width, check.as_ref())),
            ),
        },
        None => fmmu::Check::Unavailable {
            reason: "ESI projection geometry is unavailable".into(),
        },
    });
    let logical = logical_payload.zip(fmmu_check.as_ref());
    let logical_sample =
        logical.map(|(window, check)| window.sample(check, 0..width_bits.unwrap_or_default()));
    let mut entry_checks = entry_checks.into_iter();
    let manual_placement = manual_start_bit.is_some() || entry_start_bits.is_some();
    let mut bit_offset = 0;
    let entries = pdo
        .entries
        .iter()
        .enumerate()
        .map(|(position, entry)| {
            let offset = bit_offset;
            bit_offset += entry.width;
            let start = physical
                .as_ref()
                .and_then(|geometry| geometry.entries[position].as_ref())
                .map(|range| range.start);
            let padding = entry_start_bits.is_some_and(|bits| bits[position].is_none());
            let sample = match (start, snapshot) {
                (Some(start), Some(snapshot)) => {
                    Some(match saved_bits(snapshot, start, entry.width) {
                        Ok(bytes) => Sample::Available {
                            raw_hex: hex::encode_upper(bytes),
                        },
                        Err(error) => Sample::Unavailable {
                            reason: error.to_string(),
                        },
                    })
                }
                _ => None,
            };
            let entry_check = entry_checks.next().flatten();
            let logical_sample = match (padding, logical_payload, entry_check.as_ref()) {
                (true, _, _) => None,
                (_, Some(window), Some(check)) => Some(window.sample(check, 0..entry.width)),
                _ => logical.map(|(window, check)| window.sample(check, offset..bit_offset)),
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
                bit_offset: (manual_placement && physical.is_some()).then_some(offset),
                physical_start_bit: entry_start_bits.and(start),
                padding: padding.then_some("zero_filled"),
                sample,
                fmmu_check: entry_check,
                logical_sample,
            }
        })
        .collect();
    Projection {
        pdo_index: pdo.index,
        name: pdo.name.clone(),
        declared_sync_manager: pdo.default_sm,
        declared_start_address: sm.and_then(|sm| sm.start_address.clone()),
        manual_start_bit,
        width_bits: width_bits.filter(|_| manual_placement),
        byte_count: width_bits.map(|bits| bits.div_ceil(8)),
        unavailable,
        fmmu_check,
        logical_sample,
        entries,
    }
}

struct Geometry {
    entries: Vec<Option<Range<usize>>>,
    width_bits: usize,
    contiguous: Option<Range<usize>>,
}

fn geometry(
    device: &Device,
    pdo: &Definition,
    sm: Option<&VirtualSyncManager>,
    manual_start_bit: Option<u8>,
    entry_start_bits: Option<&[Option<u8>]>,
) -> Result<Geometry> {
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
    if let Some(bits) = entry_start_bits {
        let first = pdo.entries.iter().zip(bits).find(|(_, bit)| bit.is_some());
        ensure!(
            first.is_some_and(|(entry, _)| usize::from(entry.index) == start),
            "first manual register entry must start at the virtual SyncManager StartAddress"
        );
    }
    let first_bit = start * 8 + usize::from(manual_start_bit.unwrap_or_default());
    let mut next = first_bit;
    let mut ranges = Vec::with_capacity(pdo.entries.len());
    let mut width_bits = 0;
    let manual = manual_start_bit.is_some() || entry_start_bits.is_some();
    for (position, entry) in pdo.entries.iter().enumerate() {
        ensure!(entry.width > 0, "register entry width must be positive");
        width_bits += entry.width;
        if entry_start_bits.is_some_and(|bits| bits[position].is_none()) {
            ranges.push(None);
            continue;
        }
        ensure!(entry.index != 0, "zero Index could describe padding");
        ensure!(
            manual || entry.subindex == 0,
            "nonzero SubIndex needs separate interpretation"
        );
        ensure!(
            manual || entry.width.is_multiple_of(8),
            "a register entry with a non-byte width needs --register-start-bit PDO=BIT"
        );
        let start = if let Some(bit) = entry_start_bits.and_then(|bits| bits[position]) {
            usize::from(entry.index) * 8 + usize::from(bit)
        } else {
            ensure!(
                usize::from(entry.index) == next / 8,
                "register indexes must be contiguous from StartAddress"
            );
            next
        };
        next = start + entry.width;
        ensure!(
            next <= ESC_REGISTER_END * 8,
            "entry extends outside the ESC register area"
        );
        ranges.push(Some(start..next));
    }
    if let Some(bits) = entry_start_bits {
        ensure!(
            bits.iter().all(Option::is_some) || width_bits <= MAX_PAYLOAD * 8,
            "padded register projection exceeds {MAX_PAYLOAD} bytes"
        );
        let mut ordered: Vec<_> = ranges.iter().flatten().collect();
        ordered.sort_unstable_by_key(|range| range.start);
        ensure!(
            ordered.windows(2).all(|pair| pair[0].end <= pair[1].start),
            "manual register entries overlap in the physical address space"
        );
    }
    Ok(Geometry {
        entries: ranges,
        width_bits,
        contiguous: entry_start_bits.is_none().then_some(first_bit..next),
    })
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

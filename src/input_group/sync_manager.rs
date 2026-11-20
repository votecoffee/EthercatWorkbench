//! Compare saved input SyncManager apertures with the physical side of the FMMUs.
use super::{
    fmmu::{self, Read},
    read_json, validate_stations,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{ops::Range, path::Path};

const MAX_CHANNELS: usize = 16;
const MAX_FILE_BYTES: u64 = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: u32,
    devices: Vec<Station>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Station {
    pub(crate) station_address: u16,
    pub(crate) count: Read<u8>,
    pub(crate) slots: Vec<Read<[u8; 8]>>,
}

#[derive(Serialize)]
pub(super) struct Review {
    source_sha256: String,
    pub(super) valid: bool,
    pub(super) devices: Vec<Device>,
}

#[derive(Serialize)]
pub(crate) struct Device {
    position: usize,
    pub(super) station_address: u16,
    fmmu_station_matches: bool,
    count: Read<u8>,
    slots: Vec<Slot>,
    fmmu_physical_ranges: Vec<Range<u32>>,
    input_buffer_ranges: Vec<Range<u32>>,
    pub(crate) issues: Vec<String>,
}

#[derive(Serialize)]
struct Slot {
    index: usize,
    read: Read<[u8; 8]>,
    channel: Option<Channel>,
    covering_fmmu_slots: Vec<usize>,
}

#[derive(Serialize)]
struct Channel {
    physical_start: u16,
    length: u16,
    mode: u8,
    direction: u8,
    enabled: bool,
    pdi_deactivated: bool,
}

impl Channel {
    fn decode(raw: &[u8; 8]) -> Self {
        Self {
            physical_start: u16::from_le_bytes([raw[0], raw[1]]),
            length: u16::from_le_bytes([raw[2], raw[3]]),
            mode: raw[4] & 3,
            direction: (raw[4] >> 2) & 3,
            enabled: raw[6] & 1 != 0,
            pdi_deactivated: raw[7] & 1 != 0,
        }
    }

    fn range(&self) -> Range<u32> {
        let start = u32::from(self.physical_start);
        start..start + u32::from(self.length)
    }

    fn input_channel(&self) -> bool {
        self.enabled && self.mode == 0 && self.direction == 0
    }
}

impl Device {
    pub(super) fn input_buffers(&self) -> impl Iterator<Item = (usize, Range<u32>)> + '_ {
        self.slots.iter().filter_map(|slot| {
            let channel = slot.channel.as_ref()?;
            (channel.input_channel() && !channel.pdi_deactivated)
                .then(|| (slot.index, channel.range()))
        })
    }
}

pub(super) fn review(path: &Path, fmmu: &fmmu::Review) -> Result<Review> {
    let (snapshot, bytes) = read_json::<Snapshot>(path, MAX_FILE_BYTES)?;
    ensure!(
        snapshot.schema == 1,
        "unsupported group SyncManager schema {}",
        snapshot.schema
    );
    let stations: Vec<_> = snapshot
        .devices
        .iter()
        .map(|device| device.station_address)
        .collect();
    validate_stations(&stations, fmmu.devices.len())?;
    let devices = snapshot
        .devices
        .into_iter()
        .zip(&fmmu.devices)
        .enumerate()
        .map(|(position, (station, mapped))| {
            ensure!(
                station.slots.len() <= MAX_CHANNELS,
                "position {position} has more than {MAX_CHANNELS} SyncManager slots"
            );
            Ok(check(station, position, mapped))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Review {
        source_sha256: hex::encode(Sha256::digest(&bytes)),
        valid: devices.iter().all(|device| device.issues.is_empty()),
        devices,
    })
}

pub(crate) fn check(station: Station, position: usize, fmmu: &fmmu::Device) -> Device {
    let mut issues = Vec::new();
    let fmmu_station_matches = station.station_address == fmmu.station_address;
    if !fmmu_station_matches {
        issues.push(format!(
            "station address differs from FMMU evidence ({:#06x})",
            fmmu.station_address
        ));
    }
    if !fmmu.issues.is_empty() {
        issues.push("FMMU logical layout check did not pass".into());
    }
    if station.count.wkc != 1 {
        issues.push(format!(
            "SyncManager count WKC {}, expected 1",
            station.count.wkc
        ));
    } else if usize::from(station.count.value) > MAX_CHANNELS {
        issues.push(format!(
            "SyncManager count {} exceeds {MAX_CHANNELS}",
            station.count.value
        ));
    } else if usize::from(station.count.value) != station.slots.len() {
        issues.push(format!(
            "ESC reports {} SyncManager slots, snapshot contains {}",
            station.count.value,
            station.slots.len()
        ));
    }
    let mapped = fmmu.physical_read_ranges();
    let mut inputs = Vec::new();
    let mut enabled = Vec::new();
    let slots = station
        .slots
        .into_iter()
        .enumerate()
        .map(|(index, read)| {
            let mut covering_fmmu_slots = Vec::new();
            let channel =
                if read.wkc == 1 {
                    let channel = Channel::decode(&read.value);
                    let range = channel.range();
                    if channel.enabled && !range.is_empty() {
                        enabled.push((index, range.clone()));
                    }
                    if channel.input_channel() {
                        if channel.pdi_deactivated {
                            issues.push(format!("input SM{index} is deactivated by its PDI"));
                        } else if range.is_empty() || range.start < 0x1000 || range.end > 0x1_0000 {
                            issues.push(format!(
                                "input SM{index} has an invalid physical range {range:#x?}"
                            ));
                        } else {
                            covering_fmmu_slots.extend(mapped.iter().filter_map(|(slot, span)| {
                                intersects(&range, span).then_some(*slot)
                            }));
                            inputs.push((index, range));
                        }
                    }
                    Some(channel)
                } else {
                    issues.push(format!("SM{index} WKC {}, expected 1", read.wkc));
                    None
                };
            Slot {
                index,
                read,
                channel,
                covering_fmmu_slots,
            }
        })
        .collect();

    for (index, range) in &inputs {
        if let Some((other, _)) = enabled
            .iter()
            .find(|(other, other_range)| index != other && intersects(range, other_range))
        {
            issues.push(format!(
                "input SM{index} overlaps enabled SM{other} in physical memory"
            ));
        }
    }
    let (input_buffer_ranges, _) =
        merge_ranges(inputs.into_iter().map(|(_, range)| range).collect());
    let (fmmu_physical_ranges, aliased) =
        merge_ranges(mapped.into_iter().map(|(_, range)| range).collect());
    if aliased {
        issues.push("FMMU input mappings overlap in physical memory".into());
    }
    if input_buffer_ranges != fmmu_physical_ranges {
        issues.push("FMMU physical coverage differs from the enabled buffered input ranges".into());
    }
    Device {
        position,
        station_address: station.station_address,
        fmmu_station_matches,
        count: station.count,
        slots,
        fmmu_physical_ranges,
        input_buffer_ranges,
        issues,
    }
}

fn intersects(a: &Range<u32>, b: &Range<u32>) -> bool {
    a.start < b.end && b.start < a.end
}

fn merge_ranges(mut ranges: Vec<Range<u32>>) -> (Vec<Range<u32>>, bool) {
    ranges.sort_unstable_by_key(|range| range.start);
    let mut merged: Vec<Range<u32>> = Vec::with_capacity(ranges.len());
    let mut overlap = false;
    for range in ranges {
        if let Some(previous) = merged
            .last_mut()
            .filter(|previous| previous.end >= range.start)
        {
            overlap |= previous.end > range.start;
            previous.end = previous.end.max(range.end);
        } else {
            merged.push(range);
        }
    }
    (merged, overlap)
}

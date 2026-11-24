//! Review supplied FMMU register reads for the planned byte-aligned LRD.
use super::{Binding, read_json};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{ops::Range, path::Path};

pub(super) const MAX_CHANNELS: usize = 16;
const MAX_FILE_BYTES: u64 = 64 * 1024;

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {
    pub(super) schema: u32,
    pub(super) devices: Vec<Station>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct Station {
    pub(crate) station_address: u16,
    pub(crate) count: Read<u8>,
    pub(crate) slots: Vec<Read<[u8; 16]>>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct Read<T> {
    pub(crate) wkc: u16,
    pub(crate) value: T,
}

#[derive(Serialize)]
pub(crate) struct Review {
    pub(super) source_sha256: String,
    layout_matches: bool,
    stations_match: Option<bool>,
    pub(super) valid: bool,
    pub(super) devices: Vec<Device>,
}

#[derive(Serialize)]
pub(crate) struct Device {
    position: usize,
    pub(super) station_address: u16,
    station_matches: Option<bool>,
    count: Read<u8>,
    slots: Vec<Slot>,
    pub(crate) issues: Vec<String>,
}

#[derive(Serialize)]
struct Slot {
    index: usize,
    read: Read<[u8; 16]>,
    mapping: Option<Mapping>,
}

#[derive(Serialize)]
pub(crate) struct Mapping {
    logical_start: u32,
    length: u16,
    logical_start_bit: u8,
    logical_stop_bit: u8,
    physical_start: u16,
    physical_start_bit: u8,
    pub(crate) read_enabled: bool,
    pub(crate) write_enabled: bool,
    pub(crate) active: bool,
}

impl Mapping {
    pub(crate) fn decode(raw: &[u8; 16]) -> Self {
        Self {
            logical_start: u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
            length: u16::from_le_bytes([raw[4], raw[5]]),
            logical_start_bit: raw[6] & 7,
            logical_stop_bit: raw[7] & 7,
            physical_start: u16::from_le_bytes([raw[8], raw[9]]),
            physical_start_bit: raw[10] & 7,
            read_enabled: raw[11] & 1 != 0,
            write_enabled: raw[11] & 2 != 0,
            active: raw[12] & 1 != 0,
        }
    }

    pub(crate) fn byte_aligned(&self) -> bool {
        (
            self.logical_start_bit,
            self.logical_stop_bit,
            self.physical_start_bit,
        ) == (0, 7, 0)
    }

    pub(crate) fn bit_ranges(&self) -> std::result::Result<(Range<u64>, Range<u64>), &'static str> {
        if self.length == 0 {
            return Err("active mapping has zero length");
        }
        let start_byte = u64::from(self.logical_start);
        let logical_start = start_byte * 8 + u64::from(self.logical_start_bit);
        let last_byte = start_byte + u64::from(self.length) - 1;
        let logical_end = last_byte * 8 + u64::from(self.logical_stop_bit) + 1;
        if logical_end <= logical_start {
            return Err("active mapping has an empty or reversed logical bit range");
        }
        if logical_end > (1u64 << 35) {
            return Err("active mapping exceeds the logical address space");
        }
        let physical_start =
            u64::from(self.physical_start) * 8 + u64::from(self.physical_start_bit);
        let physical_end = physical_start + (logical_end - logical_start);
        if physical_end > (1u64 << 19) {
            return Err("active mapping exceeds the physical address space");
        }
        Ok((logical_start..logical_end, physical_start..physical_end))
    }

    fn read_range(&self) -> std::result::Result<Option<Range<u64>>, &'static str> {
        if !self.active || !self.read_enabled {
            return Ok(None);
        }
        if self.length == 0 {
            return Err("active read mapping has zero length");
        }
        if !self.byte_aligned() {
            return Err("active read mapping is not byte aligned");
        }
        let start = u64::from(self.logical_start);
        let end = start + u64::from(self.length);
        if end > (1u64 << 32) {
            return Err("read mapping exceeds the logical address space");
        }
        if u32::from(self.physical_start) + u32::from(self.length) > (1u32 << 16) {
            return Err("read mapping exceeds the physical address space");
        }
        Ok(Some(start..end))
    }
}

pub(super) fn review(path: &Path, bindings: &[Binding]) -> Result<Review> {
    let (snapshot, bytes) = read_json::<Snapshot>(path, MAX_FILE_BYTES)?;
    review_snapshot(snapshot, hex::encode(Sha256::digest(&bytes)), bindings)
}

pub(crate) fn load_station(path: &Path, address: u16) -> Result<(String, usize, Station)> {
    let (snapshot, bytes) = read_json::<Snapshot>(path, MAX_FILE_BYTES)?;
    ensure!(
        snapshot.schema == 1,
        "unsupported group FMMU schema {}",
        snapshot.schema
    );
    let stations: Vec<_> = snapshot
        .devices
        .iter()
        .map(|device| device.station_address)
        .collect();
    ensure!(
        (1..=super::MAX_DEVICES).contains(&stations.len()),
        "FMMU snapshot needs 1 to {} stations",
        super::MAX_DEVICES
    );
    super::validate_stations(&stations, stations.len())?;
    let (position, station) = snapshot
        .devices
        .into_iter()
        .enumerate()
        .find(|(_, station)| station.station_address == address)
        .with_context(|| format!("station {address:#06x} is absent from the FMMU snapshot"))?;
    ensure!(
        station.slots.len() <= MAX_CHANNELS,
        "station has more than {MAX_CHANNELS} FMMU slots"
    );
    Ok((hex::encode(Sha256::digest(&bytes)), position, station))
}

pub(super) fn review_snapshot(
    snapshot: Snapshot,
    source_sha256: String,
    bindings: &[Binding],
) -> Result<Review> {
    ensure!(
        snapshot.schema == 1,
        "unsupported group FMMU schema {}",
        snapshot.schema
    );
    let stations: Vec<_> = snapshot
        .devices
        .iter()
        .map(|device| device.station_address)
        .collect();
    super::validate_stations(&stations, bindings.len())?;
    let devices = snapshot
        .devices
        .into_iter()
        .zip(bindings)
        .enumerate()
        .map(|(position, (station, binding))| {
            ensure!(
                station.slots.len() <= MAX_CHANNELS,
                "position {position} has more than {MAX_CHANNELS} FMMU slots"
            );
            let expected = binding
                .offset
                .map(|start| start as u64..(start + binding.profile.tx_bytes) as u64);
            Ok(check(station, position, expected))
        })
        .collect::<Result<Vec<_>>>()?;
    let layout_matches = devices.iter().all(|device| device.issues.is_empty());
    Ok(Review {
        source_sha256,
        layout_matches,
        stations_match: None,
        valid: layout_matches,
        devices,
    })
}

impl Review {
    pub(super) fn compare_stations(&mut self, stations: &[u16]) {
        debug_assert_eq!(self.devices.len(), stations.len());
        for (device, &station) in self.devices.iter_mut().zip(stations) {
            device.station_matches = Some(device.station_address == station);
        }
        let matches = self
            .devices
            .iter()
            .all(|device| device.station_matches == Some(true));
        self.stations_match = Some(matches);
        self.valid = self.layout_matches && matches;
    }
}

impl Device {
    pub(super) fn read_mappings(
        &self,
    ) -> impl Iterator<Item = (usize, Range<u64>, Range<u32>)> + '_ {
        self.slots.iter().filter_map(|slot| {
            let mapping = slot.mapping.as_ref()?;
            let logical = mapping.read_range().ok().flatten()?;
            let start = u32::from(mapping.physical_start);
            let physical = start..start + u32::from(mapping.length);
            Some((slot.index, logical, physical))
        })
    }

    pub(super) fn physical_read_ranges(&self) -> Vec<(usize, Range<u32>)> {
        self.read_mappings()
            .map(|(index, _, physical)| (index, physical))
            .collect()
    }
}

impl Station {
    pub(crate) fn count_issues(&self) -> Vec<String> {
        let mut issues = Vec::new();
        if self.count.wkc != 1 {
            issues.push(format!("FMMU count WKC {}, expected 1", self.count.wkc));
        } else if usize::from(self.count.value) > MAX_CHANNELS {
            issues.push(format!(
                "FMMU count {} exceeds {MAX_CHANNELS}",
                self.count.value
            ));
        } else if usize::from(self.count.value) != self.slots.len() {
            issues.push(format!(
                "ESC reports {} slots, snapshot contains {}",
                self.count.value,
                self.slots.len()
            ));
        }
        issues
    }
}

pub(crate) fn check(station: Station, position: usize, expected: Option<Range<u64>>) -> Device {
    let mut issues = station.count_issues();
    let mut spans = Vec::new();
    let slots = station
        .slots
        .into_iter()
        .enumerate()
        .map(|(index, read)| {
            let mapping = if read.wkc == 1 {
                let mapping = Mapping::decode(&read.value);
                match mapping.read_range() {
                    Ok(Some(range)) => spans.push((index, range)),
                    Ok(None) => {}
                    Err(reason) => issues.push(format!("FMMU {index}: {reason}")),
                }
                Some(mapping)
            } else {
                issues.push(format!("FMMU {index} WKC {}, expected 1", read.wkc));
                None
            };
            Slot {
                index,
                read,
                mapping,
            }
        })
        .collect();

    if let Some(expected) = expected {
        spans.sort_unstable_by_key(|(_, range)| range.start);
        let mut next = expected.start;
        for (index, span) in spans {
            if span.start < expected.start || span.end > expected.end {
                issues.push(format!(
                    "FMMU {index} read range {}..{} lies outside planned input {}..{}",
                    span.start, span.end, expected.start, expected.end
                ));
                continue;
            }
            if span.start < next {
                issues.push(format!(
                    "FMMU {index} overlaps another logical input mapping at byte {}",
                    span.start
                ));
            } else if span.start > next {
                issues.push(format!(
                    "unmapped logical input bytes {next}..{}",
                    span.start
                ));
            }
            next = next.max(span.end);
        }
        if next < expected.end {
            issues.push(format!(
                "unmapped logical input bytes {next}..{}",
                expected.end
            ));
        }
    } else if !spans.is_empty() {
        issues.push("active read mapping on a position with no planned input".into());
    }
    Device {
        position,
        station_address: station.station_address,
        station_matches: None,
        count: station.count,
        slots,
        issues,
    }
}

//! Compare a register projection with the configured logical mapping saved for one station.
use crate::input_group::fmmu::{Mapping, Station, load_station};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{ops::Range, path::Path};

#[derive(Serialize)]
pub(super) struct Evidence {
    file_name: String,
    sha256: String,
    position: usize,
    pub(super) station_address: u16,
    reported_slots: u8,
    captured_slots: usize,
    identity_binding: &'static str,
    issues: Vec<String>,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum Check {
    Matched {
        slot: usize,
        physical_start: u16,
        logical_start: u32,
        byte_count: usize,
    },
    MatchedSplit {
        physical_start: u16,
        byte_count: usize,
        segments: Vec<Segment>,
    },
    MatchedBits {
        physical_start: u16,
        byte_count: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        width_bits: Option<usize>,
        segments: Vec<BitSegment>,
    },
    MatchedEntries {
        width_bits: usize,
        byte_count: usize,
        segments: Vec<BitSegment>,
    },
    Unmapped {
        reason: String,
    },
    Conflict {
        reason: String,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Serialize)]
pub(super) struct Segment {
    slot: usize,
    pub(super) projection_byte_offset: usize,
    physical_start: u16,
    pub(super) logical_start: u32,
    pub(super) byte_count: usize,
}

#[derive(Clone, Serialize)]
pub(super) struct BitSegment {
    slot: usize,
    pub(super) projection_bit_offset: usize,
    physical_start_bit: u64,
    pub(super) logical_start_bit: u64,
    pub(super) bit_count: usize,
}

impl BitSegment {
    fn from_bytes(slot: usize, physical_start: u16, logical_start: u32, byte_count: usize) -> Self {
        Self {
            slot,
            projection_bit_offset: 0,
            physical_start_bit: u64::from(physical_start) * 8,
            logical_start_bit: u64::from(logical_start) * 8,
            bit_count: byte_count * 8,
        }
    }

    fn byte_segment(&self) -> Option<Segment> {
        (self.projection_bit_offset.is_multiple_of(8)
            && self.physical_start_bit.is_multiple_of(8)
            && self.logical_start_bit.is_multiple_of(8)
            && self.bit_count.is_multiple_of(8))
        .then_some(Segment {
            slot: self.slot,
            projection_byte_offset: self.projection_bit_offset / 8,
            physical_start: (self.physical_start_bit / 8) as u16,
            logical_start: (self.logical_start_bit / 8) as u32,
            byte_count: self.bit_count / 8,
        })
    }
}

impl Check {
    pub(super) fn combine(checks: &[Self]) -> Self {
        let mut segments = Vec::new();
        let mut width_bits = 0;
        for (entry, check) in checks.iter().enumerate() {
            let start = segments.len();
            match check {
                Self::Matched {
                    slot,
                    physical_start,
                    logical_start,
                    byte_count,
                } => {
                    segments.push(BitSegment::from_bytes(
                        *slot,
                        *physical_start,
                        *logical_start,
                        *byte_count,
                    ));
                }
                Self::MatchedSplit {
                    segments: bytes, ..
                } => segments.extend(bytes.iter().map(|segment| {
                    let mut bits = BitSegment::from_bytes(
                        segment.slot,
                        segment.physical_start,
                        segment.logical_start,
                        segment.byte_count,
                    );
                    bits.projection_bit_offset = segment.projection_byte_offset * 8;
                    bits
                })),
                Self::MatchedBits { segments: bits, .. }
                | Self::MatchedEntries { segments: bits, .. } => {
                    segments.extend_from_slice(bits);
                }
                Self::Unmapped { reason }
                | Self::Conflict { reason }
                | Self::Unavailable { reason } => {
                    return Self::Unavailable {
                        reason: format!(
                            "ESI entry {} has unavailable FMMU placement ({reason})",
                            entry + 1
                        ),
                    };
                }
            }
            for segment in &mut segments[start..] {
                segment.projection_bit_offset += width_bits;
            }
            width_bits += segments[start..]
                .iter()
                .map(|segment| segment.bit_count)
                .sum::<usize>();
        }
        Self::MatchedEntries {
            width_bits,
            byte_count: width_bits.div_ceil(8),
            segments,
        }
    }
}

struct ActiveMapping {
    slot: usize,
    mapping: Mapping,
    logical: Range<u64>,
    physical: Range<u64>,
}

#[derive(Serialize)]
pub(super) struct Contributions {
    pub(super) derived_expected_wkc: Option<u16>,
    pub(super) declared_expected_wkc: Option<u16>,
    stations: Vec<StationContribution>,
}

#[derive(Serialize)]
struct StationContribution {
    station_address: u16,
    contributes: Option<bool>,
    read_ranges: Vec<LogicalRead>,
    issues: Vec<String>,
}

#[derive(Serialize)]
struct LogicalRead {
    slot: usize,
    start_bit: u64,
    end_bit_exclusive: u64,
}

impl Contributions {
    pub(super) fn other_reader(&self, selected: u16, logical: &Range<u64>) -> Option<u16> {
        self.stations
            .iter()
            .find(|station| {
                station.station_address != selected
                    && station.read_ranges.iter().any(|range| {
                        range.start_bit < logical.end && logical.start < range.end_bit_exclusive
                    })
            })
            .map(|station| station.station_address)
    }
}

struct StationMappings {
    address: u16,
    issues: Vec<String>,
    active: Vec<ActiveMapping>,
}

impl StationMappings {
    fn decode(station: &Station) -> Self {
        let mut issues = station.count_issues();
        let mut active = Vec::new();
        for (slot, read) in station.slots.iter().enumerate() {
            if read.wkc != 1 {
                issues.push(format!("FMMU {slot} WKC {}, expected 1", read.wkc));
                continue;
            }
            let mapping = Mapping::decode(&read.value);
            if mapping.active && (mapping.read_enabled || mapping.write_enabled) {
                match mapping.bit_ranges() {
                    Ok((logical, physical)) => active.push(ActiveMapping {
                        slot,
                        mapping,
                        logical,
                        physical,
                    }),
                    Err(reason) => issues.push(format!("FMMU {slot}: {reason}")),
                }
            }
        }
        Self {
            address: station.station_address,
            issues,
            active,
        }
    }

    fn contribution(&self, logical: &Range<u64>) -> StationContribution {
        let read_ranges: Vec<_> = self
            .active
            .iter()
            .filter(|slot| slot.mapping.read_enabled && overlaps(&slot.logical, logical))
            .map(|slot| LogicalRead {
                slot: slot.slot,
                start_bit: slot.logical.start.max(logical.start),
                end_bit_exclusive: slot.logical.end.min(logical.end),
            })
            .collect();
        StationContribution {
            station_address: self.address,
            contributes: self.issues.is_empty().then_some(!read_ranges.is_empty()),
            read_ranges,
            issues: self.issues.clone(),
        }
    }
}

pub(super) struct Table {
    pub(super) evidence: Evidence,
    pub(super) stations: Vec<u16>,
    decoded: Vec<StationMappings>,
}

impl Table {
    pub(super) fn load(path: &Path, address: u16) -> Result<Self> {
        ensure!(address != 0, "FMMU station address must be nonzero");
        let saved = load_station(path, address)?;
        let station = &saved.devices[saved.position];
        let decoded: Vec<_> = saved.devices.iter().map(StationMappings::decode).collect();
        Ok(Self {
            evidence: Evidence {
                file_name: path
                    .file_name()
                    .context("FMMU snapshot has no file name")?
                    .to_string_lossy()
                    .into_owned(),
                sha256: saved.sha256,
                position: saved.position,
                station_address: address,
                reported_slots: station.count.value,
                captured_slots: station.slots.len(),
                identity_binding: "absent_from_snapshot",
                issues: decoded[saved.position].issues.clone(),
            },
            stations: saved.stations,
            decoded,
        })
    }

    pub(super) fn contributions(
        &self,
        logical_start: u32,
        byte_count: usize,
        declared: Option<u16>,
    ) -> Contributions {
        let start = u64::from(logical_start) * 8;
        let logical = start..start + byte_count as u64 * 8;
        let stations: Vec<_> = self
            .decoded
            .iter()
            .map(|station| station.contribution(&logical))
            .collect();
        let derived_expected_wkc = stations.iter().try_fold(0u16, |count, station| {
            station
                .contributes
                .map(|contributes| count + u16::from(contributes))
        });
        Contributions {
            derived_expected_wkc,
            declared_expected_wkc: declared,
            stations,
        }
    }

    pub(super) fn compare(&self, physical: Range<usize>) -> Check {
        if !self.evidence.issues.is_empty() {
            return Check::Unavailable {
                reason: "selected station has incomplete or invalid FMMU evidence".into(),
            };
        }
        let register = (physical.start / 8) as u16;
        let width_bits = physical.len();
        let width = width_bits.div_ceil(8);
        let physical = physical.start as u64..physical.end as u64;
        let active = &self.decoded[self.evidence.position].active;
        let mut physical_hits: Vec<_> = active
            .iter()
            .filter(|slot| overlaps(&slot.physical, &physical))
            .collect();
        if physical_hits.is_empty() {
            return Check::Unmapped {
                reason: "no active FMMU covers the register range".into(),
            };
        }
        physical_hits.sort_unstable_by_key(|slot| (slot.physical.start, slot.slot));
        let mut segments = Vec::with_capacity(physical_hits.len());
        let mut next = physical.start;
        for slot in &physical_hits {
            let covered =
                slot.physical.start.max(physical.start)..slot.physical.end.min(physical.end);
            if covered.start < next {
                return Check::Conflict {
                    reason: format!(
                        "multiple active FMMUs {:?} overlap the projected register range",
                        physical_hits
                            .iter()
                            .map(|slot| slot.slot)
                            .collect::<Vec<_>>()
                    ),
                };
            }
            if !slot.mapping.read_enabled || slot.mapping.write_enabled {
                return Check::Conflict {
                    reason: format!(
                        "FMMU {} covering the register range is write-enabled",
                        slot.slot
                    ),
                };
            }
            if covered.start > next {
                break;
            }

            let logical_start = slot.logical.start + (covered.start - slot.physical.start);
            let logical = logical_start..logical_start + (covered.end - covered.start);
            if let Some(other) = active.iter().find(|other| {
                other.slot != slot.slot
                    && other.mapping.read_enabled
                    && overlaps(&other.logical, &logical)
            }) {
                return Check::Conflict {
                    reason: format!(
                        "FMMU {} overlaps FMMU {} in the projected logical read range",
                        other.slot, slot.slot
                    ),
                };
            }
            segments.push(BitSegment {
                slot: slot.slot,
                projection_bit_offset: (covered.start - physical.start) as usize,
                physical_start_bit: covered.start,
                logical_start_bit: logical.start,
                bit_count: (covered.end - covered.start) as usize,
            });
            next = covered.end;
        }

        if next < physical.end {
            let reason = match physical_hits.as_slice() {
                [slot] => format!(
                    "FMMU {} only partially covers the register range",
                    slot.slot
                ),
                _ if !next.is_multiple_of(8) => format!(
                    "active FMMUs leave a gap at projected register bit {:#06x}.{}",
                    next / 8,
                    next % 8,
                ),
                _ => format!(
                    "active FMMUs leave a gap at projected register byte {:#06x}",
                    next / 8
                ),
            };
            return Check::Conflict { reason };
        }
        for slot in physical_hits {
            if let Some(other) = active.iter().find(|other| {
                other.slot != slot.slot
                    && other.mapping.read_enabled
                    && (!slot.mapping.byte_aligned() || !other.mapping.byte_aligned())
                    && !separated_by_three_bytes(&slot.logical, &other.logical)
            }) {
                return Check::Conflict {
                    reason: format!(
                        "FMMU {} and FMMU {} need three unused logical bytes between same-station bitwise read mappings",
                        slot.slot, other.slot
                    ),
                };
            }
        }
        let Some(byte_segments) = segments
            .iter()
            .map(BitSegment::byte_segment)
            .collect::<Option<Vec<_>>>()
        else {
            return Check::MatchedBits {
                physical_start: register,
                byte_count: width,
                width_bits: (!width_bits.is_multiple_of(8)).then_some(width_bits),
                segments,
            };
        };
        if let [segment] = byte_segments.as_slice() {
            return Check::Matched {
                slot: segment.slot,
                physical_start: segment.physical_start,
                logical_start: segment.logical_start,
                byte_count: segment.byte_count,
            };
        }
        Check::MatchedSplit {
            physical_start: register,
            byte_count: width,
            segments: byte_segments,
        }
    }
}

fn overlaps(left: &Range<u64>, right: &Range<u64>) -> bool {
    left.start < right.end && right.start < left.end
}

fn separated_by_three_bytes(left: &Range<u64>, right: &Range<u64>) -> bool {
    left.end.div_ceil(8) + 3 <= right.start / 8 || right.end.div_ceil(8) + 3 <= left.start / 8
}

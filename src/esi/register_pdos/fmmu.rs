//! Compare a register projection with the configured logical mapping saved for one station.
use crate::input_group::fmmu::{Mapping, load_station};
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

struct ActiveMapping {
    slot: usize,
    mapping: Mapping,
    logical: Range<u64>,
    physical: Range<u64>,
}

pub(super) struct Table {
    pub(super) evidence: Evidence,
    active: Vec<ActiveMapping>,
}

impl Table {
    pub(super) fn load(path: &Path, address: u16) -> Result<Self> {
        ensure!(address != 0, "FMMU station address must be nonzero");
        let (sha256, position, station) = load_station(path, address)?;
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
        Ok(Self {
            evidence: Evidence {
                file_name: path
                    .file_name()
                    .context("FMMU snapshot has no file name")?
                    .to_string_lossy()
                    .into_owned(),
                sha256,
                position,
                station_address: address,
                reported_slots: station.count.value,
                captured_slots: station.slots.len(),
                identity_binding: "absent_from_snapshot",
                issues,
            },
            active,
        })
    }

    pub(super) fn compare(&self, register: u16, width: usize) -> Check {
        if !self.evidence.issues.is_empty() {
            return Check::Unavailable {
                reason: "selected station has incomplete or invalid FMMU evidence".into(),
            };
        }
        let start = u64::from(register) * 8;
        let physical = start..start + (width as u64) * 8;
        let physical_hits: Vec<_> = self
            .active
            .iter()
            .filter(|slot| overlaps(&slot.physical, &physical))
            .collect();
        let slot = match physical_hits.as_slice() {
            [] => {
                return Check::Unmapped {
                    reason: "no active FMMU covers the register range".into(),
                };
            }
            [slot] => slot,
            _ => {
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
        };

        if !slot.mapping.read_enabled || slot.mapping.write_enabled {
            return Check::Conflict {
                reason: format!(
                    "FMMU {} covering the register range is write-enabled",
                    slot.slot
                ),
            };
        }
        if !slot.mapping.byte_aligned() {
            return Check::Conflict {
                reason: format!("FMMU {} is not byte aligned", slot.slot),
            };
        }
        if slot.physical.start > physical.start || slot.physical.end < physical.end {
            return Check::Conflict {
                reason: format!(
                    "FMMU {} only partially covers the register range",
                    slot.slot
                ),
            };
        }

        let start = slot.logical.start + (physical.start - slot.physical.start);
        let logical = start..start + (physical.end - physical.start);
        if let Some(other) = self.active.iter().find(|other| {
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

        Check::Matched {
            slot: slot.slot,
            physical_start: register,
            logical_start: (logical.start / 8) as u32,
            byte_count: width,
        }
    }
}

fn overlaps(left: &Range<u64>, right: &Range<u64>) -> bool {
    left.start < right.end && right.start < left.end
}

//! Compare resolved module PDO candidates with a single device's saved setup readback.
use super::{
    PdoPreview, SlotPreview,
    profile::{PdoGroupAudit, PdoGroupPadding},
};
use crate::{
    benchmark::read_report_bytes_with_stop,
    esi::modular::ModulePdoGroup,
    model::Identity,
    pdo::{Layout, MappingSource, Pdo, SyncManager},
    pdo_catalog::Direction,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

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
struct ReportedLayout {
    source: Option<MappingSource>,
    layout: Layout,
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

#[derive(Debug, Serialize)]
pub(super) struct Comparison {
    pub(super) file_name: String,
    pub(super) sha256: String,
    pub(super) reported_backend: String,
    reported_serial: Option<u32>,
    tx: ObservedDirection,
    rx: ObservedDirection,
}

impl Comparison {
    fn direction(&self, direction: Direction) -> &ObservedDirection {
        match direction {
            Direction::Tx => &self.tx,
            Direction::Rx => &self.rx,
        }
    }

    pub(super) fn mapping_source(&self, direction: Direction) -> Option<MappingSource> {
        self.direction(direction).mapping_source
    }

    pub(super) fn module_pdo_groups(&self, direction: Direction) -> Option<&PdoGroupAudit> {
        self.direction(direction).module_pdo_groups.as_ref()
    }

    pub(super) fn require_group_agreement(&self) -> Result<()> {
        for direction in [Direction::Tx, Direction::Rx] {
            if let Some(groups) = self.module_pdo_groups(direction) {
                ensure!(
                    groups.errors.is_empty(),
                    "saved {direction:?} module PDO groups differ: {}",
                    groups.errors.join("; ")
                );
            }
        }
        Ok(())
    }

    pub(super) fn image_bytes(&self, direction: Direction) -> Result<usize> {
        let layout = self.direction(direction);
        layout.image_bytes.with_context(|| {
            format!(
                "saved {:?} PDO layout is unavailable: {}",
                direction,
                layout.unavailable.as_deref().unwrap_or("no image length")
            )
        })
    }
}

#[derive(Debug, Serialize)]
struct ObservedDirection {
    mapping_source: Option<MappingSource>,
    image_bytes: Option<usize>,
    unavailable: Option<String>,
    other_assignments: Vec<OtherAssignment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    module_pdo_groups: Option<PdoGroupAudit>,
}

#[derive(Debug, Serialize)]
struct OtherAssignment {
    pdo_index: u16,
    sync_manager: u8,
    bit: Option<usize>,
    entry_count: usize,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum State {
    Matched,
    DescriptorMismatch,
    Unassigned,
    Unavailable,
}

#[derive(Debug, Serialize)]
pub(super) struct Candidate {
    state: State,
    sync_manager: Option<u8>,
    sm_hint_matches: Option<bool>,
    bit: Option<usize>,
    observed_entry_count: Option<usize>,
    differences: Vec<EntryDifference>,
    assigned_exclusions: Vec<u16>,
}

impl Candidate {
    pub(super) fn matched_location(&self) -> Option<(usize, u8)> {
        match self.state {
            State::Matched => self.bit.zip(self.sync_manager),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize)]
struct EntryDifference {
    entry: usize,
    expected: Option<Descriptor>,
    observed: Option<Descriptor>,
}

#[derive(Debug, Serialize)]
struct Descriptor {
    object_index: u16,
    subindex: u8,
    width: u8,
}

impl From<u32> for Descriptor {
    fn from(value: u32) -> Self {
        Self {
            object_index: (value >> 16) as u16,
            subindex: (value >> 8) as u8,
            width: value as u8,
        }
    }
}

struct Assignment<'a> {
    sync_manager: u8,
    bit: Option<usize>,
    pdo: &'a Pdo,
}

struct CheckedDirection<'a> {
    report: ObservedDirection,
    assigned: BTreeMap<u16, Assignment<'a>>,
}

impl<'a> CheckedDirection<'a> {
    fn check(
        layout: Option<&'a ReportedLayout>,
        reason: Option<&str>,
        direction: Direction,
    ) -> Result<Self> {
        let Some(ReportedLayout { source, layout }) = layout else {
            return Ok(Self {
                report: ObservedDirection {
                    mapping_source: None,
                    image_bytes: None,
                    unavailable: Some(
                        reason
                            .unwrap_or("saved report has no PDO readback for this direction")
                            .into(),
                    ),
                    other_assignments: Vec::new(),
                    module_pdo_groups: None,
                },
                assigned: BTreeMap::new(),
            });
        };
        ensure!(
            reason.is_none(),
            "saved {:?} layout also declares unavailable readback",
            direction
        );
        ensure!(
            *source != Some(MappingSource::Esi),
            "saved {:?} layout is an ESI expectation",
            direction
        );
        let (entries, image_bytes) = layout
            .entries()
            .with_context(|| format!("check saved {:?} PDO layout", direction))?;
        let mut starts = BTreeMap::new();
        for entry in &entries {
            starts.entry(entry.pdo_index).or_insert(entry.bit);
        }
        let range = match direction {
            Direction::Tx => 0x1a00..=0x1bff,
            Direction::Rx => 0x1600..=0x17ff,
        };
        let mut assigned = BTreeMap::new();
        for sm in &layout.sync_managers {
            for pdo in &sm.pdos {
                ensure!(
                    range.contains(&pdo.index),
                    "saved PDO {:#06x} is outside the {:?} mapping range",
                    pdo.index,
                    direction
                );
                let assignment = Assignment {
                    sync_manager: sm.index,
                    bit: starts.get(&pdo.index).copied(),
                    pdo,
                };
                ensure!(
                    assigned.insert(pdo.index, assignment).is_none(),
                    "saved {:?} PDO {:#06x} is assigned to more than one SyncManager",
                    direction,
                    pdo.index
                );
            }
        }
        Ok(Self {
            report: ObservedDirection {
                mapping_source: *source,
                image_bytes: Some(image_bytes),
                unavailable: None,
                other_assignments: Vec::new(),
                module_pdo_groups: None,
            },
            assigned,
        })
    }

    fn audit_groups(
        &mut self,
        direction: Direction,
        slots: &[SlotPreview],
        groups: &[ModulePdoGroup],
    ) {
        if self.report.unavailable.is_some()
            || (groups.is_empty() && slots.iter().all(|slot| slot.module_pdo_group.is_none()))
        {
            return;
        }

        let mut members = Vec::new();
        for slot in slots {
            if let Some(group) = slot.module_pdo_group {
                members.extend(
                    slot.pdos
                        .iter()
                        .filter(|pdo| pdo.direction == direction)
                        .filter_map(|pdo| {
                            self.assigned
                                .get(&pdo.mapping.resolved)?
                                .bit
                                .map(|bit| (bit, group))
                        }),
                );
            }
        }
        members.sort_unstable_by_key(|&(bit, _)| bit);
        let mut group_order: Vec<_> = members.iter().map(|&(_, group)| group).collect();
        group_order.dedup();
        let mut errors = Vec::new();
        if let Some(pair) = group_order.windows(2).find(|pair| pair[0] > pair[1]) {
            errors.push(format!(
                "module PDO group {} precedes group {}",
                pair[0], pair[1]
            ));
        }

        let mut padding = Vec::new();
        for (group, declaration) in groups.iter().enumerate() {
            let index = match direction {
                Direction::Tx => declaration.tx_pdo,
                Direction::Rx => declaration.rx_pdo,
            };
            let Some(index) = index else {
                continue;
            };
            let assignment = self.assigned.get(&index);
            let bit = assignment.and_then(|pdo| pdo.bit);
            let width_bits = assignment.map(|pdo| {
                pdo.pdo
                    .entries
                    .iter()
                    .map(|entry| (entry & 0xff) as usize)
                    .sum::<usize>()
            });
            if let Some(pdo) = assignment
                && pdo.pdo.entries.iter().any(|entry| entry >> 8 != 0)
            {
                errors.push(format!("padding PDO {index:#06x} contains a mapped object"));
            }
            if let Some((bit, width_bits)) = bit.zip(width_bits) {
                if members.iter().any(|&(member_bit, member_group)| {
                    (member_group as usize <= group && member_bit >= bit)
                        || (member_group as usize > group && member_bit < bit)
                }) {
                    errors.push(format!(
                        "padding PDO {index:#06x} is outside the end of group {group}"
                    ));
                }
                if let Some(bytes) = declaration.alignment_bytes.filter(|&bytes| bytes > 0)
                    && !((bit + width_bits) as u64).is_multiple_of(u64::from(bytes) * 8)
                {
                    errors.push(format!(
                        "padding PDO {index:#06x} ends at bit {}, outside {bytes}-byte alignment",
                        bit + width_bits
                    ));
                }
            }
            padding.push(PdoGroupPadding {
                group,
                pdo_index: index,
                alignment_bytes: declaration.alignment_bytes,
                assigned: assignment.is_some(),
                bit,
                width_bits,
            });
        }
        self.report.module_pdo_groups = Some(PdoGroupAudit {
            group_order,
            padding,
            errors,
        });
    }

    fn finish(mut self) -> ObservedDirection {
        self.report.other_assignments = self
            .assigned
            .into_iter()
            .map(|(pdo_index, assignment)| OtherAssignment {
                pdo_index,
                sync_manager: assignment.sync_manager,
                bit: assignment.bit,
                entry_count: assignment.pdo.entries.len(),
            })
            .collect();
        self.report
    }

    fn compare(&mut self, candidate: &PdoPreview, observed: &BTreeSet<u16>) -> Candidate {
        let Some(assignment) = self.assigned.remove(&candidate.mapping.resolved) else {
            return Candidate {
                state: if self.report.unavailable.is_some() {
                    State::Unavailable
                } else {
                    State::Unassigned
                },
                sync_manager: None,
                sm_hint_matches: None,
                bit: None,
                observed_entry_count: None,
                differences: Vec::new(),
                assigned_exclusions: Vec::new(),
            };
        };
        let actual = &assignment.pdo.entries;
        let expected: Vec<_> = candidate
            .entries
            .iter()
            .map(|entry| {
                (u32::from(entry.object.resolved) << 16)
                    | (u32::from(entry.subindex) << 8)
                    | u32::from(entry.width)
            })
            .collect();
        let differences: Vec<_> = (0..expected.len().max(actual.len()))
            .filter_map(|entry| {
                let expected = expected.get(entry).copied();
                let observed = actual.get(entry).copied();
                (expected != observed).then(|| EntryDifference {
                    entry,
                    expected: expected.map(Descriptor::from),
                    observed: observed.map(Descriptor::from),
                })
            })
            .collect();
        Candidate {
            state: if differences.is_empty() {
                State::Matched
            } else {
                State::DescriptorMismatch
            },
            sync_manager: Some(assignment.sync_manager),
            sm_hint_matches: candidate
                .declared_sm
                .map(|hint| hint == assignment.sync_manager),
            bit: assignment.bit,
            observed_entry_count: Some(actual.len()),
            differences,
            assigned_exclusions: candidate
                .excludes
                .iter()
                .filter_map(|excluded| {
                    observed
                        .contains(&excluded.resolved)
                        .then_some(excluded.resolved)
                })
                .collect(),
        }
    }
}

pub(super) fn compare(
    path: &Path,
    identity: &Identity,
    inventory_serial: Option<u32>,
    slots: &mut [SlotPreview],
    groups: &[ModulePdoGroup],
) -> Result<Comparison> {
    let bytes = read_report_bytes_with_stop(path, None)?;
    let report: SavedReport =
        serde_json::from_slice(&bytes).context("parse saved run report for PDO comparison")?;
    let [device] = report.devices.as_slice() else {
        anyhow::bail!("saved run report must identify exactly one device");
    };
    ensure!(
        device.identity.as_ref() == Some(identity),
        "saved run device identity differs from the ESI selection"
    );
    ensure!(
        inventory_serial
            .zip(device.serial)
            .is_none_or(|(inventory, run)| inventory == run),
        "saved module inventory serial differs from the saved PDO run"
    );
    let readback = report
        .pdo_verification
        .as_ref()
        .map(|value| &value.readback);
    let tx = readback.and_then(|value| value.tx.as_ref());
    let rx = readback.and_then(|value| value.rx.as_ref());
    let mut checked_tx = CheckedDirection::check(
        tx,
        readback.and_then(|value| value.tx_unavailable.as_deref()),
        Direction::Tx,
    )?;
    let mut checked_rx = CheckedDirection::check(
        rx,
        readback.and_then(|value| value.rx_unavailable.as_deref()),
        Direction::Rx,
    )?;
    if let Some((tx, rx)) = tx.zip(rx) {
        ensure!(
            !tx.layout.sync_managers.iter().any(|tx_sm| rx
                .layout
                .sync_managers
                .iter()
                .any(|rx_sm| tx_sm.index == rx_sm.index)),
            "saved Tx and Rx PDO layouts share a SyncManager"
        );
    }
    checked_tx.audit_groups(Direction::Tx, slots, groups);
    checked_rx.audit_groups(Direction::Rx, slots, groups);
    let observed = checked_tx
        .assigned
        .keys()
        .chain(checked_rx.assigned.keys())
        .copied()
        .collect();
    for candidate in slots.iter_mut().flat_map(|slot| &mut slot.pdos) {
        candidate.saved_readback = Some(match candidate.direction {
            Direction::Tx => checked_tx.compare(candidate, &observed),
            Direction::Rx => checked_rx.compare(candidate, &observed),
        });
    }
    Ok(Comparison {
        file_name: path
            .file_name()
            .context("saved run report path has no file name")?
            .to_string_lossy()
            .into_owned(),
        sha256: hex::encode(Sha256::digest(&bytes)),
        reported_backend: report.backend,
        reported_serial: device.serial,
        tx: checked_tx.finish(),
        rx: checked_rx.finish(),
    })
}

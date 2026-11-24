//! Compose an offline PDO image from explicit assignment choices and resolved ESI definitions.
use super::{SlotPreview, readback};
use crate::{
    esi::modular::ModulePdoGroup,
    model::{EsiSource, Identity, MAX_PAYLOAD},
    pdo::{Entry, Layout, MappingSource, Pdo, SyncManager},
    pdo_catalog::Direction,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::Path,
};

const MAX_REQUEST_BYTES: u64 = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: u32,
    identity: Identity,
    tx: Vec<Assignment>,
    rx: Vec<Assignment>,
    #[serde(default)]
    tx_split_groups: Vec<SplitGroupPadding>,
    #[serde(default)]
    rx_split_groups: Vec<SplitGroupPadding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assignment {
    index: u16,
    sm: u8,
    entries: Option<Vec<ManualEntry>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManualEntry {
    object_index: u16,
    subindex: u8,
    width: u8,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum SplitGroupPadding {
    Assigned { group: u32, sm: u8, widths: Vec<u8> },
    Unassigned { group: u32 },
}

impl SplitGroupPadding {
    fn group(&self) -> u32 {
        match self {
            Self::Assigned { group, .. } | Self::Unassigned { group } => *group,
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct ExpectedLayout {
    file_name: String,
    sha256: String,
    tx: Image,
    rx: Image,
    #[serde(skip_serializing_if = "Option::is_none")]
    saved_comparison: Option<SavedComparison>,
}

#[derive(Debug, Serialize)]
struct Image {
    layout: Layout,
    image_bytes: usize,
    entries: Vec<Entry>,
    pdo_sources: Vec<PdoSource>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    split_groups: Vec<SplitGroupPadding>,
}

#[derive(Debug, Serialize)]
struct PdoSource {
    pdo_index: u16,
    sync_manager: u8,
    declared_sm: Option<u8>,
    group: Option<u32>,
    origin: Origin,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Origin {
    Device,
    DeviceVirtualTemplate,
    Module { slot: usize, module_ident: u32 },
    GroupPadding { alignment_bytes: u32 },
}

#[derive(Debug, Serialize)]
struct SavedComparison {
    tx: DirectionComparison,
    rx: DirectionComparison,
}

#[derive(Debug, Serialize)]
struct DirectionComparison {
    observed_bytes: Option<usize>,
    assignments_match: Option<bool>,
    unavailable: Option<String>,
}

enum CandidateEntries {
    Declared(Result<Vec<u32>>),
    Manual,
}

struct Candidate {
    origin: Origin,
    declared_sm: Option<u8>,
    group: Option<u32>,
    mandatory: bool,
    entries: CandidateEntries,
    excludes: Vec<u16>,
}

impl ExpectedLayout {
    pub(super) fn compare_saved(&mut self, readback: &readback::Comparison) {
        let compare = |direction, expected: &Image| {
            let (actual, observed_bytes, unavailable) = readback.observed_layout(direction);
            if actual.is_some()
                && expected.layout.mapping_source == MappingSource::EsiWithManualEntries
                && readback.mapping_source(direction) != Some(MappingSource::Coe)
            {
                return DirectionComparison {
                    observed_bytes,
                    assignments_match: None,
                    unavailable: Some(
                        "virtual PDO templates require saved CoE layout evidence".into(),
                    ),
                };
            }
            DirectionComparison {
                observed_bytes,
                assignments_match: actual.map(|layout| expected.layout.same_assignments(layout)),
                unavailable: unavailable.map(str::to_owned),
            }
        };
        self.saved_comparison = Some(SavedComparison {
            tx: compare(Direction::Tx, &self.tx),
            rx: compare(Direction::Rx, &self.rx),
        });
    }
}

pub(super) fn compose(
    path: &Path,
    esi: &EsiSource,
    slots: &[SlotPreview],
    groups: &[ModulePdoGroup],
) -> Result<ExpectedLayout> {
    let mut bytes = Vec::new();
    File::open(path)
        .context("open expected PDO layout request")?
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read expected PDO layout request")?;
    ensure!(
        bytes.len() as u64 <= MAX_REQUEST_BYTES,
        "expected PDO layout request exceeds 64 KiB"
    );
    let request: Request =
        serde_json::from_slice(&bytes).context("parse expected PDO layout request")?;
    ensure!(
        request.schema == 1,
        "unsupported expected PDO layout request schema"
    );
    ensure!(
        request.identity == esi.identity,
        "expected PDO layout request identity differs from selected ESI"
    );
    ensure!(
        request.tx.len() <= 512 && request.rx.len() <= 512,
        "too many expected PDO assignments"
    );
    let tx_sms: BTreeSet<_> = request.tx.iter().map(|assignment| assignment.sm).collect();
    ensure!(
        request
            .rx
            .iter()
            .all(|assignment| !tx_sms.contains(&assignment.sm)),
        "expected Tx and Rx assignments share a SyncManager"
    );

    let (tx, tx_exclusions) = compose_direction(
        Direction::Tx,
        &request.tx,
        esi,
        slots,
        groups,
        request.tx_split_groups,
    )
    .context("compose expected Tx PDO image")?;
    let (rx, rx_exclusions) = compose_direction(
        Direction::Rx,
        &request.rx,
        esi,
        slots,
        groups,
        request.rx_split_groups,
    )
    .context("compose expected Rx PDO image")?;
    let assigned: BTreeSet<_> = tx
        .pdo_sources
        .iter()
        .chain(&rx.pdo_sources)
        .map(|pdo| pdo.pdo_index)
        .collect();
    for (index, excluded) in tx_exclusions.into_iter().chain(rx_exclusions) {
        ensure!(
            !assigned.contains(&excluded),
            "PDO {index:#06x} excludes assigned PDO {excluded:#06x}"
        );
    }

    Ok(ExpectedLayout {
        file_name: path
            .file_name()
            .context("expected PDO layout request has no file name")?
            .to_string_lossy()
            .into_owned(),
        sha256: hex::encode(Sha256::digest(&bytes)),
        tx,
        rx,
        saved_comparison: None,
    })
}

fn candidate_descriptors(
    direction: Direction,
    esi: &EsiSource,
    slots: &[SlotPreview],
) -> BTreeMap<u16, Candidate> {
    let mut candidates: BTreeMap<_, _> = esi
        .pdo_catalog
        .iter()
        .filter(|pdo| pdo.direction == direction)
        .map(|pdo| {
            let is_template =
                pdo.virtual_pdo && pdo.entries.is_empty() && !pdo.fixed && !pdo.unsupported;
            let (origin, entries) = if is_template {
                (Origin::DeviceVirtualTemplate, CandidateEntries::Manual)
            } else {
                let descriptors = if pdo.virtual_pdo || pdo.unsupported {
                    Err(anyhow::anyhow!(
                        "virtual or vendor-dependent device PDO requires separate interpretation"
                    ))
                } else {
                    pdo.entries
                        .iter()
                        .map(|entry| {
                            let width = u8::try_from(entry.width)
                                .context("PDO entry exceeds the descriptor bit width")?;
                            Ok(descriptor(entry.index, entry.subindex, width))
                        })
                        .collect()
                };
                (Origin::Device, CandidateEntries::Declared(descriptors))
            };
            (
                pdo.index,
                Candidate {
                    origin,
                    declared_sm: pdo.default_sm,
                    group: esi.device_pdo_group,
                    mandatory: pdo.mandatory,
                    entries,
                    excludes: pdo.excludes.clone(),
                },
            )
        })
        .collect();
    for slot in slots {
        for pdo in slot.pdos.iter().filter(|pdo| pdo.direction == direction) {
            candidates.insert(
                pdo.mapping.resolved,
                Candidate {
                    origin: Origin::Module {
                        slot: slot.slot,
                        module_ident: slot.module_ident,
                    },
                    declared_sm: pdo.declared_sm,
                    group: slot.module_pdo_group,
                    mandatory: pdo.mandatory,
                    entries: CandidateEntries::Declared(Ok(pdo
                        .entries
                        .iter()
                        .map(|entry| descriptor(entry.object.resolved, entry.subindex, entry.width))
                        .collect())),
                    excludes: pdo.excludes.iter().map(|index| index.resolved).collect(),
                },
            );
        }
    }
    candidates
}

fn descriptor(index: u16, subindex: u8, width: u8) -> u32 {
    (u32::from(index) << 16) | (u32::from(subindex) << 8) | u32::from(width)
}

fn padding_index(group: &ModulePdoGroup, direction: Direction) -> Option<u16> {
    match direction {
        Direction::Tx => group.tx_pdo,
        Direction::Rx => group.rx_pdo,
    }
}

fn split_group_rules<'a>(
    chosen: &[(&Assignment, Candidate)],
    rules: &'a [SplitGroupPadding],
) -> Result<BTreeMap<u32, &'a SplitGroupPadding>> {
    let mut managers_by_group = BTreeMap::<_, BTreeSet<_>>::new();
    for (assignment, candidate) in chosen {
        let group = candidate
            .group
            .context("grouped image composition requires explicit group membership")?;
        managers_by_group
            .entry(group)
            .or_default()
            .insert(assignment.sm);
    }
    ensure!(
        chosen
            .windows(2)
            .all(|pair| pair[0].0.sm != pair[1].0.sm || pair[0].1.group <= pair[1].1.group),
        "expected assignments are out of PDO group order within a SyncManager"
    );
    let mut by_group = BTreeMap::new();
    for rule in rules {
        let group = rule.group();
        let managers = managers_by_group
            .get(&group)
            .filter(|managers| managers.len() > 1)
            .with_context(|| {
                format!("PDO group {group} is not split across SyncManagers in this direction")
            })?;
        ensure!(
            by_group.insert(group, rule).is_none(),
            "duplicate split-group padding choice for PDO group {group}"
        );
        if let SplitGroupPadding::Assigned { sm, widths, .. } = rule {
            ensure!(
                managers.contains(sm),
                "split-group padding for PDO group {group} requires a SyncManager containing one of its PDOs"
            );
            ensure!(
                !widths.is_empty() && widths.len() <= 255 && !widths.contains(&0),
                "split-group padding for PDO group {group} requires 1 to 255 nonzero entry widths"
            );
        }
    }
    for (group, managers) in managers_by_group {
        ensure!(
            managers.len() == 1 || by_group.contains_key(&group),
            "PDO group {group} spans SyncManagers and requires an explicit split-group padding choice"
        );
    }
    Ok(by_group)
}

fn compose_direction(
    direction: Direction,
    assignments: &[Assignment],
    esi: &EsiSource,
    slots: &[SlotPreview],
    groups: &[ModulePdoGroup],
    split_groups: Vec<SplitGroupPadding>,
) -> Result<(Image, Vec<(u16, u16)>)> {
    let mut candidates = candidate_descriptors(direction, esi, slots);
    let padding_indexes: BTreeSet<_> = groups
        .iter()
        .filter_map(|group| padding_index(group, direction))
        .collect();
    ensure!(
        assignments.iter().all(|assignment| assignment.sm < 16)
            && assignments.windows(2).all(|pair| pair[0].sm <= pair[1].sm),
        "expected SyncManagers must use ascending order and indexes below 16"
    );
    let range = match direction {
        Direction::Tx => 0x1a00..=0x1bff,
        Direction::Rx => 0x1600..=0x17ff,
    };
    let mut chosen = Vec::with_capacity(assignments.len());
    for assignment in assignments {
        let index = assignment.index;
        ensure!(
            range.contains(&index),
            "PDO {index:#06x} is outside this direction's mapping range"
        );
        ensure!(
            !padding_indexes.contains(&index),
            "padding PDO {index:#06x} is calculated from the group declaration"
        );
        let candidate = candidates.remove(&index).with_context(|| {
            format!("PDO {index:#06x} is unknown in this direction or is assigned more than once")
        })?;
        ensure!(
            !candidate.mandatory || candidate.declared_sm == Some(assignment.sm),
            "mandatory PDO {index:#06x} requires its declared SyncManager"
        );
        chosen.push((assignment, candidate));
    }
    for (&index, candidate) in &candidates {
        ensure!(
            !candidate.mandatory || padding_indexes.contains(&index),
            "mandatory PDO {index:#06x} is missing from the expected assignments"
        );
    }
    let group_rules = if !groups.is_empty()
        || !split_groups.is_empty()
        || chosen
            .iter()
            .any(|(_, candidate)| candidate.group.is_some())
    {
        split_group_rules(&chosen, &split_groups)?
    } else {
        BTreeMap::new()
    };

    let mut layout = Layout {
        mapping_source: MappingSource::Esi,
        sync_managers: Vec::new(),
    };
    let mut pdo_sources = Vec::new();
    let mut exclusions = Vec::new();
    let mut chosen = chosen.into_iter().peekable();
    let mut direction_bits = 0usize;
    while let Some((assignment, candidate)) = chosen.next() {
        let index = assignment.index;
        let sm = assignment.sm;
        if layout
            .sync_managers
            .last()
            .is_none_or(|manager| manager.index != sm)
        {
            // The PDO layout rounds up at each SyncManager boundary.
            direction_bits = direction_bits.div_ceil(8) * 8;
            layout.sync_managers.push(SyncManager {
                index: sm,
                configured_bytes: None,
                pdos: Vec::new(),
            });
        }
        let manager = layout
            .sync_managers
            .last_mut()
            .expect("SyncManager for selected PDO");
        let entries = match candidate.entries {
            CandidateEntries::Declared(descriptors) => {
                let descriptors =
                    descriptors.with_context(|| format!("read PDO {index:#06x} descriptors"))?;
                ensure!(
                    assignment.entries.is_none(),
                    "PDO {index:#06x} accepts manual entries only for an entryless virtual device template"
                );
                descriptors
            }
            CandidateEntries::Manual => {
                ensure!(
                    !esi.virtual_sync_managers.contains(&sm)
                        && !candidate
                            .declared_sm
                            .is_some_and(|declared| esi.virtual_sync_managers.contains(&declared)),
                    "PDO {index:#06x} references a virtual SyncManager that requires separate interpretation"
                );
                let manual = assignment.entries.as_deref().with_context(|| {
                    format!("virtual PDO {index:#06x} needs explicit manual entries")
                })?;
                ensure!(
                    (1..=255).contains(&manual.len()),
                    "virtual PDO {index:#06x} needs 1 to 255 manual entries"
                );
                layout.mapping_source = MappingSource::EsiWithManualEntries;
                manual
                    .iter()
                    .map(|entry| descriptor(entry.object_index, entry.subindex, entry.width))
                    .collect()
            }
        };
        ensure!(
            !entries.is_empty(),
            "expected PDO {index:#06x} has no entries"
        );
        direction_bits += entries
            .iter()
            .map(|entry| (entry & 0xff) as usize)
            .sum::<usize>();
        ensure!(
            direction_bits <= MAX_PAYLOAD * 8,
            "expected PDO image exceeds the payload limit"
        );
        manager.pdos.push(Pdo { index, entries });
        pdo_sources.push(PdoSource {
            pdo_index: index,
            sync_manager: sm,
            declared_sm: candidate.declared_sm,
            group: candidate.group,
            origin: candidate.origin,
        });
        exclusions.extend(
            candidate
                .excludes
                .into_iter()
                .map(|excluded| (index, excluded)),
        );

        if let Some(number) = candidate.group
            && chosen
                .peek()
                .is_none_or(|(assignment, next)| assignment.sm != sm || next.group != Some(number))
        {
            let group = groups.get(number as usize).with_context(|| {
                format!("ESI has no alignment declaration for PDO group {number}")
            })?;
            let alignment_bytes = group
                .alignment_bytes
                .filter(|&size| size != 0 && size as usize <= MAX_PAYLOAD)
                .with_context(|| {
                    format!("PDO group {number} needs a nonzero alignment within the payload limit")
                })?;
            let alignment_bits = alignment_bytes as usize * 8;
            let entries: Vec<u32> = match group_rules.get(&number) {
                Some(SplitGroupPadding::Assigned {
                    sm: owner, widths, ..
                }) if *owner == sm => {
                    let padding: usize = widths.iter().map(|&width| usize::from(width)).sum();
                    ensure!(
                        (direction_bits + padding).is_multiple_of(alignment_bits),
                        "split-group padding for PDO group {number} ends outside its {alignment_bytes}-byte boundary"
                    );
                    widths.iter().copied().map(u32::from).collect()
                }
                Some(_) => continue,
                None => {
                    let padding =
                        (alignment_bits - direction_bits % alignment_bits) % alignment_bits;
                    let mut entries = vec![255; padding / 255];
                    if !padding.is_multiple_of(255) {
                        entries.push((padding % 255) as u32);
                    }
                    entries
                }
            };
            if entries.is_empty() {
                continue;
            }
            let index = padding_index(group, direction)
                .with_context(|| format!("PDO group {number} needs a declared padding PDO"))?;
            direction_bits += entries.iter().map(|&width| width as usize).sum::<usize>();
            manager.pdos.push(Pdo { index, entries });
            pdo_sources.push(PdoSource {
                pdo_index: index,
                sync_manager: sm,
                declared_sm: None,
                group: Some(number),
                origin: Origin::GroupPadding { alignment_bytes },
            });
        }
    }
    let (entries, image_bytes) = layout.entries()?;
    Ok((
        Image {
            layout,
            image_bytes,
            entries,
            pdo_sources,
            split_groups,
        },
        exclusions,
    ))
}

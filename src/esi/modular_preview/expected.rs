//! Compose an offline PDO image from explicit assignment choices and resolved ESI definitions.
use super::{SlotPreview, readback};
use crate::{
    esi::modular::ModulePdoGroup,
    model::{EsiSource, Identity, MAX_PAYLOAD},
    pdo::{Entry, Layout, MappingSource, Pdo, SyncManager},
    pdo_catalog::{Assignment, Direction},
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

struct Candidate {
    origin: Origin,
    declared_sm: Option<u8>,
    group: Option<u32>,
    mandatory: bool,
    descriptors: Result<Vec<u32>>,
    excludes: Vec<u16>,
}

impl ExpectedLayout {
    pub(super) fn compare_saved(&mut self, readback: &readback::Comparison) {
        let compare = |direction, expected: &Image| {
            let (actual, observed_bytes, unavailable) = readback.observed_layout(direction);
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

    let (tx, tx_exclusions) = compose_direction(Direction::Tx, &request.tx, esi, slots, groups)
        .context("compose expected Tx PDO image")?;
    let (rx, rx_exclusions) = compose_direction(Direction::Rx, &request.rx, esi, slots, groups)
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
            (
                pdo.index,
                Candidate {
                    origin: Origin::Device,
                    declared_sm: pdo.default_sm,
                    group: esi.device_pdo_group,
                    mandatory: pdo.mandatory,
                    descriptors,
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
                    descriptors: Ok(pdo
                        .entries
                        .iter()
                        .map(|entry| descriptor(entry.object.resolved, entry.subindex, entry.width))
                        .collect()),
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

fn compose_direction(
    direction: Direction,
    assignments: &[Assignment],
    esi: &EsiSource,
    slots: &[SlotPreview],
    groups: &[ModulePdoGroup],
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
    let grouped = !groups.is_empty()
        || chosen
            .iter()
            .any(|(_, candidate)| candidate.group.is_some());
    if grouped && let Some((first, _)) = chosen.first() {
        ensure!(
            chosen
                .iter()
                .all(|(assignment, candidate)| assignment.sm == first.sm
                    && candidate.group.is_some()),
            "grouped image composition requires explicit group membership and one SyncManager per direction"
        );
        ensure!(
            chosen
                .windows(2)
                .all(|pair| pair[0].1.group <= pair[1].1.group),
            "expected assignments are out of PDO group order"
        );
    }

    let mut layout = Layout {
        mapping_source: MappingSource::Esi,
        sync_managers: Vec::new(),
    };
    let mut pdo_sources = Vec::new();
    let mut exclusions = Vec::new();
    let mut chosen = chosen.into_iter().peekable();
    let mut used_bits = 0usize;
    while let Some((assignment, candidate)) = chosen.next() {
        let index = assignment.index;
        let sm = assignment.sm;
        if layout
            .sync_managers
            .last()
            .is_none_or(|manager| manager.index != sm)
        {
            used_bits = 0;
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
        let entries = candidate
            .descriptors
            .with_context(|| format!("read PDO {index:#06x} descriptors"))?;
        ensure!(
            !entries.is_empty(),
            "expected PDO {index:#06x} has no entries"
        );
        used_bits += entries
            .iter()
            .map(|entry| (entry & 0xff) as usize)
            .sum::<usize>();
        ensure!(
            used_bits <= MAX_PAYLOAD * 8,
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
                .is_none_or(|(_, next)| next.group != Some(number))
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
            let padding = (alignment_bits - used_bits % alignment_bits) % alignment_bits;
            if padding == 0 {
                continue;
            }
            let index = padding_index(group, direction)
                .with_context(|| format!("PDO group {number} needs a declared padding PDO"))?;
            let mut entries = vec![255; padding / 255];
            if !padding.is_multiple_of(255) {
                entries.push((padding % 255) as u32);
            }
            used_bits += padding;
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
        },
        exclusions,
    ))
}

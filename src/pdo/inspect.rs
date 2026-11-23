//! Inspect one saved run's observed PDO assignment independently of ESI defaults.
use super::{Entry, Layout, MappingSource, SyncManager, saved};
use crate::{
    model::{Identity, PdoCapabilities, Profile},
    pdo_catalog::{self, Direction},
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{collections::BTreeMap, path::Path};

pub mod profile;

#[derive(Debug, Serialize)]
pub struct Inspection<'a> {
    schema: u32,
    #[serde(flatten)]
    evidence: saved::Evidence,
    identity: &'a Identity,
    esi_sha256: Option<&'a str>,
    pdo_capabilities: Option<&'a PdoCapabilities>,
    tx: Observed<'a>,
    rx: Observed<'a>,
}

#[derive(Debug, Serialize)]
struct Observed<'a> {
    mapping_source: Option<MappingSource>,
    image_bytes: Option<usize>,
    unavailable: Option<String>,
    expected_selection_matches: Option<bool>,
    sync_managers: Vec<SyncManager>,
    entries: Vec<ObservedEntry<'a>>,
    payload_hex: Option<String>,
}

#[derive(Debug, Serialize)]
struct ObservedEntry<'a> {
    #[serde(flatten)]
    geometry: Entry,
    esi_hint: Option<EsiHint<'a>>,
    raw_hex: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct EsiHint<'a> {
    name: &'a str,
    data_type: &'a str,
}

pub fn inspect<'a>(
    profile: &'a Profile,
    report: &Path,
    tx_payload: Option<&[u8]>,
    rx_payload: Option<&[u8]>,
) -> Result<Inspection<'a>> {
    let identity = profile
        .expected_identity
        .as_ref()
        .context("saved PDO inspection requires an expected profile identity")?;
    ensure!(
        profile
            .esi
            .as_ref()
            .is_none_or(|esi| &esi.identity == identity),
        "attached ESI identity differs from the expected profile identity"
    );
    let run = saved::Run::load(report, identity)?;
    let expected = profile
        .esi_pdo_selection
        .as_ref()
        .map(|selection| {
            let source = profile
                .esi
                .as_ref()
                .context("profile selection needs an ESI catalog")?;
            pdo_catalog::build(&source.pdo_catalog, selection)
        })
        .transpose()?;
    let tx = inspect_direction(
        profile,
        &run,
        Direction::Tx,
        tx_payload,
        expected.as_ref().map(|expected| &expected.tx_layout),
    )?;
    let rx = inspect_direction(
        profile,
        &run,
        Direction::Rx,
        rx_payload,
        expected.as_ref().map(|expected| &expected.rx_layout),
    )?;
    run.validate_sync_manager_separation()?;
    Ok(Inspection {
        schema: 1,
        evidence: run.evidence,
        identity,
        esi_sha256: profile.esi.as_ref().map(|esi| esi.sha256.as_str()),
        pdo_capabilities: profile
            .esi
            .as_ref()
            .and_then(|esi| esi.pdo_capabilities.as_ref()),
        tx,
        rx,
    })
}

fn inspect_direction<'a>(
    profile: &'a Profile,
    run: &saved::Run,
    direction: Direction,
    payload: Option<&[u8]>,
    expected: Option<&Layout>,
) -> Result<Observed<'a>> {
    let (reported, unavailable) = run.direction(direction);
    let Some(reported) = reported else {
        ensure!(
            payload.is_none(),
            "saved {direction:?} PDO readback is unavailable for payload inspection"
        );
        return Ok(Observed {
            mapping_source: None,
            image_bytes: None,
            unavailable: Some(
                unavailable
                    .unwrap_or("saved report has no PDO readback for this direction")
                    .into(),
            ),
            expected_selection_matches: None,
            sync_managers: Vec::new(),
            entries: Vec::new(),
            payload_hex: None,
        });
    };
    let (entries, image_bytes) = reported.checked_entries(direction, unavailable)?;
    if let Some(bytes) = payload {
        ensure!(
            bytes.len() == image_bytes,
            "saved {direction:?} PDO image requires {image_bytes} bytes, got {}",
            bytes.len()
        );
    }
    let mut hints = BTreeMap::new();
    for pdo in profile
        .esi
        .iter()
        .flat_map(|source| &source.pdo_catalog)
        .filter(|pdo| pdo.direction == direction && !pdo.virtual_pdo && !pdo.unsupported)
    {
        for entry in pdo.entries.iter().filter(|entry| entry.index != 0) {
            let hint = EsiHint {
                name: &entry.name,
                data_type: &entry.data_type,
            };
            hints
                .entry((entry.index, entry.subindex, entry.width))
                .and_modify(|previous| {
                    if *previous != Some(hint) {
                        *previous = None;
                    }
                })
                .or_insert(Some(hint));
        }
    }
    let entries = entries
        .into_iter()
        .map(|entry| {
            let esi_hint = hints
                .get(&(entry.object_index, entry.subindex, entry.width))
                .copied()
                .flatten();
            let raw_hex = payload
                .filter(|_| entry.object_index != 0)
                .map(|bytes| entry_hex(bytes, &entry));
            ObservedEntry {
                geometry: entry,
                esi_hint,
                raw_hex,
            }
        })
        .collect();
    Ok(Observed {
        mapping_source: reported.source,
        image_bytes: Some(image_bytes),
        unavailable: None,
        expected_selection_matches: expected
            .map(|expected| expected.same_assignments(&reported.layout)),
        sync_managers: reported.layout.sync_managers.clone(),
        entries,
        payload_hex: payload.map(hex::encode_upper),
    })
}

fn entry_hex(payload: &[u8], entry: &Entry) -> String {
    let mut bytes = [0u8; 32];
    for bit in 0..entry.width {
        let source = entry.bit + bit;
        let value = (payload[source / 8] >> (source % 8)) & 1;
        bytes[bit / 8] |= value << (bit % 8);
    }
    hex::encode_upper(&bytes[..entry.width.div_ceil(8)])
}

//! Build an offline decoder profile with geometry bound to saved PDO readback.
use super::{Observed, inspect};
use crate::{
    model::{Field, Identity, Kind, Profile, Source},
    pdo::{Layout, MappingSource, SyncManager, saved},
    pdo_catalog::Direction,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

#[derive(Clone, Debug)]
pub struct Choice {
    bit: usize,
    kind: Kind,
}

pub fn choice(text: &str) -> Result<Choice> {
    let (bit, kind) = text.split_once('=').context("expected BIT=KIND")?;
    let bit = bit.parse::<usize>().context("invalid field bit offset")?;
    let kind = match kind {
        "bool" => Kind::Bool,
        "unsigned" => Kind::Unsigned,
        "signed" => Kind::Signed,
        "f32" => Kind::F32,
        "f64" => Kind::F64,
        "raw" => Kind::Raw,
        _ => anyhow::bail!(
            "unknown field kind {kind:?}; use bool, unsigned, signed, f32, f64 or raw"
        ),
    };
    Ok(Choice { bit, kind })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub report_file_name: String,
    pub report_sha256: String,
    pub reported_backend: String,
    pub reported_serial: Option<u32>,
    pub identity: Identity,
    pub tx: Image,
    pub rx: Image,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Image {
    pub image_bytes: usize,
    pub mapping_source: Option<MappingSource>,
    pub sync_managers: Vec<SyncManager>,
    pub withheld_bits_at_export: Vec<usize>,
}

impl Provenance {
    pub(crate) fn validate(&self, profile: &Profile) -> Result<()> {
        ensure!(
            profile.expected_identity.as_ref() == Some(&self.identity)
                && profile
                    .esi
                    .as_ref()
                    .is_none_or(|esi| esi.identity == self.identity),
            "observed PDO decoder identity differs from the profile or attached ESI"
        );
        ensure!(
            profile.modular_decoder.is_none() && profile.esi_pdo_selection.is_none(),
            "an observed PDO decoder cannot carry a modular decoder or an ESI PDO selection"
        );
        ensure!(
            !self.report_file_name.is_empty()
                && self.report_sha256.len() == 64
                && self
                    .report_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "invalid observed PDO decoder report provenance"
        );
        saved::validate_sync_manager_separation(&self.tx.sync_managers, &self.rx.sync_managers)?;
        self.tx
            .validate(Direction::Tx, profile.tx_bytes, &profile.tx)?;
        self.rx
            .validate(Direction::Rx, profile.rx_bytes, &profile.rx)
    }
}

impl Image {
    fn validate(&self, direction: Direction, image_bytes: usize, fields: &[Field]) -> Result<()> {
        let reported = saved::ReportedLayout {
            source: self.mapping_source,
            layout: Layout {
                mapping_source: self.mapping_source.unwrap_or_default(),
                sync_managers: self.sync_managers.clone(),
            },
        };
        let (entries, bytes) = reported.checked_entries(direction, None)?;
        ensure!(
            bytes == self.image_bytes && bytes == image_bytes,
            "observed {direction:?} image length differs from saved PDO layout"
        );
        for field in fields {
            ensure!(
                entries.iter().any(|entry| {
                    entry.object_index != 0
                        && entry.bit == field.bit
                        && entry.width == field.width
                        && field.pdo_index == Some(entry.pdo_index)
                        && field.object_index == Some(entry.object_index)
                        && field.subindex == Some(entry.subindex)
                }),
                "field {} differs from saved {direction:?} PDO geometry",
                field.name
            );
        }
        ensure!(
            self.withheld_bits_at_export
                .windows(2)
                .all(|pair| pair[0] < pair[1])
                && self.withheld_bits_at_export.iter().all(|&bit| entries
                    .iter()
                    .any(|entry| entry.bit == bit && entry.object_index != 0)),
            "invalid {direction:?} withheld PDO offsets"
        );
        Ok(())
    }
}

pub fn build(
    baseline: &Profile,
    report: &Path,
    tx_choices: &[Choice],
    rx_choices: &[Choice],
) -> Result<Profile> {
    let inspected = inspect(baseline, report, None, None)?;
    let (tx_image, tx) = image(Direction::Tx, inspected.tx, tx_choices)?;
    let (rx_image, rx) = image(Direction::Rx, inspected.rx, rx_choices)?;
    ensure!(
        !tx.is_empty() || !rx.is_empty(),
        "saved PDO layout has no decodable fields; supply explicit field kinds"
    );
    let identity = inspected.identity.clone();
    let evidence = inspected.evidence;
    let profile = Profile {
        name: format!("{} · Observed PDO decoder", baseline.name),
        expected_identity: Some(identity.clone()),
        esi: baseline.esi.clone(),
        tx_bytes: tx_image.image_bytes,
        rx_bytes: rx_image.image_bytes,
        tx,
        rx,
        observed_decoder: Some(Provenance {
            report_file_name: evidence.file_name,
            report_sha256: evidence.sha256,
            reported_backend: evidence.reported_backend,
            reported_serial: evidence.reported_serial,
            identity,
            tx: tx_image,
            rx: rx_image,
        }),
        ..Profile::default()
    };
    profile.validate()?;
    Ok(profile)
}

fn image(
    direction: Direction,
    observed: Observed<'_>,
    choices: &[Choice],
) -> Result<(Image, Vec<Field>)> {
    let image_bytes = observed.image_bytes.with_context(|| {
        format!(
            "saved {direction:?} PDO layout is unavailable: {}",
            observed.unavailable.as_deref().unwrap_or("no image length")
        )
    })?;
    let mut by_bit = BTreeMap::new();
    for choice in choices {
        ensure!(
            by_bit.insert(choice.bit, choice.kind).is_none(),
            "duplicate {direction:?} kind choice for bit {}",
            choice.bit
        );
    }
    let mut fields = Vec::new();
    let mut withheld_bits_at_export = Vec::new();
    for entry in observed
        .entries
        .into_iter()
        .filter(|entry| entry.geometry.object_index != 0)
    {
        let geometry = entry.geometry;
        let hint_kind = entry
            .esi_hint
            .and_then(|hint| scalar_kind(hint.data_type, geometry.width));
        let manual = by_bit.remove(&geometry.bit);
        let Some(kind) = manual.or(hint_kind) else {
            withheld_bits_at_export.push(geometry.bit);
            continue;
        };
        let label = entry
            .esi_hint
            .map_or("Object", |hint| hint.name)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let field = Field {
            name: format!(
                "{label} [{:04X}/{:04X}:{:02X} @{}]",
                geometry.pdo_index, geometry.object_index, geometry.subindex, geometry.bit
            ),
            bit: geometry.bit,
            width: geometry.width,
            kind,
            log: direction == Direction::Tx,
            source: match (manual, hint_kind) {
                (Some(_), Some(_)) => Source::Override,
                (Some(_), None) => Source::Manual,
                (None, _) => Source::Esi,
            },
            pdo_index: Some(geometry.pdo_index),
            object_index: Some(geometry.object_index),
            subindex: Some(geometry.subindex),
            ..Field::default()
        };
        match field.validate() {
            Ok(()) => fields.push(field),
            Err(error) if manual.is_some() => return Err(error),
            Err(_) => withheld_bits_at_export.push(geometry.bit),
        }
    }
    if let Some(bit) = by_bit.keys().next() {
        anyhow::bail!(
            "{direction:?} kind choice at bit {bit} does not identify an observed non-padding entry"
        );
    }
    Ok((
        Image {
            image_bytes,
            mapping_source: observed.mapping_source,
            sync_managers: observed.sync_managers,
            withheld_bits_at_export,
        },
        fields,
    ))
}

pub(crate) fn scalar_kind(data_type: &str, width: usize) -> Option<Kind> {
    let kind = match (data_type, width) {
        ("BOOL" | "BIT", 1) => Kind::Bool,
        ("SINT", 8) | ("INT", 16) | ("DINT", 32) | ("LINT", 64) => Kind::Signed,
        ("USINT" | "BYTE", 8)
        | ("UINT" | "WORD", 16)
        | ("UDINT" | "DWORD", 32)
        | ("ULINT" | "LWORD", 64) => Kind::Unsigned,
        ("REAL" | "REAL32", 32) => Kind::F32,
        ("LREAL" | "REAL64", 64) => Kind::F64,
        _ => return None,
    };
    Some(kind)
}

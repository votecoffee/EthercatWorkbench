//! Reconstruct selected rows from the raw replay and match them to the saved CSV parts.
use super::{
    InputGroup, read_json,
    replay::{Options, PreparedReplay, prepare_capture},
};
use crate::{
    capture::{CaptureStats, METADATA, part_path, selects_sample},
    capture_audit::{MAX_BYTES, Part, inspect_part},
    model::LogMode,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const MAX_RECEIPT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
pub struct Evidence<'a> {
    pub fmmu: Option<&'a Path>,
    pub sync_managers: Option<&'a Path>,
    pub pdo: Option<&'a Path>,
}

#[derive(Deserialize)]
struct SavedReplay {
    schema: u32,
    source: String,
    fixture_sha256: String,
    mode: LogMode,
    rotate_rows: u64,
    capture: CaptureStats,
    error: Option<String>,
}

#[derive(Serialize)]
pub struct Audit {
    schema: u32,
    source: &'static str,
    receipt: PathBuf,
    pub(super) receipt_sha256: String,
    pub(super) fixture_sha256: String,
    csv_base: PathBuf,
    mode: LogMode,
    pub(super) expected_rows: u64,
    pub(super) verified_rows: u64,
    pub(super) complete: bool,
    capture_error: Option<String>,
    pub(super) parts: Vec<Part>,
    #[serde(skip)]
    pub(super) rotated: bool,
    #[serde(skip)]
    pub(super) evidence_hashes: [Option<String>; 3],
}

pub fn verify(
    group: &InputGroup,
    fixture: &Path,
    receipt: &Path,
    csv: &Path,
    evidence: Evidence<'_>,
) -> Result<Audit> {
    verify_with_layout(group, fixture, receipt, csv, evidence, None)
}

pub(super) fn verify_with_layout(
    group: &InputGroup,
    fixture: &Path,
    receipt: &Path,
    csv: &Path,
    evidence: Evidence<'_>,
    layout: Option<(u64, bool)>,
) -> Result<Audit> {
    ensure!(
        csv.extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("csv")),
        "CSV base must end in .csv"
    );
    let (saved, bytes) = read_json::<SavedReplay>(receipt, MAX_RECEIPT_BYTES)?;
    ensure!(
        saved.schema == 1 && saved.source == "offline_group_replay",
        "expected a schema 1 group replay receipt"
    );
    ensure!(
        layout
            .is_none_or(|(parts, rotated)| (parts, rotated)
                == (saved.capture.parts, saved.rotate_rows != 0)),
        "saved replay CSV layout differs from bundle inventory"
    );
    let prepared = prepare_capture(
        group,
        fixture,
        &Options {
            csv,
            mode: saved.mode,
            rotate_rows: saved.rotate_rows,
            fmmu: evidence.fmmu,
            sync_managers: evidence.sync_managers,
            pdo: evidence.pdo,
        },
    )?;
    ensure!(
        prepared.fixture_sha256 == saved.fixture_sha256,
        "fixture SHA-256 differs from replay receipt"
    );

    let indexes = expected_selection(&prepared);
    let expected_rows = indexes.len() as u64;
    let cap = &saved.capture;
    let complete = saved.error.is_none();
    ensure!(
        cap.utc_start == prepared.utc_start
            && cap.selected == expected_rows
            && cap.overruns == 0
            && cap.written <= expected_rows,
        "CSV capture counters or UTC anchor differ from replay evidence"
    );
    ensure!(
        !complete || cap.written == expected_rows,
        "complete replay receipt omits selected rows"
    );
    let rotate = saved.rotate_rows;
    let expected_parts = if rotate == 0 {
        1
    } else {
        cap.written.div_ceil(rotate).max(1)
    };
    let extra_header =
        !complete && rotate != 0 && cap.written > 0 && cap.written.is_multiple_of(rotate);
    ensure!(
        cap.parts == expected_parts || (extra_header && cap.parts == expected_parts + 1),
        "replay receipt part count differs from rotation and written rows"
    );

    let parts = verify_parts(csv, &prepared, &indexes, cap)?;
    let expected = prepared.into_report(saved.capture.clone(), saved.error.clone());
    let evidence_hashes = [
        expected.plan.fmmu.as_ref().map(|r| r.source_sha256.clone()),
        expected
            .plan
            .sync_managers
            .as_ref()
            .map(|r| r.source_sha256.clone()),
        expected.plan.pdo.as_ref().map(|r| r.source_sha256.clone()),
    ];
    let recorded: serde_json::Value =
        serde_json::from_slice(bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes))?;
    ensure!(
        serde_json::to_value(expected)? == recorded,
        "replay receipt differs from the rebuilt cycles, timing or profile/mapping evidence"
    );
    Ok(Audit {
        schema: 1,
        source: "group_replay_csv_audit",
        receipt: receipt.to_owned(),
        receipt_sha256: hex::encode(Sha256::digest(&bytes)),
        fixture_sha256: saved.fixture_sha256,
        csv_base: csv.to_owned(),
        mode: saved.mode,
        expected_rows,
        verified_rows: cap.written,
        complete,
        capture_error: saved.error,
        parts,
        rotated: rotate != 0,
        evidence_hashes,
    })
}

fn expected_selection(prepared: &PreparedReplay<'_>) -> Vec<usize> {
    let mut indexes = Vec::new();
    let mut previous = None;
    let profile = &prepared.profile;
    for (index, entry) in prepared.cycles.iter().enumerate() {
        if let Some(data) = entry.payload.as_deref() {
            let generation = entry.receipt.connection_generation;
            if selects_sample(profile.mode, &profile.tx, generation, data, previous) {
                indexes.push(index);
                previous = Some((generation, data));
            }
        }
    }
    indexes
}

fn verify_parts(
    base: &Path,
    prepared: &PreparedReplay<'_>,
    selection: &[usize],
    cap: &CaptureStats,
) -> Result<Vec<Part>> {
    let fields = &prepared.profile.tx;
    let header: Vec<_> = METADATA
        .into_iter()
        .chain(fields.iter().map(|field| field.name.as_str()))
        .collect();
    let rotate = prepared.profile.rotate_rows;
    let mut parts = Vec::new();
    let mut sample = 0;
    let mut bytes_left = MAX_BYTES;
    for index in 1..=cap.parts {
        let path = part_path(base, index, rotate)?;
        let part = inspect_part(&path, &header, bytes_left, None, |row_number, row| {
            (|| {
                ensure!(sample < cap.written, "CSV has extra rows");
                let entry = &prepared.cycles[selection[sample as usize]];
                let cycle = &entry.receipt;
                let data = entry.payload.as_deref().expect("selected replay input");
                let metadata = [
                    prepared.utc_start.clone(),
                    cycle
                        .elapsed_us
                        .expect("selected replay receive time")
                        .to_string(),
                    (sample + 1).to_string(),
                    cycle.connection_generation.to_string(),
                    cycle.cycle_index.to_string(),
                ];
                ensure!(
                    row.len() == header.len(),
                    "CSV row width differs from header"
                );
                for (column, expected) in metadata.iter().enumerate() {
                    ensure!(
                        &row[column] == expected,
                        "CSV {} differs from replay",
                        METADATA[column]
                    );
                }
                for (field, actual) in fields.iter().zip(row.iter().skip(METADATA.len())) {
                    let expected = field.decode(data).context("decode selected replay input")?;
                    ensure!(
                        expected == actual,
                        "CSV field {} differs from recorded input",
                        field.name
                    );
                }
                sample += 1;
                Ok(())
            })()
            .with_context(|| format!("data row {row_number}"))
        })
        .with_context(|| format!("CSV part {}", path.display()))?;
        let rows = if rotate == 0 {
            cap.written
        } else {
            cap.written.saturating_sub((index - 1) * rotate).min(rotate)
        };
        ensure!(
            part.rows == rows,
            "CSV part {} row count differs from replay rotation",
            path.display()
        );
        bytes_left -= part.bytes;
        parts.push(part);
    }
    ensure!(
        sample == cap.written,
        "CSV row count differs from replay receipt"
    );
    Ok(parts)
}

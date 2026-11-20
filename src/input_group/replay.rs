//! Replay saved group cycles into the bounded CSV writer using the recorded receive clock.
mod virtual_capture;
pub use virtual_capture::{VirtualScenario, generate_virtual};

use super::{
    AlRead, InputGroup, Inspection,
    clock_rehearsal::{ClockCheck, ClockFrames, ClockRecording},
    decode_al_reads, decode_frame_hex, read_json, validate_stations,
};
use crate::{
    capture::{Capture, CaptureStats},
    model::{LogMode, MAX_PAYLOAD, Profile},
    review::check_cancel,
    run::Spacing,
};
use anyhow::{Context, Result, ensure};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::atomic::AtomicBool};

const MAX_FIXTURE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CYCLES: usize = 4096;
const MAX_CANDIDATES: usize = 64;
pub(super) const MODELED_UTC: &str = "2026-01-01T00:00:00.000000Z";

pub struct Options<'a> {
    pub csv: &'a Path,
    pub mode: LogMode,
    pub rotate_rows: u64,
    pub fmmu: Option<&'a Path>,
    pub sync_managers: Option<&'a Path>,
    pub pdo: Option<&'a Path>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    pub(super) schema: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) virtual_scenario: Option<VirtualScenario>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) virtual_dc: Option<ClockRecording>,
    pub(super) capture_start_utc: String,
    pub(super) stations: Vec<u16>,
    pub(super) cycles: Vec<RecordedCycle>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordedCycle {
    pub(super) connection_generation: u64,
    pub(super) cycle_index: u64,
    pub(super) index: u8,
    pub(super) elapsed_us: Option<u64>,
    pub(super) received_hex: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) clock_frames: Option<ClockFrames>,
}

pub(super) struct PreparedCycle {
    pub(super) receipt: Cycle,
    pub(super) payload: Option<Vec<u8>>,
}

#[derive(Debug, Serialize)]
pub struct Cycle {
    pub connection_generation: u64,
    pub cycle_index: u64,
    index: u8,
    pub elapsed_us: Option<u64>,
    pub actual_wkc: Option<u16>,
    pub al: Vec<AlRead>,
    pub ignored_frames: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clock: Option<ClockCheck>,
    pub valid: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct Counts {
    pub cycles: usize,
    pub matched_replies: usize,
    pub valid: usize,
    pub unmatched_cycles: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clock_rejections: Option<usize>,
    pub wkc_mismatches: usize,
    pub invalid_al: usize,
    pub ignored_frames: usize,
}

#[derive(Debug, Serialize)]
pub struct ReplayDetails {
    pub utc_start: String,
    pub virtual_scenario: Option<VirtualScenario>,
    pub virtual_dc: Option<ClockRecording>,
    pub stations: Vec<u16>,
    pub expected_wkc: u16,
    pub counts: Counts,
    pub receive_spacing: Spacing,
    pub valid_receive_spacing: Spacing,
    pub cycles: Vec<Cycle>,
}

#[derive(Serialize)]
pub struct Report<'a> {
    schema: u32,
    source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    virtual_scenario: Option<VirtualScenario>,
    #[serde(skip_serializing_if = "Option::is_none")]
    virtual_dc: Option<ClockRecording>,
    fixture_sha256: String,
    stations: Vec<u16>,
    pub(super) plan: Inspection<'a>,
    mode: LogMode,
    rotate_rows: u64,
    queue_capacity: usize,
    counts: Counts,
    receive_spacing: Spacing,
    valid_receive_spacing: Spacing,
    capture: CaptureStats,
    cycles: Vec<Cycle>,
    pub error: Option<String>,
}

impl Report<'_> {
    pub(super) fn into_details(self) -> ReplayDetails {
        ReplayDetails {
            utc_start: self.capture.utc_start,
            virtual_scenario: self.virtual_scenario,
            virtual_dc: self.virtual_dc,
            stations: self.stations,
            expected_wkc: self.plan.expected_wkc,
            counts: self.counts,
            receive_spacing: self.receive_spacing,
            valid_receive_spacing: self.valid_receive_spacing,
            cycles: self.cycles,
        }
    }
}

pub(super) struct PreparedReplay<'a> {
    virtual_scenario: Option<VirtualScenario>,
    virtual_dc: Option<ClockRecording>,
    pub(super) utc_start: String,
    pub(super) fixture_sha256: String,
    stations: Vec<u16>,
    plan: Inspection<'a>,
    pub(super) profile: Profile,
    pub(super) cycles: Vec<PreparedCycle>,
}

pub fn run<'a>(group: &'a InputGroup, file: &Path, options: Options<'_>) -> Result<Report<'a>> {
    let prepared = prepare_capture(group, file, &options, None)?;
    let mut capture = Capture::start_replay(options.csv, &prepared.profile, &prepared.utc_start)?;
    for PreparedCycle { receipt, payload } in &prepared.cycles {
        if let Some(payload) = payload {
            let mut data = [0; MAX_PAYLOAD];
            data[..payload.len()].copy_from_slice(payload);
            capture.submit_elapsed(
                receipt
                    .elapsed_us
                    .expect("matched cycle has a receive timestamp"),
                receipt.connection_generation,
                receipt.cycle_index,
                &data,
            );
        }
    }
    let (capture, result) = capture.finish();
    let error = result
        .err()
        .map(|error| format!("CSV replay incomplete: {error:#}"));
    Ok(prepared.into_report(capture, error))
}

pub(super) fn prepare_capture<'a>(
    group: &'a InputGroup,
    file: &Path,
    options: &Options<'_>,
    stop: Option<&AtomicBool>,
) -> Result<PreparedReplay<'a>> {
    check_cancel(stop)?;
    let (fixture, bytes) = read_json::<Fixture>(file, MAX_FIXTURE_BYTES)?;
    check_cancel(stop)?;
    match (
        fixture.schema,
        &fixture.virtual_dc,
        fixture.virtual_scenario,
    ) {
        (1, None, _) => {}
        (2, Some(_), None) => ensure!(
            fixture.capture_start_utc == MODELED_UTC,
            "DC replay needs the authored UTC anchor"
        ),
        _ => ensure!(
            false,
            "unsupported group replay schema or source metadata {}",
            fixture.schema
        ),
    }
    let anchor = DateTime::parse_from_rfc3339(&fixture.capture_start_utc)
        .context("invalid group replay capture-start timestamp")?;
    ensure!(
        anchor.offset().local_minus_utc() == 0,
        "group replay capture start must use UTC"
    );
    ensure!(
        (1..=MAX_CYCLES).contains(&fixture.cycles.len()),
        "group replay requires 1–{MAX_CYCLES} cycles"
    );
    validate_stations(&fixture.stations, group.bindings.len())?;
    ensure!(
        options.sync_managers.is_none() || options.fmmu.is_some(),
        "SyncManager review requires FMMU evidence"
    );
    let mut plan = group.inspection(None, None);
    if let Some(fmmu) = options.fmmu {
        let mut mapping = group.load_mapping_evidence(fmmu, options.sync_managers, options.pdo)?;
        mapping.compare_stations(&fixture.stations);
        ensure!(
            mapping.valid(),
            "saved mapping evidence failed; review it with inspect-input-group before replay"
        );
        mapping.attach(&mut plan);
    } else {
        ensure!(
            options.pdo.is_none(),
            "TxPDO review requires FMMU and SyncManager evidence"
        );
    }

    let prepared = prepare(
        group,
        &fixture.stations,
        fixture.cycles,
        fixture.virtual_dc.as_ref(),
        stop,
    )?;
    let queue_capacity = prepared.len(); // At most one CSV row per supplied cycle.
    let profile = Profile {
        tx_bytes: group.input_bytes,
        tx: group
            .bindings
            .iter()
            .flat_map(|binding| {
                binding
                    .profile
                    .tx
                    .iter()
                    .filter(|field| field.log)
                    .map(|field| {
                        let mut combined = field.clone();
                        let offset = binding
                            .offset
                            .expect("validated TxPDO field has an input offset");
                        combined.bit += offset * 8;
                        combined.name =
                            format!("Position {} {}", binding.entry.position, field.name);
                        combined
                    })
            })
            .collect(),
        queue_capacity,
        rotate_rows: options.rotate_rows,
        mode: options.mode,
        ..Profile::default()
    };
    ensure!(
        !profile.tx.is_empty(),
        "select at least one TxPDO field for CSV"
    );
    Ok(PreparedReplay {
        virtual_scenario: fixture.virtual_scenario,
        virtual_dc: fixture.virtual_dc,
        utc_start: fixture.capture_start_utc,
        fixture_sha256: hex::encode(Sha256::digest(&bytes)),
        stations: fixture.stations,
        plan,
        profile,
        cycles: prepared,
    })
}

impl<'a> PreparedReplay<'a> {
    pub(super) fn into_report(self, capture: CaptureStats, error: Option<String>) -> Report<'a> {
        let mut counts = Counts {
            cycles: self.cycles.len(),
            clock_rejections: self.virtual_dc.as_ref().map(|_| 0),
            ..Counts::default()
        };
        let mut cycles = Vec::with_capacity(self.cycles.len());
        for PreparedCycle { receipt, .. } in self.cycles {
            counts.ignored_frames += receipt.ignored_frames;
            counts.valid += usize::from(receipt.valid);
            if let Some(wkc) = receipt.actual_wkc {
                counts.matched_replies += 1;
                counts.wkc_mismatches += usize::from(wkc != self.plan.expected_wkc);
                counts.invalid_al += usize::from(receipt.al.iter().any(|al| !al.clean_safeop));
            } else if receipt.clock.as_ref().is_some_and(|clock| !clock.valid) {
                *counts.clock_rejections.as_mut().expect("DC replay counts") += 1;
            } else {
                counts.unmatched_cycles += 1;
            }
            cycles.push(receipt);
        }
        Report {
            schema: 1,
            source: "offline_group_replay",
            virtual_scenario: self.virtual_scenario,
            virtual_dc: self.virtual_dc,
            fixture_sha256: self.fixture_sha256,
            stations: self.stations,
            plan: self.plan,
            mode: self.profile.mode,
            rotate_rows: self.profile.rotate_rows,
            queue_capacity: self.profile.queue_capacity,
            counts,
            receive_spacing: spacing(cycles.iter()),
            valid_receive_spacing: spacing(cycles.iter().filter(|cycle| cycle.valid)),
            capture,
            cycles,
            error,
        }
    }
}

fn prepare(
    group: &InputGroup,
    stations: &[u16],
    cycles: Vec<RecordedCycle>,
    dc: Option<&ClockRecording>,
    stop: Option<&AtomicBool>,
) -> Result<Vec<PreparedCycle>> {
    check_cancel(stop)?;
    let mut tracker = dc
        .map(|dc| dc.tracker(group, stations, cycles.len()))
        .transpose()?;
    let mut previous_cycle = (0, 0);
    let mut previous_received = None;
    cycles
        .into_iter()
        .enumerate()
        .map(|(position, cycle)| {
            check_cancel(stop)?;
            let label = position + 1;
            let order = (cycle.connection_generation, cycle.cycle_index);
            ensure!(
                order.0 > 0 && order.1 > 0 && order > previous_cycle,
                "replay cycle {label} needs positive, increasing generation/cycle order"
            );
            previous_cycle = order;
            ensure!(
                cycle.received_hex.len() <= MAX_CANDIDATES,
                "too many frame candidates in replay cycle {label}"
            );
            let clock = match (&mut tracker, cycle.clock_frames) {
                (Some(tracker), Some(frames)) => {
                    ensure!(
                        order == (1, label as u64) && cycle.index == tracker.input_slot(),
                        "DC replay cycle {label} does not match the authored generation or frame order"
                    );
                    let clock = tracker.inspect_recorded(frames)
                        .with_context(|| format!("DC replay cycle {label}"))?;
                    ensure!(
                        clock.valid || (cycle.received_hex.is_empty() && cycle.elapsed_us.is_none()),
                        "clock-rejected replay cycle {label} cannot carry an input reply or timestamp"
                    );
                    Some(clock)
                }
                (None, None) => None,
                _ => anyhow::bail!("unexpected or missing DC frames in replay cycle {label}"),
            };
            let expected = group.expected_frame(cycle.index, stations)?;
            let mut receipt = Cycle {
                connection_generation: order.0,
                cycle_index: order.1,
                index: cycle.index,
                elapsed_us: cycle.elapsed_us,
                actual_wkc: None,
                al: Vec::new(),
                ignored_frames: 0,
                clock,
                valid: false,
            };
            let mut payload = None;
            for (index, candidate) in cycle.received_hex.iter().enumerate() {
                check_cancel(stop)?;
                let bytes = decode_frame_hex(candidate)
                    .with_context(|| format!("replay cycle {label} candidate {}", index + 1))?;
                if let Some(parts) = expected.reply(&bytes) {
                    ensure!(
                        index + 1 == cycle.received_hex.len(),
                        "matching reply must be the final candidate in replay cycle {label}"
                    );
                    let (data, wkc) = parts[0];
                    receipt.actual_wkc = Some(wkc);
                    receipt.al = decode_al_reads(stations, &parts[1..]);
                    receipt.valid =
                        wkc == group.expected_wkc && receipt.al.iter().all(|al| al.clean_safeop);
                    if receipt.valid {
                        payload = Some(data.to_vec());
                    }
                } else {
                    receipt.ignored_frames += 1;
                }
            }
            ensure!(
                receipt.elapsed_us.is_some() == receipt.actual_wkc.is_some(),
                "replay cycle {label} needs elapsed_us exactly when a reply matches"
            );
            if let Some(received) = receipt.elapsed_us {
                ensure!(
                    dc.is_none_or(|dc| received == dc.modeled_elapsed_us(order.1)),
                    "replay cycle {label} timestamp differs from the authored SYNC0 schedule"
                );
                ensure!(
                    previous_received.is_none_or(|previous| received >= previous),
                    "recorded receive time regresses in replay cycle {label}"
                );
                previous_received = Some(received);
            }
            Ok(PreparedCycle { receipt, payload })
        })
        .collect()
}

fn spacing<'a>(cycles: impl Iterator<Item = &'a Cycle>) -> Spacing {
    let mut gaps = Vec::new();
    let mut previous = None;
    for (generation, at) in
        cycles.filter_map(|cycle| cycle.elapsed_us.map(|at| (cycle.connection_generation, at)))
    {
        if let Some((before_generation, before)) = previous
            && generation == before_generation
        {
            gaps.push(at - before);
        }
        previous = Some((generation, at));
    }
    gaps.sort_unstable();
    let percentile = |percent: usize| {
        let rank = (gaps.len() * percent).div_ceil(100usize);
        rank.checked_sub(1).map(|index| gaps[index])
    };
    Spacing {
        count: gaps.len() as u64,
        p50_us: percentile(50),
        p95_us: percentile(95),
        p99_us: percentile(99),
        longest_gap_us: gaps.last().copied(),
    }
}

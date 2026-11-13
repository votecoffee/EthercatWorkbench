//! Offline comparisons of saved runs. Saved counters are evidence, not hardware acceptance.
use crate::{
    capture::CaptureStats,
    model::{Identity, LogMode, Profile, Scheduler},
    run::{Mode, RunOptions, Spacing},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fs::File, io::Read, path::PathBuf, sync::atomic::AtomicBool};

const MAX_REPORT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frontend {
    Cli,
    Gui,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    Synthetic { faults: bool },
    Virtual { model: String, fault: String },
    Safeop,
    Replay { fixture: PathBuf },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunContext {
    pub schema: u32,
    pub app_version: String,
    pub frontend: Frontend,
    pub source: Source,
    pub profile: Profile,
    pub profile_sha256: String,
    pub comparison_sha256: String,
    pub duration_limit_us: u64,
    pub csv_enabled: bool,
}

pub(crate) fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

impl RunContext {
    pub fn new(profile: &Profile, options: &RunOptions) -> Result<Self> {
        let source = match &options.mode {
            Mode::Simulate { faults } => Source::Synthetic { faults: *faults },
            Mode::Virtual { model, fault } => Source::Virtual {
                model: format!("{model:?}"),
                fault: format!("{fault:?}"),
            },
            Mode::SafeOp { .. } => Source::Safeop,
            Mode::Replay { fixture } => Source::Replay {
                fixture: fixture.clone(),
            },
        };
        let (profile_sha256, comparison_sha256) = Self::hashes(profile)?;
        Ok(Self {
            schema: 1,
            app_version: env!("CARGO_PKG_VERSION").into(),
            frontend: options.frontend,
            source,
            profile: profile.clone(),
            profile_sha256,
            comparison_sha256,
            duration_limit_us: options.duration.as_micros().try_into()?,
            csv_enabled: options.csv.is_some(),
        })
    }

    fn hashes(profile: &Profile) -> Result<(String, String)> {
        let exact = hash(&serde_json::to_vec(profile)?);
        let mut common = profile.clone();
        common.scheduler = Scheduler::Deadline;
        Ok((exact, hash(&serde_json::to_vec(&common)?)))
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(self.schema == 1, "unsupported run-context schema");
        ensure!(!self.app_version.is_empty(), "missing application version");
        self.profile.validate()?;
        let (exact, common) = Self::hashes(&self.profile)?;
        ensure!(
            self.profile_sha256 == exact && self.comparison_sha256 == common,
            "run-context profile hash mismatch"
        );
        ensure!(
            (1..=86_400_000_000).contains(&self.duration_limit_us),
            "invalid run duration limit"
        );
        ensure!(self.csv_enabled, "run context requires enabled CSV logging");
        ensure!(
            self.profile.tx.iter().any(|field| field.log),
            "run context requires selected CSV fields"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ObservedDevice {
    position: u16,
    station_address: u16,
    alias: u16,
    link_ports: [bool; 4],
    identity: Option<Identity>,
    serial: Option<u32>,
    tx_bytes: Option<usize>,
    rx_bytes: Option<usize>,
}

#[derive(Deserialize)]
struct SavedRun {
    context: Option<RunContext>,
    #[serde(default)]
    cyclic_elapsed_us: u64,
    backend: String,
    scheduler: Scheduler,
    requested_cycle_us: u64,
    input_loss_timeout_ms: u64,
    connection_generation: u64,
    cycles: u64,
    replies: u64,
    valid: u64,
    timeouts: u64,
    missed_deadlines: u64,
    wkc_mismatches: u64,
    state_mismatches: u64,
    transport_errors: u64,
    ignored_frames: u64,
    expected_wkc: u16,
    send_spacing: Spacing,
    receive_spacing: Spacing,
    capture: Option<CaptureStats>,
    devices: Vec<ObservedDevice>,
    synchronization: Option<crate::sync::Synchronization>,
    pdo_verification: Option<Value>,
    stopped_al: Option<(u16, u16)>,
    cancelled: bool,
    error: Option<String>,
    http: Option<crate::http_feed::Stats>,
    mqtt: Option<crate::mqtt_feed::Stats>,
}

impl SavedRun {
    fn checked(&self) -> Result<(&RunContext, &CaptureStats)> {
        let ctx = self.context.as_ref().context(
            "report has no versioned run context; collect a new trial with Workbench 0.10 or later",
        )?;
        ctx.validate()?;
        ensure!(
            self.mqtt.is_some() == ctx.profile.mqtt.is_some(),
            "MQTT feed report/configuration disagree"
        );
        if let Some(mqtt) = &self.mqtt {
            ensure!(
                !mqtt.active
                    && !mqtt.connected
                    && mqtt.offered == self.cycles
                    && mqtt
                        .drained
                        .checked_add(mqtt.queue_drops)
                        .and_then(|n| n.checked_add(mqtt.queue_pending))
                        == Some(mqtt.offered)
                    && mqtt
                        .coalesced
                        .checked_add(mqtt.attempted_events)
                        .and_then(|n| n.checked_add(mqtt.unsent_events))
                        == Some(mqtt.drained)
                    && mqtt.unsent_events <= 1
                    && mqtt.write_completions.checked_add(mqtt.publish_errors)
                        == Some(mqtt.publish_attempts),
                "MQTT feed counters are inconsistent or still active/connected"
            );
        }
        ensure!(
            self.http.is_some() == ctx.profile.http.is_some(),
            "HTTP feed report/configuration disagree"
        );
        if let Some(http) = &self.http {
            ensure!(
                !http.active
                    && http.offered == self.cycles
                    && http
                        .dispatched
                        .checked_add(http.queue_drops)
                        .and_then(|n| n.checked_add(http.pending))
                        == Some(http.offered),
                "HTTP feed counters are inconsistent or still active"
            );
        }
        ensure!(
            self.error.is_none() && !self.cancelled,
            "trial failed or was cancelled"
        );
        ensure!(
            self.transport_errors == 0
                && self.valid >= 2
                && self.cyclic_elapsed_us
                    >= ctx
                        .duration_limit_us
                        .saturating_sub(ctx.profile.requested_cycle_us),
            "trial has no usable completed cyclic measurement"
        );
        ensure!(
            self.cycles
                <= ctx
                    .duration_limit_us
                    .div_ceil(ctx.profile.requested_cycle_us),
            "cycle count exceeds the requested duration/period bound"
        );
        ensure!(
            self.scheduler == ctx.profile.scheduler
                && self.requested_cycle_us == ctx.profile.requested_cycle_us
                && self.input_loss_timeout_ms == ctx.profile.input_loss_timeout_ms,
            "report timing settings differ from its run context"
        );
        ensure!(
            self.connection_generation > 0
                && self.valid <= self.replies
                && self.replies <= self.cycles
                && self.timeouts == self.cycles - self.replies
                && self.wkc_mismatches <= self.replies - self.valid
                && self.state_mismatches <= self.replies - self.valid
                && self.replies - self.valid
                    <= self.wkc_mismatches.saturating_add(self.state_mismatches),
            "inconsistent cyclic counters"
        );
        check_spacing(&self.send_spacing, self.cycles - 1)?;
        check_spacing(&self.receive_spacing, self.replies - 1)?;
        ensure!(
            self.send_spacing.longest_gap_us <= Some(self.cyclic_elapsed_us)
                && self.receive_spacing.longest_gap_us <= Some(self.cyclic_elapsed_us),
            "spacing exceeds the measured cyclic interval"
        );
        let cap = self
            .capture
            .as_ref()
            .context("trial has no saved capture counters")?;
        ensure!(
            cap.parts > 0
                && cap.written > 0
                && cap.selected <= self.valid
                && cap.overruns <= cap.selected
                && cap.written == cap.selected - cap.overruns,
            "inconsistent or undrained capture counters"
        );
        if ctx.profile.mode == LogMode::Every {
            ensure!(
                cap.selected == self.valid,
                "every-valid trial omitted valid samples"
            );
        }
        let start = chrono::DateTime::parse_from_rfc3339(&cap.utc_start)
            .context("invalid capture UTC anchor")?;
        ensure!(
            start.offset().local_minus_utc() == 0,
            "capture anchor is not UTC"
        );
        ensure!(
            self.devices.len() == 1 && self.expected_wkc == 1,
            "comparison requires one device"
        );
        let device = &self.devices[0];
        ensure!(
            device.tx_bytes == Some(ctx.profile.tx_bytes),
            "observed input size differs from context"
        );
        let backend = match ctx.source {
            Source::Synthetic { .. } => "Synthetic fixture",
            Source::Virtual { .. } => "Virtual EtherCAT ESC / EtherCrab SAFEOP",
            Source::Safeop => "EtherCrab / Npcap LRD SAFEOP",
            Source::Replay { .. } => {
                anyhow::bail!("replay spacing is playback timing; replay trials are not compared")
            }
        };
        ensure!(
            self.backend == backend,
            "backend differs from recorded source"
        );
        if matches!(ctx.source, Source::Virtual { .. } | Source::Safeop) {
            ensure!(
                self.stopped_al == Some((1, 0)),
                "trial has no confirmed INIT cleanup"
            );
            ensure!(
                device.identity.is_some()
                    && device.identity == ctx.profile.expected_identity
                    && device.rx_bytes == Some(ctx.profile.rx_bytes),
                "observed identity or output size differs from context"
            );
            self.synchronization
                .as_ref()
                .context("device synchronization readback missing")?
                .dc
                .confirm_disabled()?;
            ensure!(
                self.pdo_verification
                    .as_ref()
                    .and_then(|v| v.get("readback"))
                    .is_some_and(Value::is_object),
                "PDO readback result missing"
            );
        }
        Ok((ctx, cap))
    }
}

fn check_spacing(spacing: &Spacing, expected: u64) -> Result<()> {
    let values = [
        spacing.p50_us,
        spacing.p95_us,
        spacing.p99_us,
        spacing.longest_gap_us,
    ];
    ensure!(
        spacing.count == expected && values.iter().all(Option::is_some),
        "missing or inconsistent spacing measurements"
    );
    ensure!(
        values.windows(2).all(|v| v[0] <= v[1]),
        "spacing percentiles are out of order"
    );
    Ok(())
}

fn sync_settings(sync: &Option<crate::sync::Synchronization>) -> Result<Option<Value>> {
    let mut settings = sync.as_ref().map(serde_json::to_value).transpose()?;
    if let Some(dc) = settings
        .as_mut()
        .and_then(|v| v.get_mut("dc"))
        .and_then(Value::as_object_mut)
    {
        // Startup measurements vary between initializations; retain them in each original report.
        dc.remove("system_time_offset_ns");
        dc.remove("transmission_delay_ns");
    }
    Ok(settings)
}

#[derive(Debug, Serialize)]
pub struct Trial {
    pub file: PathBuf,
    pub sha256: String,
    pub scheduler: Scheduler,
    pub utc_start: String,
    pub cyclic_elapsed_us: u64,
    pub connection_generation: u64,
    pub cycles: u64,
    pub replies: u64,
    pub valid: u64,
    pub timeouts: u64,
    pub missed_deadlines: u64,
    pub wkc_mismatches: u64,
    pub state_mismatches: u64,
    pub ignored_frames: u64,
    pub send_spacing: Spacing,
    pub receive_spacing: Spacing,
    pub capture: CaptureStats,
    pub http: Option<crate::http_feed::Stats>,
    pub mqtt: Option<crate::mqtt_feed::Stats>,
}

#[derive(Debug, Serialize)]
pub struct Range {
    pub min: u64,
    pub median: f64,
    pub max: u64,
}

fn range(mut values: Vec<u64>) -> Range {
    values.sort_unstable();
    let mid = values.len() / 2;
    let median = if values.len().is_multiple_of(2) {
        (values[mid - 1] as f64 + values[mid] as f64) / 2.0
    } else {
        values[mid] as f64
    };
    Range {
        min: values[0],
        median,
        max: values[values.len() - 1],
    }
}

#[derive(Debug, Serialize)]
pub struct ScheduleSummary {
    pub scheduler: Scheduler,
    pub trials: usize,
    pub send_p99_us: Range,
    pub receive_p99_us: Range,
}

#[derive(Debug, Serialize)]
pub struct Comparison {
    pub schema: u32,
    pub app_version: String,
    pub frontend: Frontend,
    pub source: Source,
    pub comparison_sha256: String,
    pub common_profile_settings: Value,
    pub duration_limit_us: u64,
    devices: Vec<ObservedDevice>,
    pub synchronization_settings: Option<Value>,
    pub pdo_verification: Option<Value>,
    pub trials: Vec<Trial>,
    pub schedules: Vec<ScheduleSummary>,
    pub csv_audits: Option<Vec<crate::capture_audit::Audit>>,
    pub warnings: Vec<String>,
}

pub fn compare_files(files: &[PathBuf]) -> Result<Comparison> {
    compare_files_inner(files, None)
}

fn compare_files_inner(files: &[PathBuf], stop: Option<&AtomicBool>) -> Result<Comparison> {
    crate::review::check_cancel(stop)?;
    ensure!((2..=32).contains(&files.len()), "select 2–32 saved reports");
    let mut inputs = Vec::new();
    for file in files {
        let bytes = read_report_bytes_with_stop(file, stop)?;
        let report: SavedRun =
            serde_json::from_slice(bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes))
                .with_context(|| format!("parse report {}", file.display()))?;
        report
            .checked()
            .with_context(|| format!("check report {}", file.display()))?;
        inputs.push((file.clone(), hash(&bytes), report));
    }
    crate::review::check_cancel(stop)?;
    let result = compare(inputs)?;
    crate::review::check_cancel(stop)?;
    Ok(result)
}

pub(crate) fn read_report_bytes_with_stop(
    file: &std::path::Path,
    stop: Option<&AtomicBool>,
) -> Result<Vec<u8>> {
    crate::review::check_cancel(stop)?;
    let mut bytes = Vec::new();
    let mut reader =
        File::open(file).with_context(|| format!("open saved report {}", file.display()))?;
    let mut buffer = [0u8; 8192];
    while bytes.len() as u64 <= MAX_REPORT_BYTES {
        crate::review::check_cancel(stop)?;
        let limit = buffer
            .len()
            .min((MAX_REPORT_BYTES + 1 - bytes.len() as u64) as usize);
        let n = reader.read(&mut buffer[..limit])?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
    ensure!(
        bytes.len() as u64 <= MAX_REPORT_BYTES,
        "report exceeds 16 MiB: {}",
        file.display()
    );
    crate::review::check_cancel(stop)?;
    Ok(bytes)
}

pub fn compare_with_captures(files: &[PathBuf], bases: &[PathBuf]) -> Result<Comparison> {
    compare_with_captures_inner(files, bases, None)
}

pub(crate) fn compare_cancelable(
    files: &[PathBuf],
    bases: Option<&[PathBuf]>,
    stop: &AtomicBool,
) -> Result<Comparison> {
    match bases {
        Some(bases) => compare_with_captures_inner(files, bases, Some(stop)),
        None => compare_files_inner(files, Some(stop)),
    }
}

fn compare_with_captures_inner(
    files: &[PathBuf],
    bases: &[PathBuf],
    stop: Option<&AtomicBool>,
) -> Result<Comparison> {
    ensure!(
        files.len() == bases.len(),
        "provide one --csv base per report, in the same order"
    );
    let mut result = compare_files_inner(files, stop)?;
    let mut audits = Vec::new();
    for ((file, base), trial) in files.iter().zip(bases).zip(&result.trials) {
        let audit = crate::capture_audit::verify_with_stop(file, base, stop)?;
        ensure!(
            audit.report_sha256 == trial.sha256,
            "report changed during comparison"
        );
        audits.push(audit);
    }
    result
        .warnings
        .retain(|w| !w.starts_with("Capture counters are checked;"));
    result.warnings.push("CSV structure, typed text and metadata are audited; PDO meaning and original payload bits are not independently verified.".into());
    result.csv_audits = Some(audits);
    crate::review::check_cancel(stop)?;
    Ok(result)
}

fn compare(inputs: Vec<(PathBuf, String, SavedRun)>) -> Result<Comparison> {
    let first = &inputs[0].2;
    let (base, _) = first.checked()?;
    let sync = sync_settings(&first.synchronization)?;
    let mut settings = serde_json::to_value(&base.profile)?;
    settings
        .as_object_mut()
        .expect("profile object")
        .remove("scheduler");
    let mut result = Comparison {
        schema: 1, app_version: base.app_version.clone(), frontend: base.frontend,
        source: base.source.clone(), comparison_sha256: base.comparison_sha256.clone(),
        common_profile_settings: settings, duration_limit_us: base.duration_limit_us,
        devices: first.devices.clone(), synchronization_settings: sync.clone(),
        pdo_verification: first.pdo_verification.clone(),
        trials: Vec::new(), schedules: Vec::new(), csv_audits: None,
        warnings: vec![
            "Host send/dequeue spacing is not wire timing or device synchronization accuracy.".into(),
            "Capture counters are checked; CSV bytes and field values are not inspected by compare-runs.".into(),
            "Saved JSON and its hashes are editable evidence, not signed runtime attestation or bench acceptance.".into(),
            "Summary ranges describe per-run p99 values; percentiles are not pooled across trials.".into(),
        ],
    };
    if !matches!(base.source, Source::Safeop) {
        result
            .warnings
            .push("Offline fixture results do not qualify physical hardware.".into());
    }
    if base.frontend == Frontend::Cli {
        result
            .warnings
            .push("CLI trials do not establish GUI-plus-logger benchmark behavior.".into());
    }
    let mut seen = HashSet::new();
    let mut anchors = HashSet::new();
    let mut previous = None;
    for (file, sha256, r) in &inputs {
        let (ctx, cap) = r.checked()?;
        ensure!(seen.insert(sha256), "duplicate report: {}", file.display());
        ensure!(
            anchors.insert(&cap.utc_start),
            "duplicate capture anchor: {}",
            file.display()
        );
        ensure!(
            ctx.comparison_sha256 == base.comparison_sha256
                && ctx.source == base.source
                && ctx.app_version == base.app_version
                && ctx.frontend == base.frontend
                && ctx.duration_limit_us == base.duration_limit_us,
            "trial configuration differs (only scheduler may vary): {}",
            file.display()
        );
        ensure!(
            r.devices == first.devices && sync_settings(&r.synchronization)? == sync,
            "observed device/topology or synchronization settings differ: {}",
            file.display()
        );
        ensure!(
            r.pdo_verification == first.pdo_verification,
            "PDO assignment readback or verification differs: {}",
            file.display()
        );
        let anchor = chrono::DateTime::parse_from_rfc3339(&cap.utc_start)?;
        ensure!(
            previous.is_none_or(|at| at < anchor),
            "supply reports in capture-start order"
        );
        previous = Some(anchor);
        if r.timeouts > 0 || r.wkc_mismatches > 0 || r.state_mismatches > 0 || cap.overruns > 0 {
            result.warnings.push(format!(
                "Trial {} has invalid exchanges or logger overruns; inspect its counters.",
                file.display()
            ));
        }
        if let Some(http) = &r.http
            && (http.queue_drops > 0
                || http.pending > 0
                || http.io_errors > 0
                || http.rejected_requests > 0
                || http.worker_failed
                || http.worker_error.is_some())
        {
            result.warnings.push(format!("Trial {} has HTTP feed loss, client errors or worker failure; inspect its independent interface counters.",file.display()));
        }
        if let Some(mqtt) = &r.mqtt
            && (mqtt.queue_drops > 0
                || mqtt.queue_pending > 0
                || mqtt.unsent_events > 0
                || mqtt.errors > 0
                || mqtt.publish_errors > 0
                || mqtt.worker_failed
                || mqtt.worker_error.is_some())
        {
            result.warnings.push(format!("Trial {} has MQTT feed loss, unsent input, network errors or worker failure; coalescing and TCP write completion are independent of CSV/bus quality and do not prove consumer delivery.",file.display()));
        }
        result.trials.push(Trial {
            file: file.clone(),
            sha256: sha256.clone(),
            scheduler: r.scheduler,
            utc_start: cap.utc_start.clone(),
            cyclic_elapsed_us: r.cyclic_elapsed_us,
            connection_generation: r.connection_generation,
            cycles: r.cycles,
            replies: r.replies,
            valid: r.valid,
            timeouts: r.timeouts,
            missed_deadlines: r.missed_deadlines,
            wkc_mismatches: r.wkc_mismatches,
            state_mismatches: r.state_mismatches,
            ignored_frames: r.ignored_frames,
            send_spacing: r.send_spacing.clone(),
            receive_spacing: r.receive_spacing.clone(),
            capture: cap.clone(),
            http: r.http.clone(),
            mqtt: r.mqtt.clone(),
        });
    }
    for scheduler in [Scheduler::Deadline, Scheduler::Relative] {
        let trials: Vec<_> = result
            .trials
            .iter()
            .filter(|t| t.scheduler == scheduler)
            .collect();
        ensure!(
            !trials.is_empty(),
            "both deadline and relative trials are required"
        );
        if trials.len() < 3 {
            result.warnings.push(format!(
                "{scheduler:?} has fewer than three trials; collect repeated runs."
            ));
        }
        result.schedules.push(ScheduleSummary {
            scheduler,
            trials: trials.len(),
            send_p99_us: range(
                trials
                    .iter()
                    .map(|t| t.send_spacing.p99_us.expect("checked"))
                    .collect(),
            ),
            receive_p99_us: range(
                trials
                    .iter()
                    .map(|t| t.receive_spacing.p99_us.expect("checked"))
                    .collect(),
            ),
        });
    }
    if result
        .trials
        .windows(2)
        .any(|w| w[0].scheduler == w[1].scheduler)
    {
        result.warnings.push(
            "Trial order does not alternate schedulers; order effects may influence results."
                .into(),
        );
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn fixture(scheduler: Scheduler, second: u32, p99: u64) -> SavedRun {
        let mut profile: Profile =
            serde_json::from_str(include_str!("../samples/synthetic.json")).unwrap();
        profile.scheduler = scheduler;
        let options = RunOptions {
            frontend: Frontend::Cli,
            mode: Mode::Simulate { faults: false },
            duration: Duration::from_secs(1),
            csv: Some("unused.csv".into()),
            generation: 1,
        };
        serde_json::from_value(serde_json::json!({
            "context": RunContext::new(&profile, &options).unwrap(),
            "cyclic_elapsed_us": 1_000_020, "backend": "Synthetic fixture", "scheduler": scheduler,
            "requested_cycle_us": profile.requested_cycle_us, "input_loss_timeout_ms": profile.input_loss_timeout_ms,
            "connection_generation": 1, "cycles": 1000, "replies": 1000, "valid": 1000,
            "timeouts": 0, "missed_deadlines": 0, "wkc_mismatches": 0, "state_mismatches": 0,
            "transport_errors": 0, "ignored_frames": 0, "expected_wkc": 1,
            "send_spacing": {"count":999,"p50_us":1,"p95_us":2,"p99_us":p99,"longest_gap_us":p99+1},
            "receive_spacing": {"count":999,"p50_us":1,"p95_us":2,"p99_us":p99,"longest_gap_us":p99+1},
            "capture":{"selected":1000,"written":1000,"overruns":0,"parts":2,
                "utc_start":format!("2026-01-01T00:00:{second:02}Z")},
            "devices":[{"position":0,"station_address":0,"alias":0,"link_ports":[false,false,false,false],
                "identity":profile.expected_identity,"serial":null,"tx_bytes":profile.tx_bytes,"rx_bytes":profile.rx_bytes}],
            "synchronization":null,"stopped_al":null,"cancelled":false,"error":null
        })).unwrap()
    }

    fn inputs(reports: Vec<SavedRun>) -> Vec<(PathBuf, String, SavedRun)> {
        reports
            .into_iter()
            .enumerate()
            .map(|(i, r)| (format!("trial-{i}.json").into(), format!("hash-{i}"), r))
            .collect()
    }

    #[test]
    fn compares_repeated_trials_without_pooling_their_percentiles() {
        let result = compare(inputs(vec![
            fixture(Scheduler::Deadline, 0, 100),
            fixture(Scheduler::Relative, 1, 200),
            fixture(Scheduler::Deadline, 2, 900),
            fixture(Scheduler::Relative, 3, 400),
        ]))
        .unwrap();
        assert_eq!(result.schedules[0].receive_p99_us.median, 500.0);
        assert_eq!(result.schedules[1].receive_p99_us.median, 300.0);
        assert_eq!(result.trials[2].receive_spacing.p99_us, Some(900));
        assert_eq!(result.common_profile_settings.get("scheduler"), None);
        assert!(result.warnings.iter().any(|w| w.contains("CSV bytes")));
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("Offline fixture"))
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("GUI-plus-logger"))
        );
    }

    #[test]
    fn comparison_retains_http_losses_separately_and_rejects_mixed_config_or_bad_counts() {
        let mut runs = vec![
            fixture(Scheduler::Deadline, 0, 100),
            fixture(Scheduler::Relative, 1, 200),
        ];
        for run in &mut runs {
            let ctx = run.context.as_mut().unwrap();
            ctx.profile.http = Some(crate::http_feed::Config::default());
            let (exact, common) = RunContext::hashes(&ctx.profile).unwrap();
            ctx.profile_sha256 = exact;
            ctx.comparison_sha256 = common;
            run.http = Some(crate::http_feed::Stats {
                offered: 1000,
                dispatched: 997,
                queue_drops: 3,
                history_evictions: 500,
                io_errors: 2,
                ..Default::default()
            });
        }
        let checked = compare(inputs(runs)).unwrap();
        assert_eq!(checked.trials[0].http.as_ref().unwrap().queue_drops, 3);
        assert_eq!(checked.trials[0].capture.overruns, 0);
        assert!(
            checked
                .warnings
                .iter()
                .any(|w| w.contains("HTTP feed loss"))
        );
        let mut bad = fixture(Scheduler::Deadline, 0, 100);
        bad.http = Some(crate::http_feed::Stats::default());
        assert!(bad.checked().is_err());
    }

    #[test]
    fn fingerprint_excludes_only_scheduler_and_detects_stale_context() {
        let mut a = fixture(Scheduler::Deadline, 0, 100);
        let b = fixture(Scheduler::Relative, 1, 200);
        let ca = a.context.as_mut().unwrap();
        let cb = b.context.as_ref().unwrap();
        assert_ne!(ca.profile_sha256, cb.profile_sha256);
        assert_eq!(ca.comparison_sha256, cb.comparison_sha256);
        ca.profile.tx[0].bit += 1;
        assert!(
            a.checked()
                .unwrap_err()
                .to_string()
                .contains("hash mismatch")
        );
        let mut a = fixture(Scheduler::Deadline, 0, 100);
        let ca = a.context.as_mut().unwrap();
        ca.profile.queue_capacity += 1;
        (ca.profile_sha256, ca.comparison_sha256) = RunContext::hashes(&ca.profile).unwrap();
        assert!(
            compare(inputs(vec![a, b]))
                .unwrap_err()
                .to_string()
                .contains("configuration differs")
        );
    }

    #[test]
    fn mqtt_comparison_retains_coalescing_and_checks_both_accounting_domains() {
        let enable = |run: &mut SavedRun| {
            let ctx = run.context.as_mut().unwrap();
            ctx.profile.mqtt = Some(crate::mqtt_feed::Config::default());
            (ctx.profile_sha256, ctx.comparison_sha256) = RunContext::hashes(&ctx.profile).unwrap();
            run.mqtt = Some(crate::mqtt_feed::Stats {
                offered: 1000,
                drained: 997,
                queue_drops: 3,
                coalesced: 996,
                unsent_events: 1,
                errors: 1,
                ..Default::default()
            });
        };
        let mut runs = vec![
            fixture(Scheduler::Deadline, 0, 100),
            fixture(Scheduler::Relative, 1, 200),
        ];
        for run in &mut runs {
            enable(run);
        }
        let result = compare(inputs(runs)).unwrap();
        assert_eq!(result.trials[0].mqtt.as_ref().unwrap().coalesced, 996);
        assert_eq!(result.trials[0].capture.overruns, 0);
        assert!(result.warnings.iter().any(|w| w.contains("MQTT feed loss")));
        let mut bad = fixture(Scheduler::Deadline, 0, 100);
        enable(&mut bad);
        bad.mqtt.as_mut().unwrap().coalesced += 1;
        assert!(bad.checked().is_err());
        bad.mqtt.as_mut().unwrap().coalesced -= 1;
        bad.mqtt.as_mut().unwrap().queue_drops += 1;
        assert!(bad.checked().is_err());
    }

    #[test]
    fn rejects_mixed_frontends_sources_duration_and_observed_topology() {
        for change in 0..5 {
            let a = fixture(Scheduler::Deadline, 0, 100);
            let mut b = fixture(Scheduler::Relative, 1, 200);
            match change {
                0 => b.context.as_mut().unwrap().frontend = Frontend::Gui,
                1 => b.context.as_mut().unwrap().source = Source::Synthetic { faults: true },
                2 => b.context.as_mut().unwrap().duration_limit_us = 999_000,
                3 => b.devices[0].serial = Some(123),
                _ => b.context.as_mut().unwrap().app_version = "other".into(),
            }
            assert!(compare(inputs(vec![a, b])).is_err(), "change {change}");
        }
    }

    #[test]
    fn rejects_legacy_failed_cancelled_and_internally_inconsistent_runs() {
        for change in 0..13 {
            let mut r = fixture(Scheduler::Deadline, 0, 100);
            match change {
                0 => r.context = None,
                1 => r.cancelled = true,
                2 => r.error = Some("failed".into()),
                3 => r.capture.as_mut().unwrap().written -= 1,
                4 => r.capture = None,
                5 => r.context.as_mut().unwrap().csv_enabled = false,
                6 => r.send_spacing.count -= 1,
                7 => r.receive_spacing.p95_us = Some(900),
                8 => r.valid -= 1,
                9 => r.cyclic_elapsed_us = 10,
                10 => r.cycles = u64::MAX,
                11 => r.transport_errors = 1,
                _ => r.requested_cycle_us += 1,
            }
            assert!(r.checked().is_err(), "change {change}");
        }
    }

    #[test]
    fn rejects_duplicates_reversed_order_and_missing_scheduler() {
        let mut trials = inputs(vec![
            fixture(Scheduler::Deadline, 0, 100),
            fixture(Scheduler::Relative, 1, 100),
        ]);
        trials[1].1 = trials[0].1.clone();
        assert!(
            compare(trials)
                .unwrap_err()
                .to_string()
                .contains("duplicate report")
        );
        let trials = inputs(vec![
            fixture(Scheduler::Deadline, 0, 100),
            fixture(Scheduler::Relative, 0, 100),
        ]);
        assert!(
            compare(trials)
                .unwrap_err()
                .to_string()
                .contains("duplicate capture anchor")
        );
        let trials = inputs(vec![
            fixture(Scheduler::Deadline, 1, 100),
            fixture(Scheduler::Relative, 0, 100),
        ]);
        assert!(
            compare(trials)
                .unwrap_err()
                .to_string()
                .contains("capture-start order")
        );
        let trials = inputs(vec![
            fixture(Scheduler::Deadline, 0, 100),
            fixture(Scheduler::Deadline, 1, 100),
        ]);
        assert!(
            compare(trials)
                .unwrap_err()
                .to_string()
                .contains("both deadline and relative")
        );
    }

    #[test]
    fn preserves_logger_loss_and_excludes_only_measured_dc_offset_and_delay() {
        let mut a = fixture(Scheduler::Deadline, 0, 100);
        let b = fixture(Scheduler::Relative, 1, 200);
        let cap = a.capture.as_mut().unwrap();
        cap.overruns = 2;
        cap.written = 998;
        let result = compare(inputs(vec![a, b])).unwrap();
        assert_eq!(result.trials[0].capture.overruns, 2);
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("invalid exchanges or logger overruns"))
        );
        let mut sync = crate::sync::Synchronization::default();
        let zero = sync_settings(&Some(sync.clone())).unwrap();
        sync.dc.system_time_offset_ns = Some(crate::sync::RegisterRead {
            value: Some(123),
            unavailable: None,
        });
        sync.dc.transmission_delay_ns = Some(crate::sync::RegisterRead {
            value: Some(456),
            unavailable: None,
        });
        assert_eq!(sync_settings(&Some(sync.clone())).unwrap(), zero);
        sync.dc.sync0_cycle_ns = Some(crate::sync::RegisterRead {
            value: Some(1000),
            unavailable: None,
        });
        assert_ne!(sync_settings(&Some(sync)).unwrap(), zero);
    }
}

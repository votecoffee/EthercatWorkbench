use crate::{
    capture::{Capture, CaptureStats},
    health::{InputHealth, InputIssue, Tracker},
    model::{Identity, MAX_PAYLOAD, Profile, Scheduler},
};
use anyhow::{Context, Result, ensure};
use hdrhistogram::Histogram;
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering::Relaxed},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Default, Serialize)]
pub struct DeviceInfo {
    pub position: u16,
    pub station_address: u16,
    pub alias: u16,
    pub link_ports: [bool; 4],
    pub identity: Option<Identity>,
    pub name: Option<String>,
    pub coe_name: Option<crate::sync::RegisterRead<String>>,
    pub diagnostics: Option<Arc<crate::esc::Diagnosis>>,
    pub serial: Option<u32>,
    pub tx_bytes: Option<usize>,
    pub rx_bytes: Option<usize>,
    pub dc_support: Option<String>,
    pub al_status: u16,
    pub al_code: u16,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Spacing {
    pub count: u64,
    pub p50_us: Option<u64>,
    pub p95_us: Option<u64>,
    pub p99_us: Option<u64>,
    pub longest_gap_us: Option<u64>,
}

struct Gaps {
    histogram: Histogram<u64>,
    previous: Option<Instant>,
    longest: u64,
}

impl Gaps {
    fn new() -> Self {
        Self {
            histogram: Histogram::new_with_max(3_600_000_000, 3).expect("valid histogram bounds"),
            previous: None,
            longest: 0,
        }
    }

    fn tick(&mut self, at: Instant) {
        if let Some(previous) = self.previous {
            let gap = at.saturating_duration_since(previous).as_micros() as u64;
            self.longest = self.longest.max(gap);
            self.histogram.saturating_record(gap);
        }
        self.previous = Some(at);
    }

    fn report(&self) -> Spacing {
        let count = self.histogram.len();
        let percentile =
            |q| (count != 0).then(|| self.histogram.value_at_quantile(q).min(self.longest));
        Spacing {
            count,
            p50_us: percentile(0.50),
            p95_us: percentile(0.95),
            p99_us: percentile(0.99),
            longest_gap_us: (count != 0).then_some(self.longest),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub context: Option<Arc<crate::benchmark::RunContext>>,
    pub cyclic_elapsed_us: u64,
    pub backend: String,
    pub requested_cycle_us: u64,
    pub input_loss_timeout_ms: u64,
    pub input_health: InputHealth,
    pub transport_errors: u64,
    pub scheduler: Scheduler,
    pub device_sync: String,
    pub dc_sync: String,
    pub synchronization: Option<crate::sync::Synchronization>,
    pub sync_review: Option<Arc<crate::sync_review::Review>>,
    pub connection_generation: u64,
    pub cycles: u64,
    pub replies: u64,
    pub valid: u64,
    pub timeouts: u64,
    pub missed_deadlines: u64,
    pub wkc_mismatches: u64,
    pub state_mismatches: u64,
    pub ignored_frames: u64,
    pub replay_exchanges: Option<usize>,
    pub replay_origin: Option<String>,
    pub virtual_esc: Option<crate::virtual_esc::VirtualStats>,
    pub expected_wkc: u16,
    pub actual_wkc: Option<u16>,
    pub send_spacing: Spacing,
    pub receive_spacing: Spacing,
    pub capture: Option<CaptureStats>,
    pub devices: Vec<DeviceInfo>,
    pub pdo_verification: Option<Arc<crate::pdo::Verification>>,
    pub stopped_al: Option<(u16, u16)>,
    pub setup_failure_al: Option<(u16, u16)>,
    pub cancelled: bool,
    pub error: Option<String>,
    pub http: Option<crate::http_feed::Stats>,
    pub mqtt: Option<crate::mqtt_feed::Stats>,
    pub shared_memory: Option<crate::shared_memory::Stats>,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub phase: String,
    pub report: Report,
    pub payload: [u8; MAX_PAYLOAD],
    pub payload_len: usize,
    pub valid: bool,
    pub last_valid_received_at: Option<Instant>,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            phase: "Starting".into(),
            report: Report::default(),
            payload: [0; MAX_PAYLOAD],
            payload_len: 0,
            valid: false,
            last_valid_received_at: None,
        }
    }
}

pub struct Exchange {
    pub sent: Instant,
    pub received: Option<Instant>,
    pub wkc: u16,
    pub status: Option<(u16, u16)>,
    pub data: [u8; MAX_PAYLOAD],
    pub ignored_frames: u64,
}

pub trait Bus {
    fn exchange(&mut self, cycle: u64) -> Result<Option<Exchange>>;
    fn stop(&mut self) -> Result<Option<(u16, u16)>>;
}

#[derive(Clone, Debug)]
pub enum Mode {
    Simulate {
        faults: bool,
    },
    Replay {
        fixture: PathBuf,
    },
    Virtual {
        model: crate::virtual_esc::VirtualModel,
        fault: crate::virtual_esc::VirtualFault,
    },
    SafeOp {
        approved: crate::run::BenchApproval,
    },
}

#[derive(Clone, Debug)]
pub struct BenchApproval {
    _confirmed: (),
}

impl BenchApproval {
    pub fn confirm(isolated_bench_and_esc_writes_approved: bool) -> Result<Self> {
        ensure!(
            isolated_bench_and_esc_writes_approved,
            "SAFEOP requires approval for isolated-bench ESC setup and teardown writes"
        );
        Ok(Self { _confirmed: () })
    }
}

pub struct RunOptions {
    pub frontend: crate::benchmark::Frontend,
    pub mode: Mode,
    pub duration: Duration,
    pub csv: Option<PathBuf>,
    pub generation: u64,
}

pub fn run(
    profile: Profile,
    options: RunOptions,
    stop: &AtomicBool,
    view: &Mutex<Snapshot>,
) -> Report {
    let mut report = Report {
        requested_cycle_us: profile.requested_cycle_us,
        input_loss_timeout_ms: profile.input_loss_timeout_ms,
        scheduler: profile.scheduler,
        connection_generation: options.generation,
        ..Report::default()
    };
    let result = run_inner(&profile, options, stop, view, &mut report);
    report.cancelled = stop.load(Relaxed);
    if let Ok(review) = crate::sync_review::review(&profile, report.synchronization.as_ref()) {
        report.sync_review = review.map(Arc::new);
    }
    if let Some((status, code)) = report.stopped_al
        && let Some(device) = report.devices.first_mut()
    {
        device.al_status = status;
        device.al_code = code;
    }
    if let Err(err) = result {
        report.error = Some(format!("{err:#}"));
    }
    let mut last = view.lock().unwrap_or_else(|err| err.into_inner());
    last.report.clone_from(&report);
    last.phase = if report.error.is_some() {
        "Failed"
    } else if report.cancelled {
        "Cancelled"
    } else {
        "Stopped"
    }
    .into();
    last.valid = false;
    report
}

fn run_inner(
    profile: &Profile,
    options: RunOptions,
    stop: &AtomicBool,
    view: &Mutex<Snapshot>,
    report: &mut Report,
) -> Result<()> {
    profile.validate()?;
    report.sync_review = crate::sync_review::review(profile, None)?.map(Arc::new);
    ensure!(profile.tx_bytes > 0, "a TxPDO image is required");
    ensure!(
        !options.duration.is_zero() && options.duration <= Duration::from_secs(86_400),
        "duration must be within 1 day"
    );
    ensure!(
        options.generation > 0,
        "connection generation must be positive"
    );
    report.context = Some(Arc::new(crate::benchmark::RunContext::new(
        profile, &options,
    )?));
    let http = profile
        .http
        .as_ref()
        .map(crate::http_feed::Bound::bind)
        .transpose()?;
    let shared_memory = profile
        .shared_memory
        .as_ref()
        .map(crate::shared_memory::Bound::bind)
        .transpose()?;
    report.shared_memory = shared_memory
        .as_ref()
        .map(crate::shared_memory::Bound::stats);
    let mut bindings = Bindings {
        http,
        shared_memory,
    };
    report.http = bindings.http.as_ref().map(crate::http_feed::Bound::stats);
    if options.frontend == crate::benchmark::Frontend::Cli
        && let Some(http) = &report.http
    {
        eprintln!(
            "HTTP input feed bound at {}; serves after setup",
            http.address
        );
    }
    match options.mode {
        Mode::Simulate { faults } => {
            report.backend = "Synthetic fixture".into();
            report.expected_wkc = 1;
            report.device_sync = "Simulated free-running".into();
            report.dc_sync = "Simulated, no DC".into();
            report.devices = vec![DeviceInfo {
                identity: profile.expected_identity.clone(),
                name: Some("Synthetic fixture".into()),
                tx_bytes: Some(profile.tx_bytes),
                rx_bytes: Some(profile.rx_bytes),
                al_status: 4,
                ..DeviceInfo::default()
            }];
            cycle(
                Simulated { faults },
                profile,
                &options,
                stop,
                view,
                report,
                &mut bindings,
            )
        }
        Mode::Replay { ref fixture } => {
            let replay = crate::replay::Replay::load(fixture, profile)?;
            report.backend = "Offline raw Ethernet frame replay".into();
            report.expected_wkc = 1;
            report.device_sync = "Offline playback".into();
            report.dc_sync = "Fixture has no device clock measurements".into();
            report.replay_exchanges = Some(replay.len());
            report.replay_origin = Some(replay.origin.clone());
            report.devices = vec![DeviceInfo {
                station_address: replay.station_address,
                name: Some("Replay fixture".into()),
                tx_bytes: Some(profile.tx_bytes),
                ..DeviceInfo::default()
            }];
            cycle(replay, profile, &options, stop, view, report, &mut bindings)?;
            ensure!(
                Some(report.cycles as usize) == report.replay_exchanges || stop.load(Relaxed),
                "replay duration expired before all recorded exchanges were processed"
            );
            Ok(())
        }
        Mode::Virtual { model, fault } => {
            report.backend = "Virtual EtherCAT ESC / EtherCrab SAFEOP".into();
            #[cfg(windows)]
            {
                crate::live::virtual_safeop(
                    profile,
                    model,
                    fault,
                    stop,
                    view,
                    report,
                    |bus, report| cycle(bus, profile, &options, stop, view, report, &mut bindings),
                )
            }
            #[cfg(not(windows))]
            {
                let _ = (model, fault);
                anyhow::bail!("the virtual setup path currently requires the Windows build")
            }
        }
        Mode::SafeOp { ref approved } => {
            #[cfg(windows)]
            {
                report.backend = "EtherCrab / Npcap LRD SAFEOP".into();
                crate::live::safeop(profile, approved, stop, view, report, |bus, report| {
                    cycle(bus, profile, &options, stop, view, report, &mut bindings)
                })
            }
            #[cfg(not(windows))]
            {
                let _ = approved;
                anyhow::bail!("live EtherCAT requires Windows x64")
            }
        }
    }
}

#[derive(Default)]
struct Bindings {
    http: Option<crate::http_feed::Bound>,
    shared_memory: Option<crate::shared_memory::Bound>,
}

fn cycle(
    mut bus: impl Bus,
    profile: &Profile,
    options: &RunOptions,
    stop: &AtomicBool,
    view: &Mutex<Snapshot>,
    report: &mut Report,
    bindings: &mut Bindings,
) -> Result<()> {
    let mut shared_memory = match bindings
        .shared_memory
        .take()
        .map(|bound| crate::shared_memory::Hub::start(bound, profile, report))
        .transpose()
    {
        Ok(memory) => memory,
        Err(error) => {
            let cleanup = bus.stop().map(|al| report.stopped_al = al);
            return combine(Err(error), cleanup);
        }
    };
    let mut http = match bindings
        .http
        .take()
        .map(|bound| crate::http_feed::Hub::start(bound, profile, report))
        .transpose()
    {
        Ok(http) => http,
        Err(error) => {
            if let Some(memory) = &shared_memory {
                memory.deactivate();
            }
            let cleanup = bus.stop().map(|al| report.stopped_al = al);
            if let Some(memory) = shared_memory.take() {
                report.shared_memory = Some(memory.finish());
            }
            return combine(Err(error), cleanup);
        }
    };
    let mut mqtt = match profile
        .mqtt
        .as_ref()
        .map(|config| crate::mqtt_feed::Hub::start(config, profile, report))
        .transpose()
    {
        Ok(mqtt) => mqtt,
        Err(error) => {
            if let Some(http) = &http {
                http.deactivate();
            }
            if let Some(memory) = &shared_memory {
                memory.deactivate();
            }
            let cleanup = bus.stop().map(|al| report.stopped_al = al);
            if let Some(http) = http.take() {
                report.http = Some(http.finish());
            }
            if let Some(memory) = shared_memory.take() {
                report.shared_memory = Some(memory.finish());
            }
            return combine(Err(error), cleanup);
        }
    };
    let mut capture = match options
        .csv
        .as_ref()
        .map(|path| Capture::start(path, profile))
        .transpose()
    {
        Ok(capture) => capture,
        Err(error) => {
            if let Some(http) = &http {
                http.deactivate();
            }
            if let Some(mqtt) = &mqtt {
                mqtt.deactivate();
            }
            if let Some(memory) = &shared_memory {
                memory.deactivate();
            }
            let cleanup = bus.stop().map(|al| report.stopped_al = al);
            if let Some(http) = http.take() {
                report.http = Some(http.finish());
            }
            if let Some(mqtt) = mqtt.take() {
                report.mqtt = Some(mqtt.finish());
            }
            if let Some(memory) = shared_memory.take() {
                report.shared_memory = Some(memory.finish());
            }
            return combine(Err(error), cleanup);
        }
    };
    let interval = Duration::from_micros(profile.requested_cycle_us);
    let sleeper = spin_sleep::SpinSleeper::default()
        .with_spin_strategy(spin_sleep::SpinStrategy::SpinLoopHint);
    let mut sends = Gaps::new();
    let mut receives = Gaps::new();
    let start = Instant::now();
    let end = start + options.duration;
    let mut deadline = start;
    let mut publish = start;
    let mut last = None;
    let mut health = Tracker::new(start);
    let mut index = 0;
    let mut result = (|| {
        while !stop.load(Relaxed) && deadline < end {
            if capture.as_ref().is_some_and(Capture::failed) {
                break;
            }
            sleeper.sleep(deadline.saturating_duration_since(Instant::now()));
            let now = Instant::now();
            let late_slots =
                (now.saturating_duration_since(deadline).as_micros() / interval.as_micros()) as u32;
            if late_slots != 0 {
                report.missed_deadlines += u64::from(late_slots);
                if profile.scheduler == Scheduler::Deadline {
                    deadline += interval * late_slots;
                    index += u64::from(late_slots);
                }
            }
            if now >= end || stop.load(Relaxed) {
                break;
            }
            index += 1;
            let attempt = Instant::now();
            let exchange = match bus.exchange(index) {
                Ok(Some(exchange)) => exchange,
                Ok(None) => break,
                Err(error) => {
                    report.cycles += 1;
                    report.transport_errors += 1;
                    report.actual_wkc = None;
                    health.invalid(
                        &mut report.input_health,
                        InputIssue::TransportError,
                        attempt,
                        Instant::now(),
                    );
                    last = Some(([0; MAX_PAYLOAD], false, false));
                    let observation = crate::input_feed::Observation {
                        cycle_index: index,
                        received: None,
                        observed: Instant::now(),
                        valid: false,
                        expected_wkc: report.expected_wkc,
                        actual_wkc: None,
                        al: None,
                        issue: Some(InputIssue::TransportError),
                        counts: feed_counts(report, capture.as_ref()),
                        data: &[0; MAX_PAYLOAD],
                    };
                    if let Some(http) = http.as_mut() {
                        http.offer(observation);
                    }
                    if let Some(mqtt) = mqtt.as_mut() {
                        mqtt.offer(observation);
                    }
                    if let Some(memory) = shared_memory.as_mut() {
                        memory.offer(observation);
                    }
                    return Err(error.context("cyclic Ethernet transport failed"));
                }
            };
            report.cycles += 1;
            report.ignored_frames += exchange.ignored_frames;
            sends.tick(exchange.sent);
            report.actual_wkc = exchange.received.map(|_| exchange.wkc);
            let status_ok = exchange
                .status
                .is_some_and(|(status, code)| status & 0x1f == 4 && code == 0);
            if exchange.received.is_some()
                && let Some((status, code)) = exchange.status
                && let Some(device) = report.devices.first_mut()
            {
                device.al_status = status;
                device.al_code = code;
            }
            let valid = if let Some(received) = exchange.received {
                receives.tick(received);
                report.replies += 1;
                let wkc_ok = exchange.wkc == report.expected_wkc;
                report.wkc_mismatches += u64::from(!wkc_ok);
                report.state_mismatches += u64::from(!status_ok);
                if wkc_ok && status_ok {
                    report.valid += 1;
                    if let Some(capture) = capture.as_mut() {
                        capture.submit(
                            received,
                            report.connection_generation,
                            index,
                            &exchange.data,
                        );
                    }
                }
                wkc_ok && status_ok
            } else {
                report.timeouts += 1;
                false
            };
            let observed = Instant::now();
            let previous_issue = report.input_health.current_issue;
            if valid {
                health.valid(
                    &mut report.input_health,
                    index,
                    exchange.received.expect("valid reply"),
                );
            } else {
                let issue = if exchange.received.is_none() {
                    InputIssue::Timeout
                } else {
                    match (exchange.wkc == report.expected_wkc, status_ok) {
                        (false, false) => InputIssue::WorkingCounterAndAlStatus,
                        (false, true) => InputIssue::WorkingCounter,
                        _ => InputIssue::AlStatus,
                    }
                };
                health.invalid(&mut report.input_health, issue, exchange.sent, observed);
            }
            last = Some((exchange.data, exchange.received.is_some(), valid));
            let observation = crate::input_feed::Observation {
                cycle_index: index,
                received: exchange.received,
                observed,
                valid,
                expected_wkc: report.expected_wkc,
                actual_wkc: exchange.received.map(|_| exchange.wkc),
                al: exchange.received.and(exchange.status),
                issue: report.input_health.current_issue,
                counts: feed_counts(report, capture.as_ref()),
                data: &exchange.data,
            };
            if let Some(http) = http.as_mut() {
                http.offer(observation);
            }
            if let Some(mqtt) = mqtt.as_mut() {
                mqtt.offer(observation);
            }
            if let Some(memory) = shared_memory.as_mut() {
                memory.offer(observation);
            }
            if !valid {
                check_input_loss(&report.input_health, profile.input_loss_timeout_ms)?;
            }
            if observed >= publish || previous_issue != report.input_health.current_issue {
                if let Ok(mut snapshot) = view.try_lock() {
                    update(report, &sends, &receives, capture.as_ref());
                    report.http = http.as_ref().map(crate::http_feed::Hub::stats);
                    report.mqtt = mqtt.as_ref().map(crate::mqtt_feed::Hub::stats);
                    report.shared_memory =
                        shared_memory.as_ref().map(crate::shared_memory::Hub::stats);
                    snapshot.report.clone_from(report);
                    snapshot.phase = "Cycling".into();
                    publish_payload(&mut snapshot, last, profile.tx_bytes, health.last_valid);
                }
                publish = observed + Duration::from_millis(100);
            }
            deadline = match profile.scheduler {
                Scheduler::Deadline => deadline + interval,
                Scheduler::Relative => now + interval,
            };
        }
        Ok(())
    })();
    report.cyclic_elapsed_us = start.elapsed().as_micros() as u64;
    health.refresh(&mut report.input_health, Instant::now());
    if result.is_ok() && !stop.load(Relaxed) {
        result = check_input_loss(&report.input_health, profile.input_loss_timeout_ms);
    }
    update(report, &sends, &receives, capture.as_ref());
    if let Some(http) = &http {
        http.deactivate();
        report.http = Some(http.stats());
    }
    if let Some(mqtt) = &mqtt {
        mqtt.deactivate();
        report.mqtt = Some(mqtt.stats());
    }
    if let Some(memory) = &shared_memory {
        memory.deactivate();
        report.shared_memory = Some(memory.stats());
    }
    if let Ok(mut snapshot) = view.try_lock() {
        snapshot.phase = "Stopping cyclic input".into();
        snapshot.report.clone_from(report);
        publish_payload(&mut snapshot, last, profile.tx_bytes, health.last_valid);
        snapshot.valid = false;
    }
    result = combine(result, bus.stop().map(|al| report.stopped_al = al));
    update(report, &sends, &receives, capture.as_ref());
    if let Some(capture) = capture {
        let (stats, write_result) = capture.finish();
        report.capture = Some(stats);
        result = combine(result, write_result.context("CSV capture incomplete"));
    }
    if let Some(http) = http.take() {
        report.http = Some(http.finish());
    }
    if let Some(mqtt) = mqtt.take() {
        report.mqtt = Some(mqtt.finish());
    }
    if let Some(memory) = shared_memory.take() {
        report.shared_memory = Some(memory.finish());
    }
    if let Ok(mut snapshot) = view.lock() {
        publish_payload(&mut snapshot, last, profile.tx_bytes, health.last_valid);
        snapshot.valid = false;
    }
    result?;
    ensure!(
        report.valid > 0 || stop.load(Relaxed),
        "no valid SAFEOP input exchanges"
    );
    Ok(())
}

fn publish_payload(
    snapshot: &mut Snapshot,
    last: Option<([u8; MAX_PAYLOAD], bool, bool)>,
    len: usize,
    last_valid_received_at: Option<Instant>,
) {
    snapshot.last_valid_received_at = last_valid_received_at;
    if let Some((data, replied, valid)) = last {
        snapshot.payload = data;
        snapshot.payload_len = if replied { len } else { 0 };
        snapshot.valid = valid;
    }
}

fn check_input_loss(health: &InputHealth, timeout_ms: u64) -> Result<()> {
    ensure!(
        timeout_ms == 0
            || health.consecutive_invalid == 0
            || health.ongoing_invalid_us < timeout_ms * 1000,
        "input loss timeout after {} us and {} consecutive invalid exchanges ({})",
        health.ongoing_invalid_us,
        health.consecutive_invalid,
        health.current_issue.map_or("unknown", InputIssue::label)
    );
    Ok(())
}

fn combine(primary: Result<()>, followup: Result<()>) -> Result<()> {
    match (primary, followup) {
        (Err(primary), Err(followup)) => Err(primary.context(format!("also failed: {followup:#}"))),
        (primary, followup) => primary.and(followup),
    }
}

fn feed_counts(report: &Report, capture: Option<&Capture>) -> crate::http_feed::Counts {
    crate::http_feed::Counts {
        cycles: report.cycles,
        valid: report.valid,
        timeouts: report.timeouts,
        wkc_mismatches: report.wkc_mismatches,
        al_mismatches: report.state_mismatches,
        transport_errors: report.transport_errors,
        missed_deadlines: report.missed_deadlines,
        csv: capture.map(Capture::counts),
    }
}

fn update(report: &mut Report, sends: &Gaps, receives: &Gaps, capture: Option<&Capture>) {
    report.send_spacing = sends.report();
    report.receive_spacing = receives.report();
    report.capture = capture.map(Capture::stats);
}

struct Simulated {
    faults: bool,
}

impl Bus for Simulated {
    fn exchange(&mut self, cycle: u64) -> Result<Option<Exchange>> {
        let sent = Instant::now();
        let mut data = [0; MAX_PAYLOAD];
        let step = ((cycle - 1) / 4) as u16;
        data[0..2].copy_from_slice(&step.to_le_bytes());
        data[2] = (step & 1) as u8;
        data[4..8].copy_from_slice(&(f32::from(step) / 4.0).to_le_bytes());
        Ok(Some(Exchange {
            sent,
            received: (!(self.faults && cycle.is_multiple_of(149))).then(Instant::now),
            wkc: u16::from(!(self.faults && cycle.is_multiple_of(97))),
            status: Some((4, 0)),
            data,
            ignored_frames: 0,
        }))
    }

    fn stop(&mut self) -> Result<Option<(u16, u16)>> {
        Ok(None)
    }
}

pub fn spawn(
    profile: Profile,
    options: RunOptions,
    stop: Arc<AtomicBool>,
    view: Arc<Mutex<Snapshot>>,
) -> Result<thread::JoinHandle<Report>> {
    Ok(thread::Builder::new()
        .name("ethercat-cycle".into())
        .spawn(move || run(profile, options, &stop, &view))?)
}

#[cfg(test)]
mod cycle_tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn early_non_expedited_mapping_replies_expose_the_pinned_initializer_gap_and_confirm_init() {
        use crate::virtual_esc::{InitialUploadForm, VirtualFault, VirtualModel};
        for (fault, form) in [
            (VirtualFault::InitNormalUpload, InitialUploadForm::Normal),
            (
                VirtualFault::InitSegmentedUpload,
                InitialUploadForm::SegmentedInitiation,
            ),
        ] {
            let profile: Profile =
                serde_json::from_str(include_str!("../samples/virtual.json")).unwrap();
            let report = run(
                profile,
                RunOptions {
                    frontend: crate::benchmark::Frontend::Cli,
                    mode: Mode::Virtual {
                        model: VirtualModel::Coe,
                        fault,
                    },
                    duration: Duration::from_millis(50),
                    csv: None,
                    generation: 1,
                },
                &AtomicBool::new(false),
                &Mutex::new(Snapshot::default()),
            );
            assert!(
                report.error.is_some(),
                "expected initializer incompatibility"
            );
            assert_eq!(report.stopped_al, Some((1, 0)), "{:?}", report.error);
            assert_eq!((report.cycles, report.valid), (0, 0));
            assert!(report.synchronization.is_none()); // Workbench post-PDI uploader was never reached.
            let audit = report.virtual_esc.unwrap();
            let upload = audit.initial_mapping_upload.unwrap();
            assert_eq!(
                (
                    upload.object_index,
                    upload.subindex,
                    upload.declared_bytes,
                    upload.form
                ),
                (0x1c13, 0, 1, form)
            );
            assert_eq!(audit.state_requests, vec![1, 2, 1]);
            assert_eq!(
                (
                    audit.logical_reads,
                    audit.logical_writes,
                    audit.physical_output_writes,
                    audit.op_requests,
                    audit.coe_downloads,
                    audit.dc_enable_requests,
                    audit.dc_clock_distribution
                ),
                (0, 0, 0, 0, 0, 0, 0)
            );
            assert_eq!(audit.coe_segments, 0); // Segmented initiation was rejected before any continuation.
            if form == InitialUploadForm::Normal {
                assert_eq!(audit.coe_normal_uploads, 1);
                assert_eq!(audit.coe_segmented_uploads, 0);
            } else {
                assert_eq!(audit.coe_normal_uploads, 0);
                assert_eq!(audit.coe_segmented_uploads, 1);
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn coe_cycle_setup_observations_preserve_optional_failures_and_reject_bad_primitive_sizes() {
        use crate::virtual_esc::{VirtualFault, VirtualModel};
        for (model, fault) in [
            (VirtualModel::Coe, VirtualFault::None),
            (VirtualModel::CoeNormal, VirtualFault::None),
            (VirtualModel::CoeSegmented, VirtualFault::None),
            (VirtualModel::Sii, VirtualFault::None),
            (VirtualModel::Coe, VirtualFault::SyncTimingUnavailable),
            (VirtualModel::Coe, VirtualFault::SyncTimingSize),
        ] {
            let profile: Profile = serde_json::from_str(match model {
                VirtualModel::Sii => include_str!("../samples/virtual-sii.json"),
                VirtualModel::CoeNormal => include_str!("../samples/virtual-normal.json"),
                VirtualModel::CoeSegmented => include_str!("../samples/virtual-segmented.json"),
                _ => include_str!("../samples/virtual.json"),
            })
            .unwrap();
            let report = run(
                profile,
                RunOptions {
                    frontend: crate::benchmark::Frontend::Cli,
                    mode: Mode::Virtual { model, fault },
                    duration: Duration::from_millis(50),
                    csv: None,
                    generation: 1,
                },
                &AtomicBool::new(false),
                &Mutex::new(Snapshot::default()),
            );
            assert_eq!(
                report.stopped_al,
                Some((1, 0)),
                "{model:?} {fault:?}: {:?}",
                report.error
            );
            let sync = report.synchronization.as_ref().unwrap_or_else(|| {
                panic!(
                    "{model:?} {fault:?}: setup observations missing: {:?}",
                    report.error
                )
            });
            if model == VirtualModel::Sii {
                assert!(sync.coe_cycle.is_none());
            } else {
                let cycle = sync.coe_cycle.as_ref().unwrap();
                let tx = cycle.tx.as_ref().unwrap();
                let rx = cycle.rx.as_ref().unwrap();
                assert_eq!((tx.object_index, rx.object_index), (0x1c33, 0x1c32));
                if fault == VirtualFault::None {
                    assert_eq!(
                        (
                            tx.cycle_ns.value,
                            tx.minimum_cycle_ns.value,
                            rx.cycle_ns.value,
                            rx.minimum_cycle_ns.value
                        ),
                        (Some(2_000_000), Some(0), Some(1_000_000), Some(250_000))
                    );
                } else {
                    assert!(tx.cycle_ns.value.is_none() && tx.cycle_ns.unavailable.is_some());
                }
            }
            if fault == VirtualFault::SyncTimingSize {
                assert!(report.error.is_some());
                assert_eq!(report.cycles, 0);
                assert_eq!(
                    report.virtual_esc.as_ref().unwrap().state_requests,
                    vec![1, 2, 1]
                );
            } else {
                assert!(
                    report.error.is_none(),
                    "{model:?} {fault:?}: {:?}",
                    report.error
                );
                assert!(report.valid > 0);
            }
            let audit = report.virtual_esc.as_ref().unwrap();
            assert_eq!(
                (
                    audit.op_requests,
                    audit.coe_downloads,
                    audit.logical_writes,
                    audit.physical_output_writes,
                    audit.dc_enable_requests,
                    audit.dc_clock_distribution
                ),
                (0, 0, 0, 0, 0, 0)
            );
        }
    }

    #[test]
    fn occupied_http_port_fails_before_virtual_device_setup() {
        let occupied = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut profile: Profile =
            serde_json::from_str(include_str!("../samples/virtual.json")).unwrap();
        profile.http = Some(crate::http_feed::Config {
            port: occupied.local_addr().unwrap().port(),
            ..Default::default()
        });
        let report = run(
            profile,
            RunOptions {
                frontend: crate::benchmark::Frontend::Cli,
                mode: Mode::Virtual {
                    model: crate::virtual_esc::VirtualModel::Coe,
                    fault: crate::virtual_esc::VirtualFault::None,
                },
                duration: Duration::from_millis(100),
                csv: None,
                generation: 1,
            },
            &AtomicBool::new(false),
            &Mutex::new(Snapshot::default()),
        );
        assert!(
            report
                .error
                .unwrap()
                .contains("bind read-only loopback HTTP")
        );
        assert_eq!(report.cycles, 0);
        assert!(report.virtual_esc.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn occupied_shared_name_fails_before_virtual_device_setup() {
        let config = crate::shared_memory::Config {
            name: format!("rust_preflight_{}", std::process::id()),
            ..Default::default()
        };
        let _bound = crate::shared_memory::Bound::bind(&config).unwrap();
        let mut profile: Profile =
            serde_json::from_str(include_str!("../samples/virtual.json")).unwrap();
        profile.shared_memory = Some(config);
        let report = run(
            profile,
            RunOptions {
                frontend: crate::benchmark::Frontend::Cli,
                mode: Mode::Virtual {
                    model: crate::virtual_esc::VirtualModel::Coe,
                    fault: crate::virtual_esc::VirtualFault::None,
                },
                duration: Duration::from_millis(100),
                csv: None,
                generation: 1,
            },
            &AtomicBool::new(false),
            &Mutex::new(Snapshot::default()),
        );
        assert!(report.error.unwrap().contains("name already exists"));
        assert_eq!(report.cycles, 0);
        assert!(report.virtual_esc.is_none());
    }

    struct FailingBus<'a> {
        view: &'a Mutex<Snapshot>,
        calls: u64,
        stopped: &'a AtomicBool,
    }

    impl Bus for FailingBus<'_> {
        fn exchange(&mut self, _cycle: u64) -> Result<Option<Exchange>> {
            self.calls += 1;
            if self.calls == 2 {
                anyhow::bail!("authored transport failure");
            }
            let at = Instant::now();
            Ok(Some(Exchange {
                sent: at,
                received: Some(at),
                wkc: 1,
                status: Some((4, 0)),
                data: [7; MAX_PAYLOAD],
                ignored_frames: 0,
            }))
        }

        fn stop(&mut self) -> Result<Option<(u16, u16)>> {
            let snapshot = self.view.lock().unwrap();
            assert!(!snapshot.valid);
            assert_eq!(snapshot.payload_len, 0);
            assert!(snapshot.last_valid_received_at.is_some());
            assert_eq!(
                snapshot.report.input_health.current_issue,
                Some(InputIssue::TransportError)
            );
            if let Some(http) = &snapshot.report.http {
                assert!(!http.active);
            }
            if let Some(mqtt) = &snapshot.report.mqtt {
                assert!(!mqtt.active);
            }
            if let Some(memory) = &snapshot.report.shared_memory {
                assert!(!memory.active);
            }
            self.stopped.store(true, Relaxed);
            anyhow::bail!("authored INIT cleanup failure")
        }
    }

    #[test]
    fn invalidates_before_cleanup_and_preserves_both_transport_and_cleanup_errors() {
        check_transport_cleanup(false);
        check_transport_cleanup(true);
    }

    fn check_transport_cleanup(with_http: bool) {
        let broker = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let profile = Profile {
            tx_bytes: 1,
            requested_cycle_us: 250,
            http: with_http.then_some(crate::http_feed::Config {
                port: 0,
                queue_capacity: 8,
                ..Default::default()
            }),
            mqtt: with_http.then_some(crate::mqtt_feed::Config {
                port: broker.local_addr().unwrap().port(),
                ..Default::default()
            }),
            shared_memory: with_http.then_some(crate::shared_memory::Config {
                name: format!("rust_cleanup_{}", std::process::id()),
                ..Default::default()
            }),
            ..Profile::default()
        };
        let options = RunOptions {
            frontend: crate::benchmark::Frontend::Cli,
            mode: Mode::Simulate { faults: false },
            duration: Duration::from_secs(1),
            csv: None,
            generation: 1,
        };
        let view = Mutex::new(Snapshot::default());
        let stopped = AtomicBool::new(false);
        let bus = FailingBus {
            view: &view,
            calls: 0,
            stopped: &stopped,
        };
        let mut report = Report {
            expected_wkc: 1,
            ..Report::default()
        };
        let http = profile
            .http
            .as_ref()
            .map(crate::http_feed::Bound::bind)
            .transpose()
            .unwrap();
        let error = cycle(
            bus,
            &profile,
            &options,
            &AtomicBool::new(false),
            &view,
            &mut report,
            &mut Bindings {
                http,
                shared_memory: profile
                    .shared_memory
                    .as_ref()
                    .map(crate::shared_memory::Bound::bind)
                    .transpose()
                    .unwrap(),
            },
        )
        .unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("authored transport failure"));
        assert!(text.contains("authored INIT cleanup failure"));
        assert!(stopped.load(Relaxed));
        assert_eq!(report.cycles, 2);
        assert_eq!(report.valid, 1);
        assert_eq!(report.transport_errors, 1);
        assert_eq!(report.actual_wkc, None);
        assert_eq!(report.input_health.last_valid_cycle, Some(1));
        assert_eq!(report.stopped_al, None);
        assert!(!view.lock().unwrap().valid);
        assert_eq!(report.http.is_some(), with_http);
        if let Some(feed) = report.http {
            assert!(!feed.active && !feed.worker_failed);
            assert_eq!(feed.worker_error, None);
            assert_eq!(feed.offered, 2);
            assert_eq!(feed.dispatched, 2);
            assert_eq!(feed.pending, 0);
            assert_eq!(feed.queue_drops, 0);
        }
        if let Some(feed) = report.mqtt {
            assert!(!feed.active && !feed.connected && !feed.worker_failed);
            assert_eq!(feed.offered, 2);
            assert_eq!(feed.drained, 2);
            assert_eq!(feed.queue_pending, 0);
        }
        if let Some(memory) = report.shared_memory {
            assert!(!memory.active && !memory.worker_failed && memory.shutdown_written);
            assert_eq!(memory.offered, 2);
            assert_eq!(memory.drained, 2);
            assert_eq!(memory.queue_pending, 0);
        }
    }
}

use crate::{
    capture::{Capture, CaptureStats},
    model::{Identity, MAX_PAYLOAD, Profile, Scheduler},
};
use anyhow::{Context, Result, ensure};
use hdrhistogram::Histogram;
use serde::Serialize;
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
    pub serial: Option<u32>,
    pub tx_bytes: Option<usize>,
    pub rx_bytes: Option<usize>,
    pub dc_support: Option<String>,
    pub al_status: u16,
    pub al_code: u16,
}

#[derive(Clone, Debug, Default, Serialize)]
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
    pub backend: String,
    pub requested_cycle_us: u64,
    pub scheduler: Scheduler,
    pub device_sync: String,
    pub dc_sync: String,
    pub synchronization: Option<crate::sync::Synchronization>,
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
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub phase: String,
    pub report: Report,
    pub payload: [u8; MAX_PAYLOAD],
    pub payload_len: usize,
    pub valid: bool,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            phase: "Starting".into(),
            report: Report::default(),
            payload: [0; MAX_PAYLOAD],
            payload_len: 0,
            valid: false,
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
        scheduler: profile.scheduler,
        connection_generation: options.generation,
        ..Report::default()
    };
    let result = run_inner(&profile, options, stop, view, &mut report);
    report.cancelled = stop.load(Relaxed);
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
    ensure!(profile.tx_bytes > 0, "a TxPDO image is required");
    ensure!(
        !options.duration.is_zero() && options.duration <= Duration::from_secs(86_400),
        "duration must be within 1 day"
    );
    ensure!(
        options.generation > 0,
        "connection generation must be positive"
    );
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
            cycle(Simulated { faults }, profile, &options, stop, view, report)
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
            cycle(replay, profile, &options, stop, view, report)?;
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
                    |bus, report| cycle(bus, profile, &options, stop, view, report),
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
                    cycle(bus, profile, &options, stop, view, report)
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

fn cycle(
    mut bus: impl Bus,
    profile: &Profile,
    options: &RunOptions,
    stop: &AtomicBool,
    view: &Mutex<Snapshot>,
    report: &mut Report,
) -> Result<()> {
    let mut capture = match options
        .csv
        .as_ref()
        .map(|path| Capture::start(path, profile))
        .transpose()
    {
        Ok(capture) => capture,
        Err(error) => {
            let cleanup = bus.stop().map(|al| report.stopped_al = al);
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
            let Some(exchange) = bus.exchange(index)? else {
                break;
            };
            report.cycles += 1;
            report.ignored_frames += exchange.ignored_frames;
            sends.tick(exchange.sent);
            report.actual_wkc = exchange.received.map(|_| exchange.wkc);
            let status_ok = exchange
                .status
                .is_some_and(|(status, code)| status & 0x1f == 4 && code == 0);
            if let Some((status, code)) = exchange.status
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
            last = Some((exchange.data, exchange.received.is_some(), valid));
            if now >= publish {
                if let Ok(mut snapshot) = view.try_lock() {
                    update(report, &sends, &receives, capture.as_ref());
                    snapshot.report.clone_from(report);
                    snapshot.phase = "Cycling".into();
                    publish_payload(&mut snapshot, last, profile.tx_bytes);
                }
                publish = now + Duration::from_millis(100);
            }
            deadline = match profile.scheduler {
                Scheduler::Deadline => deadline + interval,
                Scheduler::Relative => now + interval,
            };
        }
        Ok(())
    })();
    result = combine(result, bus.stop().map(|al| report.stopped_al = al));
    update(report, &sends, &receives, capture.as_ref());
    if let Some(capture) = capture {
        let (stats, write_result) = capture.finish();
        report.capture = Some(stats);
        result = combine(result, write_result.context("CSV capture incomplete"));
    }
    if let Ok(mut snapshot) = view.lock() {
        publish_payload(&mut snapshot, last, profile.tx_bytes);
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
) {
    if let Some((data, replied, valid)) = last {
        snapshot.payload = data;
        snapshot.payload_len = if replied { len } else { 0 };
        snapshot.valid = valid;
    }
}

fn combine(primary: Result<()>, followup: Result<()>) -> Result<()> {
    match (primary, followup) {
        (Err(primary), Err(followup)) => Err(primary.context(format!("also failed: {followup:#}"))),
        (primary, followup) => primary.and(followup),
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

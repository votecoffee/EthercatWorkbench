//! Exercise exact-width DC setup and teardown on one modeled reference station.
use super::{LiveBus, PacketIo, Transport, safeop_configured};
pub use crate::virtual_esc::DcRehearsalCase;
use crate::{
    esc::{AlStatus, al_status, clean_safeop},
    model::Profile,
    run::{Bus, DeviceInfo, Report as SetupReport, Snapshot},
    sync::{DcReadback, RegisterRead},
    sync_review,
    virtual_esc::{
        DC_ACTIVATION, DC_START, DC_SYNC0_CYCLE, DC_SYNC1_DELAY, DC_TIME, VirtualModel,
        VirtualStats, VirtualWire,
    },
};
use anyhow::{Context, Result, ensure};
use ethercrab::{Command, error::Error};
use serde::Serialize;
use std::sync::{Mutex, atomic::AtomicBool};

pub enum TimingRequest {
    Manual {
        period_ns: u32,
        sync1_delay_ns: Option<u32>,
    },
    StagedEsi,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TimingOrigin {
    Manual,
    StagedEsi {
        file_name: String,
        sha256: String,
        mode_index: usize,
        mode_name: String,
        sync_unit_cycle_ns: Option<u32>,
    },
}

fn resolve_timing(
    profile: &Profile,
    request: TimingRequest,
) -> Result<(u32, Option<u32>, TimingOrigin)> {
    if let TimingRequest::Manual {
        period_ns,
        sync1_delay_ns,
    } = request
    {
        return Ok((period_ns, sync1_delay_ns, TimingOrigin::Manual));
    }
    let review =
        sync_review::review(profile, None)?.context("--from-esi requires a staged ESI DC mode")?;
    let mode = &review.mode;
    ensure!(
        matches!(mode.assign_activate, 0x0300 | 0x0700),
        "staged mode needs AssignActivate 0x0300 or 0x0700"
    );
    ensure!(
        mode.notes.is_empty() && mode.sync_managers.is_empty(),
        "staged mode contains additional configuration outside the DC rehearsal"
    );
    ensure!(
        (mode.shift_sync0.is_none() || review.shift_sync0.value_ns == Some(0))
            && (mode.shift_sync1.is_none() || review.shift_sync1.value_ns == Some(0)),
        "staged mode needs absent or resolved zero SYNC shifts"
    );
    let period_ns = review
        .cycle_sync0
        .value_ns
        .and_then(|value| u32::try_from(value).ok())
        .with_context(|| format!("SYNC0 cycle unresolved: {}", review.cycle_sync0.detail))?;
    let sync1_delay_ns = if mode.assign_activate == 0x0700 {
        Some(
            review
                .cycle_sync1
                .value_ns
                .and_then(|value| u32::try_from(value).ok())
                .with_context(|| {
                    format!("SYNC1 delay unresolved: {}", review.cycle_sync1.detail)
                })?,
        )
    } else {
        ensure!(
            mode.cycle_sync1.is_none() || review.cycle_sync1.value_ns == Some(0),
            "SYNC0-only mode needs an absent or zero SYNC1 delay"
        );
        None
    };
    Ok((
        period_ns,
        sync1_delay_ns,
        TimingOrigin::StagedEsi {
            file_name: review.esi_file_name,
            sha256: review.esi_sha256,
            mode_index: review.mode_index,
            mode_name: review.mode.name,
            sync_unit_cycle_ns: review.sync_unit_cycle_ns,
        },
    ))
}

#[derive(Serialize)]
pub(super) struct Trial {
    period_ns: u32,
    start_delay_ns: u32,
    sync1_delay_ns: Option<u32>,
    timing_origin: TimingOrigin,
    #[serde(skip)]
    pub(super) attempted_station: Option<u16>,
    start_register_ns: Option<RegisterRead<u64>>,
    reference_before_cycles_ns: Option<RegisterRead<u64>>,
    activation_after_disable: Option<RegisterRead<u8>>,
}

impl Trial {
    fn activation(&self) -> u8 {
        if self.sync1_delay_ns.is_some() { 7 } else { 3 }
    }

    pub(super) fn sync_name(&self) -> &'static str {
        if self.sync1_delay_ns.is_some() {
            "virtual SYNC0+SYNC1"
        } else {
            "virtual SYNC0"
        }
    }

    pub(super) fn program(&mut self, bus: LiveBus<'_, '_>, stop: &AtomicBool) -> Result<()> {
        self.attempted_station = Some(bus.station);
        bus.port.drive(bus.tx, bus.rx, Some(stop), async {
            let station = bus.station;
            let main = bus.main;
            let now = Command::fprd(station, DC_TIME)
                .receive::<u64>(main)
                .await
                .context("read virtual reference before DC programming")?;
            let earliest = now
                .checked_add(u64::from(self.start_delay_ns))
                .context("DC start time overflow")?;
            let period = u64::from(self.period_ns);
            let start = earliest / period * period;
            ensure!(
                start > now,
                "virtual SYNC start time is unavailable or not a future aligned time"
            );
            // Use the register widths rather than the pinned group helper's u64 cycle payloads.
            Command::fpwr(station, DC_ACTIVATION)
                .send_receive::<u8>(main, 0u8)
                .await
                .context("clear DC activation before programming")?;
            Command::fpwr(station, DC_START)
                .send_receive::<u64>(main, start)
                .await
                .context("program DC start time")?;
            Command::fpwr(station, DC_SYNC0_CYCLE)
                .send_receive::<u32>(main, self.period_ns)
                .await
                .context("program SYNC0 cycle register")?;
            Command::fpwr(station, DC_SYNC1_DELAY)
                .send_receive::<u32>(main, self.sync1_delay_ns.unwrap_or(0))
                .await
                .context("program SYNC1 delay register")?;
            Command::fpwr(station, DC_ACTIVATION)
                .send_receive::<u8>(main, self.activation())
                .await
                .context("activate reviewed virtual DC outputs")?;
            Ok::<_, anyhow::Error>(())
        })
    }

    pub(super) fn confirm_active(
        &mut self,
        bus: LiveBus<'_, '_>,
        stop: &AtomicBool,
        dc: &DcReadback,
    ) -> Result<()> {
        let (start, reference) = bus.port.drive(bus.tx, bus.rx, Some(stop), async {
            let start = Command::fprd(bus.station, DC_START)
                .receive::<u64>(bus.main)
                .await;
            let reference = Command::fprd(bus.station, DC_TIME)
                .receive::<u64>(bus.main)
                .await;
            Ok::<_, Error>((
                RegisterRead::from_result(start),
                RegisterRead::from_result(reference),
            ))
        })?;
        let start_ns = start.value;
        let reference_ns = reference.value;
        self.start_register_ns = Some(start);
        self.reference_before_cycles_ns = Some(reference);
        let active = dc.activation.as_ref().and_then(|read| read.value);
        let assignment = dc.assign_activate.as_ref().and_then(|read| read.value);
        let expected = u16::from(self.activation()) << 8;
        ensure!(
            active == Some(self.activation()) && assignment == Some(expected),
            "virtual DC activation readback differs from {expected:#06x} (activation {active:?}, assignment {assignment:?})"
        );
        ensure!(
            dc.sync0_cycle_ns.as_ref().and_then(|read| read.value) == Some(self.period_ns)
                && dc.sync1_cycle_ns.as_ref().and_then(|read| read.value)
                    == Some(self.sync1_delay_ns.unwrap_or(0)),
            "virtual SYNC0 period or SYNC1 delay did not read back as requested"
        );
        ensure!(
            start_ns.zip(reference_ns).is_some_and(|(start, now)| {
                start > now && start.is_multiple_of(u64::from(self.period_ns))
            }),
            "virtual SYNC0 start time is unavailable or not a future aligned time"
        );
        Ok(())
    }

    pub(super) fn teardown(
        &mut self,
        mut bus: LiveBus<'_, '_>,
        report: &mut SetupReport,
    ) -> Result<()> {
        let sent = bus
            .port
            .drive(
                bus.tx,
                bus.rx,
                None,
                Command::fpwr(bus.station, DC_ACTIVATION).send_receive::<u8>(bus.main, 0u8),
            )
            .context("request virtual SYNC0 deactivation");
        let read = bus.port.drive(
            bus.tx,
            bus.rx,
            None,
            Command::fprd(bus.station, DC_ACTIVATION).receive::<u8>(bus.main),
        );
        let readback = RegisterRead::from_result(read);
        let confirmed = readback.value.is_some_and(|value| value & 7 == 0);
        self.activation_after_disable = Some(readback);
        // INIT is attempted even if the SYNC0 deactivation could not be confirmed.
        let init = bus.stop();
        let disable = sent.and_then(|_| {
            ensure!(confirmed, "virtual SYNC0 deactivation was not confirmed");
            Ok(())
        });
        match (disable, init) {
            (disable, Ok(al)) => {
                report.stopped_al = al;
                disable
            }
            (Err(disable), Err(init)) => {
                Err(disable.context(format!("INIT cleanup also failed: {init:#}")))
            }
            (_, Err(init)) => Err(init),
        }
    }
}

#[derive(Serialize)]
struct Cycle {
    index: u64,
    expected_reference_wkc: u16,
    reference_wkc: Option<u16>,
    reference_ns: Option<u64>,
    input_wkc: Option<u16>,
    al: Option<AlStatus>,
    tx_hex: Option<String>,
}

#[derive(Serialize)]
pub struct Report {
    schema: u32,
    scope: &'static str,
    scenario: DcRehearsalCase,
    timing_source: &'static str,
    host_requested_cycle_us: u64,
    requested_cycles: u64,
    trial: Trial,
    device: Option<DeviceInfo>,
    synchronization: Option<crate::sync::Synchronization>,
    setup_failure_al: Option<(u16, u16)>,
    stopped_al: Option<(u16, u16)>,
    cycles: Vec<Cycle>,
    wire: VirtualStats,
    pub error: Option<String>,
}

pub fn run(
    profile: &Profile,
    timing: TimingRequest,
    start_delay_ns: u32,
    cycles: u64,
    scenario: DcRehearsalCase,
) -> Result<Report> {
    profile.validate()?;
    ensure!(
        profile.expected_identity.as_ref() == Some(&VirtualModel::CoeDc.identity())
            && profile.tx_bytes == 8
            && profile.rx_bytes == 2,
        "SYNC0 rehearsal requires the authored CoE/DC identity with 8 TxPDO and 2 RxPDO bytes"
    );
    let (period_ns, sync1_delay_ns, timing_origin) = resolve_timing(profile, timing)?;
    ensure!(period_ns > 0, "SYNC0 period must be positive");
    ensure!(
        (1..=64).contains(&cycles),
        "SYNC0 rehearsal requires 1–64 cycles"
    );
    let mut trial = Trial {
        period_ns,
        start_delay_ns,
        sync1_delay_ns,
        timing_origin,
        attempted_station: None,
        start_register_ns: None,
        reference_before_cycles_ns: None,
        activation_after_disable: None,
    };
    let mut setup = SetupReport::default();
    let mut port = Transport {
        io: PacketIo::Virtual(Box::new(VirtualWire::for_dc_rehearsal(scenario))),
        seq: 0,
        ignored_frames: 0,
        mailbox_watch: None,
        mailbox_counter: None,
    };
    let mut records = Vec::with_capacity(cycles as usize);
    let stop = AtomicBool::new(false);
    let result = safeop_configured(
        profile,
        &stop,
        &Mutex::new(Snapshot::default()),
        &mut setup,
        &mut port,
        Some(&mut trial),
        |mut bus, report| {
            let dc = &mut report
                .synchronization
                .as_mut()
                .expect("readback verified")
                .dc;
            dc.cyclic_clock_distribution = true;
            report.dc_sync = dc.summary();
            run_cycles(&mut bus, &stop, cycles, &mut records)
        },
    );
    let PacketIo::Virtual(wire) = &port.io else {
        unreachable!("created in memory")
    };
    Ok(Report {
        schema: 1,
        scope: if sync1_delay_ns.is_some() {
            "virtual_sync01_rehearsal"
        } else {
            "virtual_sync0_rehearsal"
        },
        scenario,
        timing_source: "authored_reference_clock_unpaced_host",
        host_requested_cycle_us: profile.requested_cycle_us,
        requested_cycles: cycles,
        trial,
        device: setup.devices.into_iter().next(),
        synchronization: setup.synchronization,
        setup_failure_al: setup.setup_failure_al,
        stopped_al: setup.stopped_al,
        cycles: records,
        wire: wire.stats(),
        error: result.err().map(|error| format!("{error:#}")),
    })
}

fn run_cycles(
    bus: &mut LiveBus<'_, '_>,
    stop: &AtomicBool,
    cycles: u64,
    records: &mut Vec<Cycle>,
) -> Result<()> {
    for index in 1..=cycles {
        let mut cycle = Cycle {
            index,
            expected_reference_wkc: 1,
            reference_wkc: None,
            reference_ns: None,
            input_wkc: None,
            al: None,
            tx_hex: None,
        };
        // The sole configured station is the virtual reference. EtherCrab checks WKC 1.
        match bus.port.drive(
            bus.tx,
            bus.rx,
            Some(stop),
            Command::frmw(bus.station, DC_TIME).receive::<u64>(bus.main),
        ) {
            Ok(reference) => {
                cycle.reference_wkc = Some(1);
                cycle.reference_ns = Some(reference);
            }
            Err(error) => {
                if let Some(Error::WorkingCounter { received, .. }) = error.downcast_ref::<Error>()
                {
                    cycle.reference_wkc = Some(*received);
                }
                records.push(cycle);
                return Err(error).with_context(|| format!("reference clock exchange {index}"));
            }
        }
        let input = match bus
            .exchange(index)
            .context("read-only input exchange")
            .and_then(|exchange| exchange.context("missing input exchange"))
        {
            Ok(input) => input,
            Err(error) => {
                records.push(cycle);
                return Err(error);
            }
        };
        cycle.input_wkc = input.received.map(|_| input.wkc);
        cycle.al = input.status.map(|(raw, code)| al_status(raw, code));
        let valid = cycle.input_wkc == Some(1)
            && input
                .status
                .is_some_and(|(raw, code)| clean_safeop(raw, code));
        if valid {
            cycle.tx_hex = Some(hex::encode(&input.data[..bus.input]));
        }
        records.push(cycle);
        ensure!(valid, "input exchange {index} lacked WKC 1 or clean SAFEOP");
    }
    Ok(())
}

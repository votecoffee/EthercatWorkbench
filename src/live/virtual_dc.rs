//! Run one modeled SYNC0 station through the pinned EtherCrab setup and teardown.
use super::{LiveBus, PacketIo, Transport, safeop_configured};
pub use crate::virtual_esc::DcRehearsalCase;
use crate::{
    esc::{AlStatus, al_status, clean_safeop},
    model::Profile,
    run::{Bus, DeviceInfo, Report as SetupReport, Snapshot},
    sync::{DcReadback, RegisterRead},
    virtual_esc::{DC_ACTIVATION, DC_START, DC_TIME, VirtualModel, VirtualStats, VirtualWire},
};
use anyhow::{Context, Result, ensure};
use ethercrab::{Command, error::Error, subdevice_group::DcConfiguration};
use serde::Serialize;
use std::{
    sync::{Mutex, atomic::AtomicBool},
    time::Duration,
};

#[derive(Serialize)]
pub(super) struct Trial {
    period_ns: u32,
    start_delay_ns: u32,
    #[serde(skip)]
    pub(super) attempted_station: Option<u16>,
    start_register_ns: Option<RegisterRead<u64>>,
    reference_before_cycles_ns: Option<RegisterRead<u64>>,
    activation_after_disable: Option<RegisterRead<u8>>,
}

impl Trial {
    pub(super) fn configuration(&self) -> DcConfiguration {
        DcConfiguration {
            start_delay: Duration::from_nanos(u64::from(self.start_delay_ns)),
            sync0_period: Duration::from_nanos(u64::from(self.period_ns)),
            sync0_shift: Duration::ZERO,
        }
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
        ensure!(
            active == Some(3) && assignment == Some(0x0300),
            "virtual SYNC0 activation readback differs from 0x0300 (activation {active:?}, assignment {assignment:?})"
        );
        ensure!(
            dc.sync0_cycle_ns.as_ref().and_then(|read| read.value) == Some(self.period_ns)
                && dc.sync1_cycle_ns.as_ref().and_then(|read| read.value) == Some(0),
            "virtual SYNC0 period or disabled SYNC1 did not read back as requested"
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
                Command::fpwr(bus.station, DC_ACTIVATION).send(bus.main, 0u8),
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
    period_ns: u32,
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
    ensure!(period_ns > 0, "SYNC0 period must be positive");
    ensure!(
        (1..=64).contains(&cycles),
        "SYNC0 rehearsal requires 1–64 cycles"
    );
    let mut trial = Trial {
        period_ns,
        start_delay_ns,
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
        scope: "virtual_sync0_rehearsal",
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

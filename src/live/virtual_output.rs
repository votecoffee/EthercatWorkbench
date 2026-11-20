//! One-shot output rehearsal on an in-memory ESC.
use super::{AL_CONTROL, AL_STATUS, PacketIo, Transport, safeop_on};
pub use crate::virtual_esc::OutputRehearsalCase;
use crate::{
    esc::{AlStatus, al_status},
    model::{Profile, payload_hex},
    output_plan::Review,
    output_stage::profile_hash,
    pdo::{Entry, FieldState, Verification},
    run::{DeviceInfo, Report as SetupReport, Snapshot},
    virtual_esc::{OutputAudit, PD_WATCHDOG_STATUS, VirtualModel, VirtualStats, VirtualWire},
    wire::{Datagram, FPRD, FPWR, Frame, LWR},
};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use std::sync::{Arc, Mutex, atomic::AtomicBool};

const FRAME_STEP_US: u64 = 10;

#[derive(Serialize)]
struct Acknowledgement {
    expected_wkc: u16,
    actual_wkc: Option<u16>,
}

impl Acknowledgement {
    fn require_one(&self, operation: &str) -> Result<()> {
        match self.actual_wkc {
            Some(1) => Ok(()),
            Some(wkc) => bail!("{operation} WKC {wkc}, expected 1"),
            None => bail!("{operation} outcome unknown: missing matching reply"),
        }
    }
}

#[derive(Serialize)]
struct OpObservation {
    al: AlStatus,
    watchdog: WatchdogRead,
}

#[derive(Serialize)]
struct WatchdogRead {
    wkc: u16,
    raw: Option<u16>,
}

impl OpObservation {
    fn confirm(&self) -> Result<()> {
        confirm_state(&self.al, 8, "OP")?;
        let raw = self
            .watchdog
            .raw
            .context("OP watchdog status did not return WKC 1")?;
        ensure!(
            raw & 1 != 0,
            "OP watchdog status reports expired process data"
        );
        Ok(())
    }
}

#[derive(Serialize)]
struct Timing {
    clock: &'static str,
    frame_step_us: u64,
    max_op_us: u64,
    watchdog_us: u64,
    #[serde(skip)]
    op_requested_at_us: Option<u128>,
    blocked_write: Option<&'static str>,
    blocked_dispatch_elapsed_us: Option<u128>,
    init_request_elapsed_us: Option<u128>,
    init_confirmed_elapsed_us: Option<u128>,
    init_within_limit: Option<bool>,
}

impl Timing {
    fn elapsed(&self, now_us: u128) -> Option<u128> {
        self.op_requested_at_us.map(|start| now_us - start)
    }

    fn guard(&mut self, dispatch_us: u128, step: &'static str) -> Result<()> {
        let elapsed = self
            .elapsed(dispatch_us)
            .context("output deadline started before OP request")?;
        if elapsed >= u128::from(self.max_op_us) {
            self.blocked_write = Some(step);
            self.blocked_dispatch_elapsed_us = Some(elapsed);
            bail!(
                "OP time limit blocks {step} at {elapsed} us (limit {} us)",
                self.max_op_us
            );
        }
        Ok(())
    }
}

#[derive(Default, Serialize)]
struct Sequence {
    safeop: Option<AlStatus>,
    preload: Option<Acknowledgement>,
    op_request: Option<Acknowledgement>,
    op: Option<AlStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    op_watchdog: Option<WatchdogRead>,
    #[serde(skip_serializing_if = "Option::is_none")]
    before_safe_restore: Option<OpObservation>,
    output: Option<Acknowledgement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    safe_stop: Option<Acknowledgement>,
    init_request: Option<Acknowledgement>,
    init: Option<AlStatus>,
}

#[derive(Serialize)]
pub struct Report {
    schema: u32,
    scope: &'static str,
    scenario: OutputRehearsalCase,
    profile_sha256: String,
    staged_rx_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    plan_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    safe_rx_hex: Option<String>,
    device: Option<DeviceInfo>,
    pdo_verification: Option<Arc<Verification>>,
    setup_failure_al: Option<(u16, u16)>,
    setup_cleanup_al: Option<(u16, u16)>,
    sequence: Sequence,
    #[serde(skip_serializing_if = "Option::is_none")]
    timing: Option<Timing>,
    wire: VirtualStats,
    modeled_outputs: OutputAudit,
    pub error: Option<String>,
}

pub fn run(
    profile: &Profile,
    scenario: OutputRehearsalCase,
    plan: Option<&Review<'_>>,
) -> Result<Report> {
    profile.validate()?;
    let model = [
        VirtualModel::Coe,
        VirtualModel::Sii,
        VirtualModel::CoeDc,
        VirtualModel::CoeNormal,
        VirtualModel::CoeSegmented,
    ]
    .into_iter()
    .find(|model| profile.expected_identity.as_ref() == Some(&model.identity()))
    .context("output rehearsal requires an authored virtual device identity")?;
    ensure!(
        profile.tx_bytes == 8 && profile.rx_bytes == 2,
        "output rehearsal requires 8 TxPDO and 2 RxPDO bytes"
    );
    let bytes: [u8; 2] = payload_hex(&profile.staged_rx_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("stage an explicit two-byte RxPDO image first"))?;
    let profile_sha256 = profile_hash(profile)?;
    let safe = plan
        .map(|plan| {
            plan.check_profile(&profile_sha256)?;
            payload_hex(&plan.stop().safe_rx_hex)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("output plan must have a two-byte safe image"))
        })
        .transpose()?;
    let requires_plan = matches!(
        scenario,
        OutputRehearsalCase::SafeStopReplyLost
            | OutputRehearsalCase::WatchdogExpires
            | OutputRehearsalCase::WatchdogExpiresInOp
            | OutputRehearsalCase::WatchdogUnavailable
    );
    ensure!(
        !requires_plan || plan.is_some(),
        "this scenario requires a verified output plan"
    );
    let mut timing = plan.map(|review| Timing {
        clock: "modeled_frame_dispatch",
        frame_step_us: FRAME_STEP_US,
        max_op_us: review.stop().max_op_us,
        watchdog_us: review.stop().watchdog_us,
        op_requested_at_us: None,
        blocked_write: None,
        blocked_dispatch_elapsed_us: None,
        init_request_elapsed_us: None,
        init_confirmed_elapsed_us: None,
        init_within_limit: None,
    });
    let mut port = Transport {
        io: PacketIo::Virtual(Box::new(VirtualWire::for_output_rehearsal(
            model,
            scenario,
            timing.as_ref().map(|timing| timing.watchdog_us),
        ))),
        seq: 0,
        ignored_frames: 0,
        mailbox_watch: None,
        mailbox_counter: None,
    };
    let mut setup = SetupReport::default();
    let mut sequence = Sequence::default();
    let result = safeop_on(
        profile,
        &AtomicBool::new(false),
        &Mutex::new(Snapshot::default()),
        &mut setup,
        &mut port,
        |bus, report| {
            let PacketIo::Virtual(wire) = &mut bus.port.io else {
                bail!("output rehearsal requires in-memory transport");
            };
            let mut session = Session {
                wire,
                station: bus.station,
                index: bus.port.seq,
                output_sm: if model.has_coe() { 2 } else { 0 },
                now_us: 0,
                scenario,
            };
            let outcome = (|| {
                if let Some(serial) = plan.and_then(|plan| plan.stop().expected_serial) {
                    ensure!(
                        report.devices[0].serial == Some(serial),
                        "observed serial differs from output plan"
                    );
                }
                session.apply(
                    &bytes,
                    safe.as_ref(),
                    report.pdo_verification.as_deref(),
                    &mut sequence,
                    timing.as_mut(),
                )
            })();
            let cleanup = session.teardown(&mut sequence, timing.as_mut());
            match (outcome, cleanup) {
                (Err(error), Err(cleanup)) => {
                    Err(error.context(format!("INIT cleanup also failed: {cleanup:#}")))
                }
                (Err(error), _) | (_, Err(error)) => Err(error),
                (Ok(()), Ok(())) => {
                    if let Some(timing) = &timing
                        && timing.init_within_limit == Some(false)
                    {
                        bail!(
                            "INIT confirmed at {} us, beyond the OP time limit of {} us",
                            timing
                                .init_confirmed_elapsed_us
                                .expect("present for deadline check"),
                            timing.max_op_us
                        );
                    }
                    Ok(())
                }
            }
        },
    );
    let PacketIo::Virtual(wire) = &mut port.io else {
        unreachable!("created in memory")
    };
    Ok(Report {
        schema: 1,
        scope: "virtual_rxpdo_rehearsal",
        scenario,
        profile_sha256,
        staged_rx_hex: hex::encode_upper(bytes),
        plan_sha256: plan.map(|plan| plan.plan_sha256.clone()),
        safe_rx_hex: safe.map(hex::encode_upper),
        device: setup.devices.into_iter().next(),
        pdo_verification: setup.pdo_verification,
        setup_failure_al: setup.setup_failure_al,
        setup_cleanup_al: setup.stopped_al,
        sequence,
        timing,
        wire: wire.stats(),
        modeled_outputs: wire.output_audit(),
        error: result.err().map(|error| format!("{error:#}")),
    })
}

struct Session<'a> {
    wire: &'a mut VirtualWire,
    station: u16,
    index: u8,
    output_sm: u8,
    now_us: u128,
    scenario: OutputRehearsalCase,
}

impl Session<'_> {
    fn apply(
        &mut self,
        bytes: &[u8; 2],
        safe: Option<&[u8; 2]>,
        mapping: Option<&Verification>,
        receipt: &mut Sequence,
        mut timing: Option<&mut Timing>,
    ) -> Result<()> {
        let rx = &mapping.context("virtual RxPDO readback missing")?.rx;
        ensure!(
            rx.image_bytes == Some(2)
                && rx.entries
                    == [Entry {
                        sync_manager: self.output_sm,
                        pdo_index: 0x1600,
                        object_index: 0x7000,
                        subindex: 1,
                        bit: 0,
                        width: 16,
                    }]
                && rx.fields.len() == 1
                && matches!(rx.fields[0].state, FieldState::Matched),
            "output rehearsal requires a single fully matched RxPDO field covering the virtual image"
        );
        receipt.safeop = Some(self.read_al()?);
        confirm_state(receipt.safeop.as_ref().unwrap(), 4, "SAFEOP")?;
        // This model uses the two bytes immediately following its eight input bytes.
        self.write(&mut receipt.preload, LWR, 8, 0, safe.unwrap_or(bytes))?
            .require_one("SAFEOP preload")?;
        if let Some(timing) = timing.as_deref_mut() {
            timing.op_requested_at_us = Some(self.now_us);
        }
        self.write(
            &mut receipt.op_request,
            FPWR,
            self.station,
            AL_CONTROL,
            &[8, 0],
        )?
        .require_one("OP request")?;
        if let Some(timing) = timing.as_deref_mut() {
            let observed = self.observe_op()?;
            let result = observed.confirm();
            receipt.op = Some(observed.al);
            receipt.op_watchdog = Some(observed.watchdog);
            result?;
            timing.guard(self.next_dispatch(), "staged_write")?;
        } else {
            receipt.op = Some(self.read_al()?);
            confirm_state(receipt.op.as_ref().unwrap(), 8, "OP")?;
        }
        self.write(&mut receipt.output, LWR, 8, 0, bytes)?
            .require_one("OP output write")?;
        if let Some((safe, timing)) = safe.zip(timing) {
            if matches!(
                self.scenario,
                OutputRehearsalCase::WatchdogExpires | OutputRehearsalCase::WatchdogExpiresInOp
            ) {
                self.elapse(timing.watchdog_us);
            }
            // Budget for the next health read and the subsequent safe-image dispatch.
            timing.guard(
                self.next_dispatch() + u128::from(FRAME_STEP_US),
                "safe_restore",
            )?;
            receipt.before_safe_restore = Some(self.observe_op()?);
            receipt.before_safe_restore.as_ref().unwrap().confirm()?;
            self.write(&mut receipt.safe_stop, LWR, 8, 0, safe)?
                .require_one("safe-image write")?;
        }
        Ok(())
    }

    fn teardown(&mut self, receipt: &mut Sequence, mut timing: Option<&mut Timing>) -> Result<()> {
        if let Some(timing) = timing.as_deref_mut() {
            timing.init_request_elapsed_us = timing.elapsed(self.next_dispatch());
        }
        let request = self
            .write(
                &mut receipt.init_request,
                FPWR,
                self.station,
                AL_CONTROL,
                &[0x11, 0],
            )
            .and_then(|ack| ack.require_one("INIT request"));
        // AL readback independently establishes the final state even when the write reply is missing.
        receipt.init = Some(self.read_al().context("INIT readback")?);
        confirm_state(receipt.init.as_ref().unwrap(), 1, "INIT")?;
        if let Some(timing) = timing {
            timing.init_confirmed_elapsed_us = timing.elapsed(self.now_us);
            timing.init_within_limit = timing
                .init_confirmed_elapsed_us
                .map(|elapsed| elapsed <= u128::from(timing.max_op_us));
        }
        request
    }

    fn write<'a>(
        &mut self,
        receipt: &'a mut Option<Acknowledgement>,
        command: u8,
        adp: u16,
        ado: u16,
        payload: &[u8; 2],
    ) -> Result<&'a Acknowledgement> {
        self.index = self.index.wrapping_add(1);
        let frame = Frame::write(self.index, command, adp, ado, payload);
        let outcome = receipt.insert(Acknowledgement {
            expected_wkc: 1,
            actual_wkc: None,
        });
        self.send(frame.bytes())?;
        outcome.actual_wkc = self
            .wire
            .receive()
            .and_then(|reply| frame.reply(reply))
            .filter(|[(echo, _)]| *echo == payload)
            .map(|[(_, wkc)]| wkc);
        Ok(outcome)
    }

    fn read_al(&mut self) -> Result<AlStatus> {
        self.index = self.index.wrapping_add(1);
        let frame = Frame::new(
            self.index,
            [Datagram::register(FPRD, self.station, AL_STATUS, 6)],
        );
        self.send(frame.bytes())?;
        let [(bytes, wkc)] = self
            .wire
            .receive()
            .and_then(|reply| frame.reply(reply))
            .context("missing matching AL read reply")?;
        ensure!(wkc == 1, "AL read WKC {wkc}, expected 1");
        Ok(decode_al(bytes))
    }

    fn observe_op(&mut self) -> Result<OpObservation> {
        self.index = self.index.wrapping_add(1);
        let frame = Frame::new(
            self.index,
            [
                Datagram::register(FPRD, self.station, AL_STATUS, 6),
                Datagram::register(FPRD, self.station, PD_WATCHDOG_STATUS, 2),
            ],
        );
        self.send(frame.bytes())?;
        let [(al, al_wkc), (watchdog, wkc)] = self
            .wire
            .receive()
            .and_then(|reply| frame.reply(reply))
            .context("missing matching OP and watchdog reply")?;
        ensure!(al_wkc == 1, "AL read WKC {al_wkc}, expected 1");
        Ok(OpObservation {
            al: decode_al(al),
            watchdog: WatchdogRead {
                wkc,
                raw: (wkc == 1).then(|| u16::from_le_bytes([watchdog[0], watchdog[1]])),
            },
        })
    }

    fn next_dispatch(&self) -> u128 {
        self.now_us + u128::from(FRAME_STEP_US)
    }

    fn elapse(&mut self, delay_us: u64) {
        self.now_us += u128::from(delay_us);
        self.wire.advance_output_time(self.now_us);
    }

    fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.elapse(FRAME_STEP_US);
        self.wire.send(bytes)
    }
}

fn decode_al(bytes: &[u8]) -> AlStatus {
    al_status(
        u16::from_le_bytes([bytes[0], bytes[1]]),
        u16::from_le_bytes([bytes[4], bytes[5]]),
    )
}

fn confirm_state(al: &AlStatus, expected: u16, name: &str) -> Result<()> {
    ensure!(
        al.raw & 0x1f == expected && al.code == 0,
        "{name} confirmation failed, AL {:#06x} code {:#06x}",
        al.raw,
        al.code,
    );
    Ok(())
}

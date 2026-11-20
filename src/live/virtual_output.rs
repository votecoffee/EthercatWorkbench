//! One-shot output rehearsal on an in-memory ESC.
use super::{AL_CONTROL, AL_STATUS, PacketIo, Transport, safeop_on};
pub use crate::virtual_esc::OutputRehearsalCase;
use crate::{
    esc::{AlStatus, al_status},
    model::{Profile, payload_hex},
    output_stage::profile_hash,
    pdo::{Entry, FieldState, Verification},
    run::{DeviceInfo, Report as SetupReport, Snapshot},
    virtual_esc::{OutputAudit, VirtualModel, VirtualStats, VirtualWire},
    wire::{Datagram, FPRD, FPWR, Frame, LWR},
};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use std::sync::{Arc, Mutex, atomic::AtomicBool};

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

#[derive(Default, Serialize)]
struct Sequence {
    safeop: Option<AlStatus>,
    preload: Option<Acknowledgement>,
    op_request: Option<Acknowledgement>,
    op: Option<AlStatus>,
    output: Option<Acknowledgement>,
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
    device: Option<DeviceInfo>,
    pdo_verification: Option<Arc<Verification>>,
    setup_failure_al: Option<(u16, u16)>,
    setup_cleanup_al: Option<(u16, u16)>,
    sequence: Sequence,
    wire: VirtualStats,
    modeled_outputs: OutputAudit,
    pub error: Option<String>,
}

pub fn run(profile: &Profile, scenario: OutputRehearsalCase) -> Result<Report> {
    profile.validate()?;
    ensure!(
        profile.expected_identity.as_ref() == Some(&VirtualModel::Coe.identity())
            && profile.tx_bytes == 8
            && profile.rx_bytes == 2,
        "output rehearsal requires the authored CoE identity with 8 TxPDO and 2 RxPDO bytes"
    );
    let bytes: [u8; 2] = payload_hex(&profile.staged_rx_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("stage an explicit two-byte RxPDO image first"))?;
    let profile_sha256 = profile_hash(profile)?;
    let mut port = Transport {
        io: PacketIo::Virtual(Box::new(VirtualWire::for_output_rehearsal(scenario))),
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
            };
            let outcome = session.apply(&bytes, report.pdo_verification.as_deref(), &mut sequence);
            let cleanup = session.teardown(&mut sequence);
            match (outcome, cleanup) {
                (Err(error), Err(cleanup)) => {
                    Err(error.context(format!("INIT cleanup also failed: {cleanup:#}")))
                }
                (Err(error), _) | (_, Err(error)) => Err(error),
                _ => Ok(()),
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
        device: setup.devices.into_iter().next(),
        pdo_verification: setup.pdo_verification,
        setup_failure_al: setup.setup_failure_al,
        setup_cleanup_al: setup.stopped_al,
        sequence,
        wire: wire.stats(),
        modeled_outputs: wire.output_audit(),
        error: result.err().map(|error| format!("{error:#}")),
    })
}

struct Session<'a> {
    wire: &'a mut VirtualWire,
    station: u16,
    index: u8,
}

impl Session<'_> {
    fn apply(
        &mut self,
        bytes: &[u8; 2],
        mapping: Option<&Verification>,
        receipt: &mut Sequence,
    ) -> Result<()> {
        let rx = &mapping.context("virtual RxPDO readback missing")?.rx;
        ensure!(
            rx.image_bytes == Some(2)
                && rx.entries
                    == [Entry {
                        sync_manager: 2,
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
        self.write(&mut receipt.preload, LWR, 8, 0, bytes)?
            .require_one("SAFEOP preload")?;
        self.write(
            &mut receipt.op_request,
            FPWR,
            self.station,
            AL_CONTROL,
            &[8, 0],
        )?
        .require_one("OP request")?;
        receipt.op = Some(self.read_al()?);
        confirm_state(receipt.op.as_ref().unwrap(), 8, "OP")?;
        self.write(&mut receipt.output, LWR, 8, 0, bytes)?
            .require_one("OP output write")?;
        Ok(())
    }

    fn teardown(&mut self, receipt: &mut Sequence) -> Result<()> {
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
        self.wire.send(frame.bytes())?;
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
        self.wire.send(frame.bytes())?;
        let [(bytes, wkc)] = self
            .wire
            .receive()
            .and_then(|reply| frame.reply(reply))
            .context("missing matching AL read reply")?;
        ensure!(wkc == 1, "AL read WKC {wkc}, expected 1");
        Ok(al_status(
            u16::from_le_bytes([bytes[0], bytes[1]]),
            u16::from_le_bytes([bytes[4], bytes[5]]),
        ))
    }
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

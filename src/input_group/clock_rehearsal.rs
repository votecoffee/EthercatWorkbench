//! Rehearse clock distribution and clock-qualified inputs on the authored two-station wire.
use super::{
    InputGroup, Inspection, decode_frame_hex, preflight,
    replay::{Fixture, MAPPING_FIXTURE_SCHEMA, MODELED_UTC, RecordedCycle},
};
pub use crate::virtual_esc::GroupClockCase;
use crate::{
    virtual_esc::{
        DC_ACTIVATION, DC_SYNC0_CYCLE, DC_TIME, DC_TIME_DIFFERENCE, GROUP_DC, GROUP_STATIONS,
        VirtualStats, VirtualWire,
    },
    wire::{Datagram, FPRD, Frame},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

const REFERENCE: u16 = GROUP_STATIONS[0];
const FOLLOWER: u16 = GROUP_STATIONS[1];
const DISTRIBUTION_WKC: u16 = GROUP_STATIONS.len() as u16;
const MAX_CYCLES: usize = 64;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClockRecording {
    pub scenario: GroupClockCase,
    pub period_ns: u32,
    pub difference_limit_ns: u32,
    sync0_hex: String,
}

impl ClockRecording {
    pub(super) fn tracker(
        &self,
        group: &InputGroup,
        stations: &[u16],
        cycles: usize,
    ) -> Result<ClockTracker> {
        validate(group, self.period_ns, cycles)?;
        ensure!(
            stations == GROUP_STATIONS,
            "DC replay requires the authored station order"
        );
        read_sync0(&decode_frame_hex(&self.sync0_hex)?, self.period_ns)?;
        Ok(ClockTracker::new(self.difference_limit_ns))
    }

    pub(super) fn modeled_elapsed_us(&self, cycle: u64) -> u64 {
        (cycle - 1) * u64::from(self.period_ns) / 1_000
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClockFrames {
    distribution_hex: String,
    readback_hex: String,
}

pub(super) struct ClockTracker {
    input_slot: u8,
    previous: [Option<u64>; 2],
    difference_limit_ns: u32,
}

impl ClockTracker {
    fn new(difference_limit_ns: u32) -> Self {
        Self {
            input_slot: 3,
            previous: [None, None],
            difference_limit_ns,
        }
    }

    pub(super) fn input_slot(&self) -> u8 {
        self.input_slot
    }

    fn distribution_request(&self) -> Frame<1> {
        Frame::clock_request(self.input_slot - 2, REFERENCE, DC_TIME)
    }

    fn readback_request(&self) -> Frame<3> {
        Frame::new(
            self.input_slot - 1,
            [
                Datagram::register(FPRD, REFERENCE, DC_TIME, 8),
                Datagram::register(FPRD, FOLLOWER, DC_TIME, 8),
                Datagram::register(FPRD, FOLLOWER, DC_TIME_DIFFERENCE, 4),
            ],
        )
    }

    pub(super) fn inspect_recorded(&mut self, frames: ClockFrames) -> Result<ClockCheck> {
        self.inspect(
            &decode_frame_hex(&frames.distribution_hex)?,
            &decode_frame_hex(&frames.readback_hex)?,
        )
    }

    fn inspect(&mut self, distribution: &[u8], readback: &[u8]) -> Result<ClockCheck> {
        let [(payload, wkc)] = self
            .distribution_request()
            .reply(distribution)
            .context("FRMW reply does not match the expected clock distribution request")?;
        let readbacks = self
            .readback_request()
            .reply(readback)
            .context("FPRD reply does not match the expected clock readback request")?;
        let result = check_clock(
            read_u64(payload),
            wkc,
            readbacks,
            self.previous,
            self.difference_limit_ns,
        );
        if result.valid {
            self.previous = [result.reference.time_ns, result.follower.time_ns];
        }
        self.input_slot += 2 + u8::from(result.valid);
        Ok(result)
    }
}

pub struct Options {
    pub period_ns: u32,
    pub difference_limit_ns: u32,
    pub cycles: u32,
    pub scenario: GroupClockCase,
}

#[derive(Serialize)]
pub struct Report<'a> {
    schema: u32,
    source: &'static str,
    scenario: GroupClockCase,
    period_ns: u32,
    difference_limit_ns: u32,
    configured_sync0: [Sync0; 2],
    plan: Inspection<'a>,
    clock_rejections: usize,
    valid_input_cycles: usize,
    cycles: Vec<Cycle<'a>>,
    wire_audit: Vec<VirtualStats>,
}

#[derive(Serialize)]
struct Sync0 {
    station: u16,
    activation: u8,
    period_ns: u32,
}

#[derive(Serialize)]
struct Cycle<'a> {
    cycle_index: u32,
    clock: ClockCheck,
    input: Option<Inspection<'a>>,
}

#[derive(Debug, Serialize)]
pub struct ClockCheck {
    pub expected_distribution_wkc: u16,
    pub actual_distribution_wkc: u16,
    frmw_payload_ns: u64,
    reference: ClockRead,
    follower: ClockRead,
    pub difference: DifferenceRead,
    raw_follower_minus_reference_ns: Option<i128>,
    pub issues: Vec<&'static str>,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
struct ClockRead {
    station: u16,
    wkc: u16,
    time_ns: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct DifferenceRead {
    wkc: u16,
    raw: Option<u32>,
    pub received_minus_local_ns: Option<i64>,
}

pub fn run(group: &InputGroup, options: Options) -> Result<Report<'_>> {
    Ok(rehearse(group, options, false)?.0)
}

pub fn generate_replay(group: &InputGroup, options: Options) -> Result<Fixture> {
    let (_, fixture) = rehearse(group, options, true)?;
    Ok(fixture.expect("recorded rehearsal"))
}

fn validate(group: &InputGroup, period_ns: u32, cycles: usize) -> Result<()> {
    ensure!(
        preflight::matches_fixture(group, GROUP_DC),
        "group clock rehearsal requires two authored CoE/DC identities with 8 TxPDO and 2 RxPDO bytes each"
    );
    ensure!(period_ns > 0, "SYNC0 period must be positive");
    ensure!(
        (1..=MAX_CYCLES).contains(&cycles),
        "rehearsal requires 1–{MAX_CYCLES} cycles"
    );
    Ok(())
}

fn rehearse(
    group: &InputGroup,
    options: Options,
    record: bool,
) -> Result<(Report<'_>, Option<Fixture>)> {
    validate(group, options.period_ns, options.cycles as usize)?;
    let mut wire = VirtualWire::for_group_dc(options.scenario, options.period_ns);
    let mut plan = group.inspect(None)?;
    let (mapping, replies) =
        preflight::require_valid_mapping(group, &mut wire, &GROUP_STATIONS, 0)?;
    mapping.attach(&mut plan);
    let sync0 = exchange(&mut wire, &sync0_request())?;
    let configured_sync0 = read_sync0(sync0, options.period_ns)?;
    let mut fixture = if record {
        let topology = plan
            .topology
            .as_ref()
            .context("missing verified setup topology")?;
        Some(Fixture {
            schema: MAPPING_FIXTURE_SCHEMA,
            virtual_scenario: None,
            virtual_dc: Some(ClockRecording {
                scenario: options.scenario,
                period_ns: options.period_ns,
                difference_limit_ns: options.difference_limit_ns,
                sync0_hex: hex::encode(sync0),
            }),
            capture_start_utc: MODELED_UTC.into(),
            stations: GROUP_STATIONS.to_vec(),
            setup_topology: Some(vec![topology.recording(1, replies)]),
            cycles: Vec::with_capacity(options.cycles as usize),
        })
    } else {
        None
    };
    let mut tracker = ClockTracker::new(options.difference_limit_ns);
    let mut cycles = Vec::with_capacity(options.cycles as usize);
    for cycle_index in 1..=options.cycles {
        let index = tracker.input_slot();
        let distribution = exchange(&mut wire, &tracker.distribution_request())?.to_vec();
        let readback = exchange(&mut wire, &tracker.readback_request())?;
        let clock = tracker.inspect(&distribution, readback)?;
        let clock_frames = record.then(|| ClockFrames {
            distribution_hex: hex::encode(&distribution),
            readback_hex: hex::encode(readback),
        });

        let mut received_hex = Vec::new();
        let input = if clock.valid {
            let frame = group.expected_frame(index, &GROUP_STATIONS)?;
            let reply = exchange(&mut wire, &frame)?;
            if record {
                received_hex.push(hex::encode(reply));
            }
            Some(group.inspect_reply(index, &GROUP_STATIONS, reply, None)?)
        } else {
            None
        };
        if let Some(fixture) = &mut fixture {
            let cycle = u64::from(cycle_index);
            let policy = fixture
                .virtual_dc
                .as_ref()
                .expect("recorded clock settings");
            fixture.cycles.push(RecordedCycle {
                connection_generation: 1,
                cycle_index: cycle,
                index,
                elapsed_us: input.as_ref().map(|_| policy.modeled_elapsed_us(cycle)),
                received_hex,
                clock_frames,
            });
        }
        cycles.push(Cycle {
            cycle_index,
            clock,
            input,
        });
    }

    let report = Report {
        schema: 1,
        source: "virtual_group_dc_rehearsal",
        scenario: options.scenario,
        period_ns: options.period_ns,
        difference_limit_ns: options.difference_limit_ns,
        configured_sync0,
        plan,
        clock_rejections: cycles.iter().filter(|cycle| !cycle.clock.valid).count(),
        valid_input_cycles: cycles
            .iter()
            .filter(|cycle| {
                cycle
                    .input
                    .as_ref()
                    .and_then(|input| input.frame.as_ref())
                    .is_some_and(|frame| frame.valid)
            })
            .count(),
        cycles,
        wire_audit: wire.chain_audits(),
    };
    Ok((report, fixture))
}

fn exchange<'a, const N: usize>(wire: &'a mut VirtualWire, frame: &Frame<N>) -> Result<&'a [u8]> {
    wire.send(frame.bytes())?;
    wire.receive().context("missing clock rehearsal reply")
}

fn sync0_request() -> Frame<4> {
    Frame::new(
        0,
        [
            Datagram::register(FPRD, REFERENCE, DC_ACTIVATION, 1),
            Datagram::register(FPRD, REFERENCE, DC_SYNC0_CYCLE, 4),
            Datagram::register(FPRD, FOLLOWER, DC_ACTIVATION, 1),
            Datagram::register(FPRD, FOLLOWER, DC_SYNC0_CYCLE, 4),
        ],
    )
}

fn read_sync0(reply: &[u8], expected_period_ns: u32) -> Result<[Sync0; 2]> {
    let [
        (ref_activation, ref_awkc),
        (ref_period, ref_pwkc),
        (follower_activation, follower_awkc),
        (follower_period, follower_pwkc),
    ] = sync0_request()
        .reply(reply)
        .context("FPRD reply does not match the expected SYNC0 register request")?;
    ensure!(
        [ref_awkc, ref_pwkc, follower_awkc, follower_pwkc] == [1; 4],
        "SYNC0 register readback WKC mismatch"
    );
    let settings = [
        Sync0 {
            station: REFERENCE,
            activation: ref_activation[0],
            period_ns: read_u32(ref_period),
        },
        Sync0 {
            station: FOLLOWER,
            activation: follower_activation[0],
            period_ns: read_u32(follower_period),
        },
    ];
    ensure!(
        settings
            .iter()
            .all(|value| value.activation == 3 && value.period_ns == expected_period_ns),
        "SYNC0 readback does not match the authored schedule"
    );
    Ok(settings)
}

fn check_clock(
    frmw_payload_ns: u64,
    actual_distribution_wkc: u16,
    [
        (reference, reference_wkc),
        (follower, follower_wkc),
        (difference, difference_wkc),
    ]: [(&[u8], u16); 3],
    previous: [Option<u64>; 2],
    difference_limit_ns: u32,
) -> ClockCheck {
    let reference = ClockRead {
        station: REFERENCE,
        wkc: reference_wkc,
        time_ns: (reference_wkc == 1).then(|| read_u64(reference)),
    };
    let follower = ClockRead {
        station: FOLLOWER,
        wkc: follower_wkc,
        time_ns: (follower_wkc == 1).then(|| read_u64(follower)),
    };
    let raw = (difference_wkc == 1).then(|| read_u32(difference));
    let difference = DifferenceRead {
        wkc: difference_wkc,
        raw,
        received_minus_local_ns: raw.map(|value| {
            let magnitude = i64::from(value & 0x7fff_ffff);
            if value & 0x8000_0000 == 0 {
                magnitude
            } else {
                -magnitude
            }
        }),
    };

    let mut issues = Vec::new();
    if actual_distribution_wkc != DISTRIBUTION_WKC {
        issues.push("distribution_wkc");
    }
    if reference.wkc != 1 {
        issues.push("reference_time_wkc");
    }
    if follower.wkc != 1 {
        issues.push("follower_time_wkc");
    }
    if difference.wkc != 1 {
        issues.push("difference_wkc");
    }
    if reference
        .time_ns
        .is_some_and(|time| time != frmw_payload_ns)
    {
        issues.push("reference_payload_mismatch");
    }
    for (clock, old, issue) in [
        (&reference, previous[0], "reference_time_not_new"),
        (&follower, previous[1], "follower_time_not_new"),
    ] {
        if clock
            .time_ns
            .zip(old)
            .is_some_and(|(time, prior)| time <= prior)
        {
            issues.push(issue);
        }
    }
    if difference
        .received_minus_local_ns
        .is_some_and(|value| value.unsigned_abs() > u64::from(difference_limit_ns))
    {
        issues.push("difference_outside_limit");
    }
    ClockCheck {
        expected_distribution_wkc: DISTRIBUTION_WKC,
        actual_distribution_wkc,
        frmw_payload_ns,
        raw_follower_minus_reference_ns: follower
            .time_ns
            .zip(reference.time_ns)
            .map(|(follower, reference)| i128::from(follower) - i128::from(reference)),
        reference,
        follower,
        difference,
        valid: issues.is_empty(),
        issues,
    }
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("8-byte clock reply"))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("4-byte register reply"))
}

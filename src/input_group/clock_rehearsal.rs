//! Rehearse clock distribution and clock-qualified inputs on the authored virtual groups.
use super::{
    InputGroup, Inspection, decode_frame_hex, preflight,
    preflight::topology::{GenerationCheck, Recording, RuntimeCheck},
    replay::{
        DC_RECONNECT_FIXTURE_SCHEMA, Fixture, MAPPING_FIXTURE_SCHEMA, MODELED_UTC,
        MONITORED_FIXTURE_SCHEMA, RecordedCycle,
    },
};
pub use crate::virtual_esc::GroupClockCase;
use crate::{
    virtual_esc::{
        DC_ACTIVATION, DC_SYNC0_CYCLE, DC_TIME, DC_TIME_DIFFERENCE, GROUP_DC, GROUP_DC_THREE,
        GroupFixture, VirtualStats, VirtualWire,
    },
    wire::{Datagram, FPRD, Frame},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

const MAX_SYNC0_DATAGRAMS: usize = 2 * GROUP_DC_THREE.stations.len();
const MAX_READBACK_DATAGRAMS: usize = MAX_SYNC0_DATAGRAMS - 1;
const MAX_CYCLES: usize = 64;
const SWAP_CYCLE: u32 = 4;
const RESTORE_CYCLE: u32 = 6;
const FIRST_GENERATION_CYCLES: u32 = 8;
// Leave room for topology, register readback, SYNC0 and eight cycles before generation two.
const SECOND_SETUP_INDEX: u8 = 56;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClockRecording {
    pub scenario: GroupClockCase,
    pub period_ns: u32,
    pub difference_limit_ns: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    sync0_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sync0_by_generation: Option<[RecordedSync0; 2]>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordedSync0 {
    connection_generation: u64,
    reply_hex: String,
}

impl ClockRecording {
    pub(super) fn monitors_topology(&self) -> bool {
        self.scenario == GroupClockCase::TopologyChange
    }

    pub(super) fn reconnects(&self) -> bool {
        self.scenario == GroupClockCase::TopologyReconnect
    }

    pub(super) fn cycle_position(&self, ordinal: u64) -> (u64, u64) {
        let first_count = u64::from(FIRST_GENERATION_CYCLES);
        if self.reconnects() && ordinal > first_count {
            (2, ordinal - first_count)
        } else {
            (1, ordinal)
        }
    }

    pub(super) fn trackers(
        &self,
        group: &InputGroup,
        stations: &[u16],
        cycles: usize,
        setup: Option<&mut [GenerationCheck]>,
    ) -> Result<Vec<ClockTracker>> {
        let fixture = validate(group, self.period_ns, cycles, self.scenario)?;
        ensure!(
            stations == fixture.stations,
            "DC replay requires the authored station order"
        );
        match (
            self.reconnects(),
            self.sync0_hex.as_deref(),
            &self.sync0_by_generation,
        ) {
            (false, Some(legacy), None) => {
                read_sync0(stations, 0, &decode_frame_hex(legacy)?, self.period_ns)?;
                Ok(vec![ClockTracker::new(
                    fixture.stations,
                    self.difference_limit_ns,
                    0,
                )])
            }
            (true, None, Some(readbacks)) => {
                let setup = setup.context("DC reconnect requires two verified setups")?;
                ensure!(
                    setup.len() == 2,
                    "DC reconnect requires two verified setups"
                );
                readbacks
                    .iter()
                    .zip(setup)
                    .enumerate()
                    .map(|(index, (saved, checked))| {
                        let generation = index as u64 + 1;
                        let [before, after] = checked.topology.probe_indexes();
                        ensure!(
                            saved.connection_generation == generation
                                && checked.connection_generation == generation
                                && before == setup_index(generation),
                            "DC setup evidence does not match generation {generation}"
                        );
                        let slot = after.checked_add(1).context("missing SYNC0 frame slot")?;
                        checked.configured_sync0 = Some(
                            read_sync0(
                                stations,
                                slot,
                                &decode_frame_hex(&saved.reply_hex)?,
                                self.period_ns,
                            )
                            .with_context(|| format!("SYNC0 setup for generation {generation}"))?,
                        );
                        Ok(ClockTracker::new(
                            fixture.stations,
                            self.difference_limit_ns,
                            slot,
                        ))
                    })
                    .collect()
            }
            _ => anyhow::bail!("DC replay requires the SYNC0 evidence for its fixture schema"),
        }
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
    stations: &'static [u16],
    previous: Vec<Option<u64>>,
    difference_limit_ns: u32,
}

impl ClockTracker {
    fn new(stations: &'static [u16], difference_limit_ns: u32, sync0_index: u8) -> Self {
        Self {
            input_slot: sync0_index.wrapping_add(3),
            stations,
            previous: vec![None; stations.len()],
            difference_limit_ns,
        }
    }

    pub(super) fn input_slot(&self) -> u8 {
        self.input_slot
    }

    fn distribution_request(&self) -> Frame<1> {
        Frame::clock_request(self.input_slot.wrapping_sub(2), self.stations[0], DC_TIME)
    }

    fn readback_request(&self) -> Frame<MAX_READBACK_DATAGRAMS> {
        let mut parts =
            [Datagram::register(FPRD, self.stations[0], DC_TIME, 8); MAX_READBACK_DATAGRAMS];
        let mut used = 1;
        for &station in &self.stations[1..] {
            parts[used..used + 2].copy_from_slice(&[
                Datagram::register(FPRD, station, DC_TIME, 8),
                Datagram::register(FPRD, station, DC_TIME_DIFFERENCE, 4),
            ]);
            used += 2;
        }
        Frame::with_count(self.input_slot.wrapping_sub(1), parts, used)
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
            self.stations,
            read_u64(payload),
            wkc,
            &readbacks,
            &self.previous,
            self.difference_limit_ns,
        );
        if result.valid {
            self.previous[0] = result.reference.time_ns;
            self.previous[1] = result.follower.time_ns;
            for (previous, follower) in self.previous[2..]
                .iter_mut()
                .zip(&result.additional_followers)
            {
                *previous = follower.follower.time_ns;
            }
        }
        self.input_slot = self.input_slot.wrapping_add(2 + u8::from(result.valid));
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
    #[serde(flatten)]
    initial_setup: Setup<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reconnected_setup: Option<Setup<'a>>,
    clock_rejections: usize,
    valid_input_cycles: usize,
    cycles: Vec<Cycle<'a>>,
}

#[derive(Serialize)]
struct Setup<'a> {
    configured_sync0: Vec<Sync0>,
    plan: Inspection<'a>,
    wire_audit: Vec<VirtualStats>,
}

#[derive(Serialize)]
pub(super) struct Sync0 {
    station: u16,
    activation: u8,
    period_ns: u32,
}

#[derive(Serialize)]
struct Cycle<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_generation: Option<u64>,
    cycle_index: u32,
    clock: ClockCheck,
    #[serde(skip_serializing_if = "Option::is_none")]
    cyclic_topology: Option<RuntimeCheck>,
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub additional_followers: Vec<FollowerCheck>,
    pub issues: Vec<&'static str>,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct FollowerCheck {
    follower: ClockRead,
    pub difference: DifferenceRead,
    raw_follower_minus_reference_ns: Option<i128>,
    pub issues: Vec<&'static str>,
}

impl FollowerCheck {
    pub fn station(&self) -> u16 {
        self.follower.station
    }

    fn new(
        station: u16,
        time: (&[u8], u16),
        difference: (&[u8], u16),
        reference: Option<u64>,
    ) -> Self {
        let follower = ClockRead::new(station, time);
        let (bytes, wkc) = difference;
        let raw = (wkc == 1).then(|| read_u32(bytes));
        let difference = DifferenceRead {
            wkc,
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
        Self {
            raw_follower_minus_reference_ns: follower
                .time_ns
                .zip(reference)
                .map(|(follower, reference)| i128::from(follower) - i128::from(reference)),
            follower,
            difference,
            issues: Vec::new(),
        }
    }

    fn read_issues(&self, issues: &mut Vec<&'static str>) {
        if self.follower.wkc != 1 {
            issues.push("follower_time_wkc");
        }
        if self.difference.wkc != 1 {
            issues.push("difference_wkc");
        }
    }

    fn timing_issues(&self, previous: Option<u64>, limit: u32, issues: &mut Vec<&'static str>) {
        if self.follower.not_new(previous) {
            issues.push("follower_time_not_new");
        }
        if self
            .difference
            .received_minus_local_ns
            .is_some_and(|value| value.unsigned_abs() > u64::from(limit))
        {
            issues.push("difference_outside_limit");
        }
    }
}

#[derive(Debug, Serialize)]
struct ClockRead {
    station: u16,
    wkc: u16,
    time_ns: Option<u64>,
}

impl ClockRead {
    fn new(station: u16, (data, wkc): (&[u8], u16)) -> Self {
        Self {
            station,
            wkc,
            time_ns: (wkc == 1).then(|| read_u64(data)),
        }
    }

    fn not_new(&self, previous: Option<u64>) -> bool {
        self.time_ns
            .zip(previous)
            .is_some_and(|(time, prior)| time <= prior)
    }
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

fn validate(
    group: &InputGroup,
    period_ns: u32,
    cycles: usize,
    scenario: GroupClockCase,
) -> Result<GroupFixture> {
    let fixture = [GROUP_DC, GROUP_DC_THREE]
        .into_iter()
        .find(|fixture| preflight::matches_fixture(group, *fixture))
        .context("group clock rehearsal requires two authored CoE/DC stations with PDOs, or three with a no-PDO middle station")?;
    ensure!(period_ns > 0, "SYNC0 period must be positive");
    ensure!(
        (1..=MAX_CYCLES).contains(&cycles),
        "rehearsal requires 1–{MAX_CYCLES} cycles"
    );
    ensure!(
        scenario != GroupClockCase::MiddleFollowerStale || fixture.stations.len() == 3,
        "middle-follower-stale requires the three-station DC fixture"
    );
    if scenario == GroupClockCase::TopologyChange {
        ensure!(
            fixture.stations.len() == 3,
            "topology-change requires the three-station DC fixture"
        );
        ensure!(
            cycles >= RESTORE_CYCLE as usize,
            "topology-change requires at least {RESTORE_CYCLE} cycles"
        );
    }
    if scenario == GroupClockCase::TopologyReconnect {
        ensure!(
            fixture.stations.len() == 3,
            "topology-reconnect requires the three-station DC fixture"
        );
        let minimum = FIRST_GENERATION_CYCLES + 2;
        ensure!(
            cycles >= minimum as usize,
            "topology-reconnect requires at least {minimum} cycles"
        );
    }
    Ok(fixture)
}

fn setup_index(generation: u64) -> u8 {
    if generation == 1 {
        0
    } else {
        SECOND_SETUP_INDEX
    }
}

pub(super) fn modeled_elapsed_us(ordinal: u64, period_ns: u32) -> u64 {
    (ordinal - 1) * u64::from(period_ns) / 1_000
}

#[derive(Default)]
struct RecordingBuffers {
    topology: Vec<Recording>,
    sync0: Vec<RecordedSync0>,
    cycles: Vec<RecordedCycle>,
}

fn rehearse(
    group: &InputGroup,
    options: Options,
    record: bool,
) -> Result<(Report<'_>, Option<Fixture>)> {
    let layout = validate(
        group,
        options.period_ns,
        options.cycles as usize,
        options.scenario,
    )?;
    let reconnects = options.scenario == GroupClockCase::TopologyReconnect;
    let mut recording = record.then(RecordingBuffers::default);
    let mut cycles = Vec::with_capacity(options.cycles as usize);
    let initial_setup =
        rehearse_generation(group, layout, &options, 1, &mut cycles, &mut recording)?;
    let reconnected_setup = if reconnects {
        Some(rehearse_generation(
            group,
            layout,
            &options,
            2,
            &mut cycles,
            &mut recording,
        )?)
    } else {
        None
    };
    let fixture = recording.map(|recorded| {
        let (schema, sync0_hex, sync0_by_generation) = if reconnects {
            (
                DC_RECONNECT_FIXTURE_SCHEMA,
                None,
                Some(
                    recorded
                        .sync0
                        .try_into()
                        .expect("two recorded SYNC0 replies"),
                ),
            )
        } else {
            (
                if options.scenario == GroupClockCase::TopologyChange {
                    MONITORED_FIXTURE_SCHEMA
                } else {
                    MAPPING_FIXTURE_SCHEMA
                },
                Some(
                    recorded
                        .sync0
                        .into_iter()
                        .next()
                        .expect("recorded SYNC0 reply")
                        .reply_hex,
                ),
                None,
            )
        };
        Fixture {
            schema,
            virtual_scenario: None,
            virtual_dc: Some(ClockRecording {
                scenario: options.scenario,
                period_ns: options.period_ns,
                difference_limit_ns: options.difference_limit_ns,
                sync0_hex,
                sync0_by_generation,
            }),
            capture_start_utc: MODELED_UTC.into(),
            stations: layout.stations.to_vec(),
            setup_topology: Some(recorded.topology),
            cycles: recorded.cycles,
        }
    });
    let report = Report {
        schema: 1,
        source: "virtual_group_dc_rehearsal",
        scenario: options.scenario,
        period_ns: options.period_ns,
        difference_limit_ns: options.difference_limit_ns,
        initial_setup,
        reconnected_setup,
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
    };
    Ok((report, fixture))
}

fn rehearse_generation<'a>(
    group: &'a InputGroup,
    layout: GroupFixture,
    options: &Options,
    generation: u64,
    cycles: &mut Vec<Cycle<'a>>,
    recording: &mut Option<RecordingBuffers>,
) -> Result<Setup<'a>> {
    let stations = layout.stations;
    let reconnects = options.scenario == GroupClockCase::TopologyReconnect;
    let monitored = reconnects || options.scenario == GroupClockCase::TopologyChange;
    let (clock_case, fault_cycle) = if generation == 2 {
        (GroupClockCase::FollowerWkc, 1)
    } else if monitored {
        (GroupClockCase::MiddleFollowerStale, 2)
    } else {
        (options.scenario, 2)
    };
    let mut wire = VirtualWire::for_group_dc(layout, clock_case, options.period_ns, fault_cycle);
    let mut plan = group.inspect(None)?;
    let (mapping, replies) =
        preflight::require_valid_mapping(group, &mut wire, stations, setup_index(generation))?;
    mapping.attach(&mut plan);
    let topology = plan
        .topology
        .as_ref()
        .context("missing verified setup topology")?;
    let sync0_index = if reconnects {
        topology.probe_indexes()[1] + 1
    } else {
        0
    };
    let sync0 = exchange(&mut wire, &sync0_request(stations, sync0_index))?;
    let configured_sync0 = read_sync0(stations, sync0_index, sync0, options.period_ns)?;
    if let Some(recorded) = recording {
        recorded
            .topology
            .push(topology.recording(generation, replies));
        recorded.sync0.push(RecordedSync0 {
            connection_generation: generation,
            reply_hex: hex::encode(sync0),
        });
    }
    let mut tracker = ClockTracker::new(stations, options.difference_limit_ns, sync0_index);
    let (offset, count) = if generation == 2 {
        (
            FIRST_GENERATION_CYCLES,
            options.cycles - FIRST_GENERATION_CYCLES,
        )
    } else {
        (
            0,
            if reconnects {
                FIRST_GENERATION_CYCLES
            } else {
                options.cycles
            },
        )
    };
    let mut topology_latched = false;
    for cycle_index in 1..=count {
        let index = tracker.input_slot();
        let distribution = exchange(&mut wire, &tracker.distribution_request())?.to_vec();
        let readback = exchange(&mut wire, &tracker.readback_request())?;
        let clock = tracker.inspect(&distribution, readback)?;
        let clock_frames = recording.as_ref().map(|_| ClockFrames {
            distribution_hex: hex::encode(&distribution),
            readback_hex: hex::encode(readback),
        });

        if monitored && generation == 1 && matches!(cycle_index, SWAP_CYCLE | RESTORE_CYCLE) {
            wire.swap_group_stations();
        }
        let mut received_hex = Vec::new();
        let (input, cyclic_topology) = if clock.valid {
            let frame = group.cyclic_frame(index, stations, monitored)?;
            let reply = exchange(&mut wire, &frame)?;
            if recording.is_some() {
                received_hex.push(hex::encode(reply));
            }
            let guard = monitored.then_some((topology, topology_latched));
            let (input, observation) =
                group.inspect_cyclic_reply(index, stations, reply, None, guard)?;
            topology_latched |= observation
                .as_ref()
                .is_some_and(|check| !check.matches_setup);
            (Some(input), observation)
        } else {
            (None, None)
        };
        if let Some(recorded) = recording {
            let ordinal = u64::from(offset + cycle_index);
            recorded.cycles.push(RecordedCycle {
                connection_generation: generation,
                cycle_index: u64::from(cycle_index),
                index,
                elapsed_us: input
                    .as_ref()
                    .map(|_| modeled_elapsed_us(ordinal, options.period_ns)),
                received_hex,
                clock_frames,
            });
        }
        cycles.push(Cycle {
            connection_generation: reconnects.then_some(generation),
            cycle_index,
            clock,
            cyclic_topology,
            input,
        });
    }

    Ok(Setup {
        configured_sync0,
        plan,
        wire_audit: wire.chain_audits(),
    })
}

fn exchange<'a, const N: usize>(wire: &'a mut VirtualWire, frame: &Frame<N>) -> Result<&'a [u8]> {
    wire.send(frame.bytes())?;
    wire.receive().context("missing clock rehearsal reply")
}

fn sync0_request(stations: &[u16], index: u8) -> Frame<MAX_SYNC0_DATAGRAMS> {
    let mut parts = [Datagram::register(FPRD, stations[0], DC_ACTIVATION, 1); MAX_SYNC0_DATAGRAMS];
    for (&station, pair) in stations.iter().zip(parts.as_chunks_mut::<2>().0) {
        pair.copy_from_slice(&[
            Datagram::register(FPRD, station, DC_ACTIVATION, 1),
            Datagram::register(FPRD, station, DC_SYNC0_CYCLE, 4),
        ]);
    }
    Frame::with_count(index, parts, 2 * stations.len())
}

fn read_sync0(
    stations: &[u16],
    index: u8,
    reply: &[u8],
    expected_period_ns: u32,
) -> Result<Vec<Sync0>> {
    let parts = sync0_request(stations, index)
        .reply(reply)
        .context("FPRD reply does not match the expected SYNC0 register request")?;
    let mut settings = Vec::with_capacity(stations.len());
    for (position, &station) in stations.iter().enumerate() {
        let [(activation, activation_wkc), (period, period_wkc)] =
            [parts[2 * position], parts[2 * position + 1]];
        ensure!(
            activation_wkc == 1 && period_wkc == 1,
            "SYNC0 register readback WKC mismatch at {station:#06x}"
        );
        let read = Sync0 {
            station,
            activation: activation[0],
            period_ns: read_u32(period),
        };
        ensure!(
            read.activation == 3 && read.period_ns == expected_period_ns,
            "SYNC0 readback does not match the authored schedule at {station:#06x}"
        );
        settings.push(read);
    }
    Ok(settings)
}

fn check_clock(
    stations: &[u16],
    frmw_payload_ns: u64,
    actual_distribution_wkc: u16,
    readbacks: &[(&[u8], u16)],
    previous: &[Option<u64>],
    difference_limit_ns: u32,
) -> ClockCheck {
    let reference = ClockRead::new(stations[0], readbacks[0]);
    let first = FollowerCheck::new(stations[1], readbacks[1], readbacks[2], reference.time_ns);
    let expected_distribution_wkc = stations.len() as u16;
    let mut issues = Vec::new();
    if actual_distribution_wkc != expected_distribution_wkc {
        issues.push("distribution_wkc");
    }
    if reference.wkc != 1 {
        issues.push("reference_time_wkc");
    }
    first.read_issues(&mut issues);
    if reference
        .time_ns
        .is_some_and(|time| time != frmw_payload_ns)
    {
        issues.push("reference_payload_mismatch");
    }
    if reference.not_new(previous[0]) {
        issues.push("reference_time_not_new");
    }
    first.timing_issues(previous[1], difference_limit_ns, &mut issues);

    let mut additional_followers = Vec::new();
    for (position, &station) in stations.iter().enumerate().skip(2) {
        let first_datagram = 2 * position - 1;
        let mut follower = FollowerCheck::new(
            station,
            readbacks[first_datagram],
            readbacks[first_datagram + 1],
            reference.time_ns,
        );
        let mut follower_issues = Vec::new();
        follower.read_issues(&mut follower_issues);
        follower.timing_issues(
            previous[position],
            difference_limit_ns,
            &mut follower_issues,
        );
        follower.issues = follower_issues;
        additional_followers.push(follower);
    }
    if additional_followers
        .iter()
        .any(|follower| !follower.issues.is_empty())
    {
        issues.push("additional_follower_rejected");
    }
    ClockCheck {
        expected_distribution_wkc,
        actual_distribution_wkc,
        frmw_payload_ns,
        raw_follower_minus_reference_ns: first.raw_follower_minus_reference_ns,
        reference,
        follower: first.follower,
        difference: first.difference,
        additional_followers,
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

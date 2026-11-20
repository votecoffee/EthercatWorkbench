//! Rehearse clock distribution and clock-qualified inputs on the authored two-station wire.
use super::{InputGroup, Inspection, preflight};
pub use crate::virtual_esc::GroupClockCase;
use crate::{
    virtual_esc::{
        DC_ACTIVATION, DC_SYNC0_CYCLE, DC_TIME, DC_TIME_DIFFERENCE, GROUP_DC_MODELS,
        GROUP_STATIONS, VirtualStats, VirtualWire,
    },
    wire::{Datagram, FPRD, Frame},
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;

const REFERENCE: u16 = GROUP_STATIONS[0];
const FOLLOWER: u16 = GROUP_STATIONS[1];
const DISTRIBUTION_WKC: u16 = GROUP_STATIONS.len() as u16;

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

#[derive(Serialize)]
struct ClockCheck {
    expected_distribution_wkc: u16,
    actual_distribution_wkc: u16,
    frmw_payload_ns: u64,
    reference: ClockRead,
    follower: ClockRead,
    difference: DifferenceRead,
    raw_follower_minus_reference_ns: Option<i128>,
    issues: Vec<&'static str>,
    valid: bool,
}

#[derive(Serialize)]
struct ClockRead {
    station: u16,
    wkc: u16,
    time_ns: Option<u64>,
}

#[derive(Serialize)]
struct DifferenceRead {
    wkc: u16,
    raw: Option<u32>,
    received_minus_local_ns: Option<i64>,
}

pub fn run(group: &InputGroup, options: Options) -> Result<Report<'_>> {
    ensure!(
        preflight::matches_fixture(group, GROUP_DC_MODELS),
        "group clock rehearsal requires two authored CoE/DC identities with 8 TxPDO and 2 RxPDO bytes each"
    );
    ensure!(options.period_ns > 0, "SYNC0 period must be positive");
    ensure!(
        (1..=64).contains(&options.cycles),
        "rehearsal requires 1–64 cycles"
    );

    let mut wire = VirtualWire::for_group_dc(options.scenario, options.period_ns);
    let mut plan = group.inspect(None)?;
    preflight::require_valid_mapping(group, &mut wire)?.attach(&mut plan);
    let configured_sync0 = read_sync0(&mut wire, options.period_ns)?;
    let mut index = 0;
    let mut previous = [None, None];
    let mut cycles = Vec::with_capacity(options.cycles as usize);
    for cycle_index in 1..=options.cycles {
        index += 1;
        let distribute = Frame::clock_request(index, REFERENCE, DC_TIME);
        let [(payload, distribution_wkc)] = exchange(&mut wire, &distribute)?;
        let frmw_payload_ns = read_u64(payload);

        index += 1;
        let readback = Frame::new(
            index,
            [
                Datagram::register(FPRD, REFERENCE, DC_TIME, 8),
                Datagram::register(FPRD, FOLLOWER, DC_TIME, 8),
                Datagram::register(FPRD, FOLLOWER, DC_TIME_DIFFERENCE, 4),
            ],
        );
        let clock = check_clock(
            frmw_payload_ns,
            distribution_wkc,
            exchange(&mut wire, &readback)?,
            previous,
            options.difference_limit_ns,
        );
        let input = if clock.valid {
            previous = [clock.reference.time_ns, clock.follower.time_ns];
            index += 1;
            let frame = group.expected_frame(index, &GROUP_STATIONS)?;
            wire.send(frame.bytes())?;
            let reply = wire.receive().context("missing grouped input reply")?;
            Some(group.inspect_reply(index, &GROUP_STATIONS, reply, None)?)
        } else {
            None
        };
        cycles.push(Cycle {
            cycle_index,
            clock,
            input,
        });
    }

    Ok(Report {
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
    })
}

fn exchange<'a, const N: usize>(
    wire: &'a mut VirtualWire,
    frame: &Frame<N>,
) -> Result<[(&'a [u8], u16); N]> {
    wire.send(frame.bytes())?;
    frame
        .reply(wire.receive().context("missing clock rehearsal reply")?)
        .context("clock rehearsal reply does not match its request")
}

fn read_sync0(wire: &mut VirtualWire, expected_period_ns: u32) -> Result<[Sync0; 2]> {
    let request = Frame::new(
        0,
        [
            Datagram::register(FPRD, REFERENCE, DC_ACTIVATION, 1),
            Datagram::register(FPRD, REFERENCE, DC_SYNC0_CYCLE, 4),
            Datagram::register(FPRD, FOLLOWER, DC_ACTIVATION, 1),
            Datagram::register(FPRD, FOLLOWER, DC_SYNC0_CYCLE, 4),
        ],
    );
    let [
        (ref_activation, ref_awkc),
        (ref_period, ref_pwkc),
        (follower_activation, follower_awkc),
        (follower_period, follower_pwkc),
    ] = exchange(wire, &request)?;
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

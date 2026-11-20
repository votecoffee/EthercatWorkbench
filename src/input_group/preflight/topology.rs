//! Verify configured station order using the position-based traversal of the modeled wire.
use super::super::{MAX_DATAGRAMS, decode_frame_hex};
use crate::{
    virtual_esc::VirtualWire,
    wire::{APRD, BRD, Datagram, Frame},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

const FIRST_DATAGRAM: usize = 16;
const ADDRESS_OFFSET: usize = 2;
const COUNT_DATAGRAM_BYTES: usize = 14;
const POSITION_DATAGRAM_BYTES: usize = 16;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Recording {
    pub(crate) connection_generation: u64,
    before_mapping: ProbeReply,
    after_mapping: ProbeReply,
}

#[derive(Serialize)]
pub(crate) struct GenerationCheck {
    connection_generation: u64,
    #[serde(flatten)]
    topology: Check,
}

impl Recording {
    pub(crate) fn verify(&self, expected_stations: &[u16]) -> Result<GenerationCheck> {
        ensure!(
            self.before_mapping.index < self.after_mapping.index,
            "topology probe datagram indexes must increase"
        );
        let before = self
            .before_mapping
            .inspect(expected_stations)
            .context("before mapping")?;
        let after = self
            .after_mapping
            .inspect(expected_stations)
            .context("after mapping")?;
        let topology = Check::new(before, after);
        ensure!(
            topology.valid,
            "saved topology probes fail count, station order or stability checks"
        );
        Ok(GenerationCheck {
            connection_generation: self.connection_generation,
            topology,
        })
    }
}

#[derive(Serialize)]
pub(crate) struct Check {
    expected_count: usize,
    before_mapping: Observation,
    after_mapping: Observation,
    unchanged: bool,
    pub(crate) valid: bool,
}

impl Check {
    pub(super) fn new(before_mapping: Observation, after_mapping: Observation) -> Self {
        let unchanged = before_mapping.count_wkc == after_mapping.count_wkc
            && before_mapping.positions == after_mapping.positions;
        Self {
            expected_count: before_mapping.positions.len(),
            valid: before_mapping.valid && after_mapping.valid && unchanged,
            before_mapping,
            after_mapping,
            unchanged,
        }
    }

    pub(crate) fn recording(&self, connection_generation: u64) -> Recording {
        Recording {
            connection_generation,
            before_mapping: self.before_mapping.raw.clone(),
            after_mapping: self.after_mapping.raw.clone(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProbeReply {
    index: u8,
    reply_hex: String,
}

impl ProbeReply {
    fn inspect(&self, expected_stations: &[u16]) -> Result<Observation> {
        let frame = probe(self.index, expected_stations.len());
        inspect_reply(
            self.index,
            &decode_frame_hex(&self.reply_hex)?,
            &frame,
            expected_stations,
        )
    }
}

#[derive(Serialize)]
pub(super) struct Observation {
    #[serde(flatten)]
    raw: ProbeReply,
    count_wkc: u16,
    positions: Vec<Position>,
    valid: bool,
}

#[derive(PartialEq, Eq, Serialize)]
struct Position {
    position: usize,
    expected_station_address: u16,
    wkc: u16,
    station_address: Option<u16>,
    configured_alias: Option<u16>,
}

fn probe(index: u8, expected_count: usize) -> Frame<MAX_DATAGRAMS> {
    let mut parts = [Datagram::register(BRD, 0, 0x0000, 2); MAX_DATAGRAMS];
    for (position, part) in parts[1..1 + expected_count].iter_mut().enumerate() {
        let address = 0u16.wrapping_sub(position as u16);
        *part = Datagram::register(APRD, address, 0x0010, 4);
    }
    Frame::with_count(index, parts, 1 + expected_count)
}

pub(super) fn read(
    wire: &mut VirtualWire,
    next_index: &mut u8,
    expected_stations: &[u16],
) -> Result<Observation> {
    let index = *next_index;
    *next_index = index.wrapping_add(1);
    let frame = probe(index, expected_stations.len());
    wire.send(frame.bytes())?;
    let reply = wire.receive().context("missing group topology reply")?;
    inspect_reply(index, reply, &frame, expected_stations)
}

fn inspect_reply(
    index: u8,
    reply: &[u8],
    frame: &Frame<MAX_DATAGRAMS>,
    expected_stations: &[u16],
) -> Result<Observation> {
    let parts = frame
        .reply(reply)
        .context("group topology reply does not match the probe")?;
    let address = |offset: usize| {
        let start = offset + ADDRESS_OFFSET;
        u16::from_le_bytes([reply[start], reply[start + 1]])
    };
    let traversed = address(FIRST_DATAGRAM);
    for position in 0..expected_stations.len() {
        let offset = FIRST_DATAGRAM + COUNT_DATAGRAM_BYTES + position * POSITION_DATAGRAM_BYTES;
        ensure!(
            address(offset) == traversed.wrapping_sub(position as u16),
            "group topology reply auto-increment address differs at position {position}"
        );
    }
    let (_, count_wkc) = parts[0];
    let positions: Vec<_> = expected_stations
        .iter()
        .zip(&parts[1..])
        .enumerate()
        .map(
            |(position, (&expected_station_address, &(bytes, wkc)))| Position {
                position,
                expected_station_address,
                wkc,
                station_address: (wkc == 1).then(|| u16::from_le_bytes([bytes[0], bytes[1]])),
                configured_alias: (wkc == 1).then(|| u16::from_le_bytes([bytes[2], bytes[3]])),
            },
        )
        .collect();
    let valid = usize::from(count_wkc) == expected_stations.len()
        && count_wkc == traversed
        && positions
            .iter()
            .all(|position| position.station_address == Some(position.expected_station_address));
    Ok(Observation {
        raw: ProbeReply {
            index,
            reply_hex: hex::encode(reply),
        },
        count_wkc,
        positions,
        valid,
    })
}

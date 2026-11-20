//! Verify configured station order using the position-based traversal of the modeled wire.
use super::{
    super::{MAX_DATAGRAMS, decode_frame_hex},
    RegisterReview,
};
use crate::{
    virtual_esc::VirtualWire,
    wire::{APRD, BRD, Datagram, Frame},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

const ADDRESS_OFFSET: usize = 2;
const COUNT_DATAGRAM_BYTES: usize = 14;
const POSITION_DATAGRAM_BYTES: usize = 16;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Recording {
    pub(crate) connection_generation: u64,
    before_mapping: ProbeReply,
    after_mapping: ProbeReply,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mapping_replies: Option<Vec<String>>,
}

#[derive(Serialize)]
pub(in crate::input_group) struct GenerationCheck {
    pub(crate) connection_generation: u64,
    #[serde(flatten)]
    pub(in crate::input_group) topology: Check,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::input_group) mapping: Option<RegisterReview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::input_group) configured_sync0:
        Option<Vec<crate::input_group::clock_rehearsal::Sync0>>,
}

impl Recording {
    pub(crate) fn probe_indexes(&self) -> [u8; 2] {
        [self.before_mapping.index, self.after_mapping.index]
    }

    pub(in crate::input_group) fn verify(
        &self,
        expected_stations: &[u16],
    ) -> Result<GenerationCheck> {
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
            mapping: None,
            configured_sync0: None,
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
        let unchanged = before_mapping.reading == after_mapping.reading;
        Self {
            expected_count: before_mapping.reading.positions.len(),
            valid: before_mapping.reading.valid && after_mapping.reading.valid && unchanged,
            before_mapping,
            after_mapping,
            unchanged,
        }
    }

    pub(in crate::input_group) fn probe_indexes(&self) -> [u8; 2] {
        [self.before_mapping.raw.index, self.after_mapping.raw.index]
    }

    pub(crate) fn recording(
        &self,
        connection_generation: u64,
        mapping_replies: Vec<String>,
    ) -> Recording {
        Recording {
            connection_generation,
            before_mapping: self.before_mapping.raw.clone(),
            after_mapping: self.after_mapping.raw.clone(),
            mapping_replies: Some(mapping_replies),
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
    #[serde(flatten)]
    reading: Reading,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct Reading {
    count_wkc: u16,
    positions: Vec<Position>,
    valid: bool,
}

#[derive(Debug, Serialize)]
pub struct RuntimeCheck {
    #[serde(flatten)]
    reading: Reading,
    pub matches_setup: bool,
    pub held_for_setup: bool,
}

impl RuntimeCheck {
    pub(in crate::input_group) fn input_allowed(&self) -> bool {
        self.matches_setup && !self.held_for_setup
    }

    pub fn count_wkc(&self) -> u16 {
        self.reading.count_wkc
    }

    pub fn stations(&self) -> impl Iterator<Item = Option<u16>> + '_ {
        self.reading
            .positions
            .iter()
            .map(|position| position.station_address)
    }
}

impl Check {
    pub(in crate::input_group) fn check_cycle(
        &self,
        reply: &[u8],
        parts: &[(&[u8], u16)],
        stations: &[u16],
        latched: bool,
    ) -> Result<RuntimeCheck> {
        let reading = decode_reading(reply, parts, stations)?;
        let matches_setup = reading == self.after_mapping.reading;
        Ok(RuntimeCheck {
            reading,
            matches_setup,
            held_for_setup: matches_setup && latched,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct Position {
    position: usize,
    expected_station_address: u16,
    wkc: u16,
    station_address: Option<u16>,
    configured_alias: Option<u16>,
}

pub(in crate::input_group) fn fill_probe(parts: &mut [Datagram], expected_count: usize) {
    parts[0] = Datagram::register(BRD, 0, 0x0000, 2);
    for (position, part) in parts[1..1 + expected_count].iter_mut().enumerate() {
        let address = 0u16.wrapping_sub(position as u16);
        *part = Datagram::register(APRD, address, 0x0010, 4);
    }
}

fn probe(index: u8, expected_count: usize) -> Frame<MAX_DATAGRAMS> {
    let mut parts = [Datagram::register(BRD, 0, 0x0000, 2); MAX_DATAGRAMS];
    fill_probe(&mut parts, expected_count);
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
    Ok(Observation {
        raw: ProbeReply {
            index,
            reply_hex: hex::encode(reply),
        },
        reading: decode_reading(
            &reply[frame.datagram_offset(0)..],
            &parts,
            expected_stations,
        )?,
    })
}

fn decode_reading(
    reply: &[u8],
    parts: &[(&[u8], u16)],
    expected_stations: &[u16],
) -> Result<Reading> {
    let address = |offset: usize| {
        let start = offset + ADDRESS_OFFSET;
        u16::from_le_bytes([reply[start], reply[start + 1]])
    };
    let traversed = address(0);
    for position in 0..expected_stations.len() {
        let offset = COUNT_DATAGRAM_BYTES + position * POSITION_DATAGRAM_BYTES;
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
    Ok(Reading {
        count_wkc,
        positions,
        valid,
    })
}

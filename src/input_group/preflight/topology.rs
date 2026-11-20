//! Verify configured station order using the position-based traversal of the modeled wire.
use super::super::MAX_DATAGRAMS;
use crate::{
    virtual_esc::VirtualWire,
    wire::{APRD, BRD, Datagram, Frame},
};
use anyhow::{Context, Result};
use serde::Serialize;

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
}

#[derive(Serialize)]
pub(super) struct Observation {
    index: u8,
    count_wkc: u16,
    positions: Vec<Position>,
    valid: bool,
    reply_hex: String,
}

#[derive(PartialEq, Eq, Serialize)]
struct Position {
    position: usize,
    expected_station_address: u16,
    wkc: u16,
    station_address: Option<u16>,
    configured_alias: Option<u16>,
}

pub(super) fn read(
    wire: &mut VirtualWire,
    next_index: &mut u8,
    expected_stations: &[u16],
) -> Result<Observation> {
    let mut parts = [Datagram::register(BRD, 0, 0x0000, 2); MAX_DATAGRAMS];
    for (position, part) in parts[1..=expected_stations.len()].iter_mut().enumerate() {
        let address = 0u16.wrapping_sub(position as u16);
        *part = Datagram::register(APRD, address, 0x0010, 4);
    }
    let index = *next_index;
    *next_index = index.wrapping_add(1);
    let frame = Frame::with_count(index, parts, 1 + expected_stations.len());
    wire.send(frame.bytes())?;
    let reply = wire.receive().context("missing group topology reply")?;
    let parts = frame
        .reply(reply)
        .context("group topology reply does not match the probe")?;
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
        && positions
            .iter()
            .all(|position| position.station_address == Some(position.expected_station_address));
    Ok(Observation {
        index,
        count_wkc,
        positions,
        valid,
        reply_hex: hex::encode(reply),
    })
}

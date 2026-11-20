//! Produce replay candidates from an authored two-device virtual wire.
use super::{
    Fixture, InputGroup, MAPPING_FIXTURE_SCHEMA, MODELED_UTC, MONITORED_FIXTURE_SCHEMA,
    RecordedCycle,
};
use crate::{
    input_group::preflight,
    virtual_esc::{GROUP_MODELS, GROUP_STATIONS, GroupDownstream, VirtualWire},
};
use anyhow::{Context, Result, ensure};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VirtualScenario {
    #[default]
    Clean,
    Faults,
    TopologyChange,
}

pub fn generate_virtual(group: &InputGroup, scenario: VirtualScenario) -> Result<Fixture> {
    preflight::validate_virtual_group(group)?;
    let mut wire = VirtualWire::for_group_replay();
    let mut setup_topology = Vec::new();
    let mut previous_reply = String::new();
    let mut cycles = Vec::with_capacity(12);
    let faults = scenario == VirtualScenario::Faults;
    let monitored = scenario == VirtualScenario::TopologyChange;
    for ordinal in 0..12u8 {
        let index = 254u8.wrapping_add(ordinal);
        if monitored && matches!(ordinal, 2 | 4) {
            wire.swap_group_stations();
        }
        if faults {
            let condition = match ordinal {
                2 => GroupDownstream::Preop,
                3 => GroupDownstream::AlError,
                6 => GroupDownstream::MovedStation,
                _ => GroupDownstream::Clean,
            };
            wire.set_group_downstream(condition);
        }
        let (connection_generation, cycle_index) = if ordinal < 8 {
            (1, u64::from(ordinal) + 1)
        } else {
            (2, u64::from(ordinal) - 7)
        };
        if cycle_index == 1 {
            // Leave a distinct index range for the register reads in each generation.
            let first_index = if connection_generation == 1 { 0 } else { 32 };
            let (mapping, replies) =
                preflight::require_valid_mapping(group, &mut wire, first_index)?;
            let topology = mapping
                .topology
                .context("missing verified setup topology")?;
            setup_topology.push(topology.recording(connection_generation, replies));
        }
        let frame = group.cyclic_frame(index, &GROUP_STATIONS, monitored)?;
        wire.send(frame.bytes())?;
        let reply = wire.receive().context("virtual wire produced no reply")?;
        ensure!(
            frame.reply(reply).is_some(),
            "virtual wire reply did not match"
        );
        let mut received_hex = Vec::new();
        if faults && matches!(ordinal, 4 | 5) {
            received_hex.push(previous_reply);
        }
        previous_reply = hex::encode(reply);
        let dropped = faults && matches!(ordinal, 4 | 7);
        if !dropped {
            received_hex.push(previous_reply.clone());
        }
        cycles.push(RecordedCycle {
            connection_generation,
            cycle_index,
            index,
            elapsed_us: (!dropped).then_some(u64::from(ordinal) * 1000),
            received_hex,
            clock_frames: None,
        });
    }
    let audits = wire.chain_audits();
    ensure!(
        audits.len() == GROUP_MODELS.len()
            && audits.iter().all(|audit| {
                audit.logical_reads == cycles.len() as u64
                    && audit.register_writes == 0
                    && audit.logical_writes == 0
                    && audit.physical_output_writes == 0
                    && audit.state_requests.is_empty()
            }),
        "virtual group replay expected one logical read per device and cycle, with zero writes"
    );
    Ok(Fixture {
        schema: if monitored {
            MONITORED_FIXTURE_SCHEMA
        } else {
            MAPPING_FIXTURE_SCHEMA
        },
        virtual_scenario: Some(scenario),
        virtual_dc: None,
        capture_start_utc: MODELED_UTC.into(),
        stations: GROUP_STATIONS.to_vec(),
        setup_topology: Some(setup_topology),
        cycles,
    })
}

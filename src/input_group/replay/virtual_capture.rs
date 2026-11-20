//! Produce replay candidates from an authored virtual group.
use super::{
    Fixture, InputGroup, MAPPING_FIXTURE_SCHEMA, MODELED_UTC, MONITORED_FIXTURE_SCHEMA,
    PDO_FIXTURE_SCHEMA, RecordedCycle,
};
use crate::{
    input_group::preflight,
    virtual_esc::{GroupCycleState, VirtualWire},
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

pub(super) const SETUP_INDEXES: [u8; 2] = [0, 32];

pub fn generate_virtual(
    group: &InputGroup,
    scenario: VirtualScenario,
    read_pdos: bool,
) -> Result<Fixture> {
    let fixture = preflight::virtual_group(group)?;
    let stations = fixture.stations;
    let mut wire = VirtualWire::with_group_layout(fixture);
    let mut setup_topology = Vec::new();
    let mut previous_reply = String::new();
    let mut cycles = Vec::with_capacity(12);
    let faults = scenario == VirtualScenario::Faults;
    let monitored = scenario == VirtualScenario::TopologyChange;
    let mut wire_cycles = 0;
    for ordinal in 0..12u8 {
        let index = 254u8.wrapping_add(ordinal);
        if monitored && matches!(ordinal, 2 | 4) {
            wire.swap_group_stations();
        }
        if faults {
            let condition = match ordinal {
                2 => GroupCycleState::Preop,
                3 => GroupCycleState::AlError,
                6 => GroupCycleState::MovedStation,
                _ => GroupCycleState::Clean,
            };
            wire.set_group_cycle_state(stations, 1, condition);
        }
        let (connection_generation, cycle_index) = if ordinal < 8 {
            (1, u64::from(ordinal) + 1)
        } else {
            (2, u64::from(ordinal) - 7)
        };
        if cycle_index == 1 {
            if read_pdos && connection_generation == 2 {
                verify_virtual_audit(&wire, stations, wire_cycles, read_pdos)?;
                wire = VirtualWire::with_group_layout(fixture);
                wire_cycles = 0;
            }
            let first_index = SETUP_INDEXES[connection_generation as usize - 1];
            let (mapping, replies) =
                preflight::require_valid_mapping(group, &mut wire, stations, first_index)?;
            let topology = mapping
                .topology
                .as_ref()
                .context("missing verified setup topology")?;
            let mut recording = topology.recording(connection_generation, replies);
            if read_pdos {
                preflight::record_pdo_setup(group, &mut wire, fixture, &mapping, &mut recording)
                    .with_context(|| {
                        format!("setup PDO readback for generation {connection_generation}")
                    })?;
            }
            setup_topology.push(recording);
        }
        let frame = group.cyclic_frame(index, stations, monitored)?;
        wire.send(frame.bytes())?;
        let reply = wire.receive().context("virtual wire produced no reply")?;
        wire_cycles += 1;
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
    verify_virtual_audit(&wire, stations, wire_cycles, read_pdos)?;
    Ok(Fixture {
        schema: if read_pdos {
            PDO_FIXTURE_SCHEMA
        } else if monitored {
            MONITORED_FIXTURE_SCHEMA
        } else {
            MAPPING_FIXTURE_SCHEMA
        },
        virtual_scenario: Some(scenario),
        virtual_dc: None,
        capture_start_utc: MODELED_UTC.into(),
        stations: stations.to_vec(),
        setup_topology: Some(setup_topology),
        cycles,
    })
}

fn verify_virtual_audit(
    wire: &VirtualWire,
    stations: &[u16],
    cycles: u64,
    read_pdos: bool,
) -> Result<()> {
    let audits = wire.chain_audits();
    ensure!(
        audits.len() == stations.len()
            && audits.iter().all(|audit| {
                let setup_requests = if read_pdos {
                    audit.sii_reads + audit.coe_uploads
                } else {
                    0
                };
                audit.logical_reads == cycles
                    && audit.register_writes == setup_requests
                    && audit.coe_downloads == 0
                    && audit.sync_manager_writes == 0
                    && audit.fmmu_writes == 0
                    && audit.logical_writes == 0
                    && audit.physical_output_writes == 0
                    && audit.state_requests.is_empty()
            }),
        "virtual group replay expected setup read requests and one logical read per device and cycle"
    );
    Ok(())
}

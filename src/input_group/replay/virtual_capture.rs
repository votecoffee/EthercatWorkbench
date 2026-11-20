//! Produce replay candidates from an authored two-device virtual wire.
use super::{Fixture, InputGroup, RecordedCycle};
use crate::virtual_esc::{
    GROUP_MODELS, GROUP_RX_BYTES, GROUP_STATIONS, GROUP_TX_BYTES, GroupDownstream, VirtualWire,
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
}

pub fn generate_virtual(group: &InputGroup, scenario: VirtualScenario) -> Result<Fixture> {
    ensure!(
        group.bindings.len() == GROUP_MODELS.len()
            && group
                .bindings
                .iter()
                .zip(GROUP_MODELS)
                .all(|(binding, model)| {
                    binding.entry.identity == model.identity()
                        && binding.profile.tx_bytes == GROUP_TX_BYTES
                        && binding.profile.rx_bytes == GROUP_RX_BYTES
                }),
        "virtual group replay requires the authored CoE and SII identities in order with 8 TxPDO and 2 RxPDO bytes each"
    );
    let mut wire = VirtualWire::for_group_replay();
    let mut previous_reply = String::new();
    let mut cycles = Vec::with_capacity(12);
    let faults = scenario == VirtualScenario::Faults;
    for ordinal in 0..12u8 {
        let index = 254u8.wrapping_add(ordinal);
        if faults {
            let condition = match ordinal {
                2 => GroupDownstream::Preop,
                3 => GroupDownstream::AlError,
                6 => GroupDownstream::MovedStation,
                _ => GroupDownstream::Clean,
            };
            wire.set_group_downstream(condition);
        }
        let frame = group.expected_frame(index, &GROUP_STATIONS)?;
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
        let (connection_generation, cycle_index) = if ordinal < 8 {
            (1, u64::from(ordinal) + 1)
        } else {
            (2, u64::from(ordinal) - 7)
        };
        cycles.push(RecordedCycle {
            connection_generation,
            cycle_index,
            index,
            elapsed_us: (!dropped).then_some(u64::from(ordinal) * 1000),
            received_hex,
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
        schema: 1,
        virtual_scenario: Some(scenario),
        capture_start_utc: "2026-01-01T00:00:00.000000Z".into(),
        stations: GROUP_STATIONS.to_vec(),
        cycles,
    })
}

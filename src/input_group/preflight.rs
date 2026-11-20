//! Read and verify the grouped station order and register layout before cyclic input.
pub(super) mod topology;
use super::{InputGroup, Inspection, MappingReview, fmmu, fmmu::Read, sync_manager};
pub use crate::virtual_esc::GroupMappingScenario;
use crate::{
    virtual_esc::{
        GROUP_MODELS, GROUP_RX_BYTES, GROUP_STATIONS, GROUP_TX_BYTES, VirtualModel, VirtualStats,
        VirtualWire,
    },
    wire::{Datagram, FPRD, Frame},
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
pub struct Report<'a> {
    schema: u32,
    source: &'static str,
    scenario: GroupMappingScenario,
    valid: bool,
    fmmu_snapshot: fmmu::Snapshot,
    sync_manager_snapshot: sync_manager::Snapshot,
    inspection: Inspection<'a>,
    wire_audit: Vec<VirtualStats>,
}

pub fn inspect_virtual(group: &InputGroup, scenario: GroupMappingScenario) -> Result<Report<'_>> {
    validate_virtual_group(group)?;
    let mut wire = VirtualWire::for_group_replay();
    wire.apply_group_mapping_scenario(scenario);
    let (fmmu_snapshot, sync_manager_snapshot, topology) = capture_registers(&mut wire)?;
    let mapping = review(
        group,
        fmmu_snapshot.clone(),
        sync_manager_snapshot.clone(),
        topology,
    )?;
    let valid = mapping.valid();
    let mut inspection = group.inspect(None)?;
    mapping.attach(&mut inspection);
    Ok(Report {
        schema: 1,
        source: "virtual_group_register_reads",
        scenario,
        valid,
        fmmu_snapshot,
        sync_manager_snapshot,
        inspection,
        wire_audit: wire.chain_audits(),
    })
}

pub(super) fn validate_virtual_group(group: &InputGroup) -> Result<()> {
    ensure!(
        matches_fixture(group, GROUP_MODELS),
        "virtual group requires the authored CoE and SII identities in order with 8 TxPDO and 2 RxPDO bytes each"
    );
    Ok(())
}

pub(super) fn matches_fixture(group: &InputGroup, models: [VirtualModel; 2]) -> bool {
    group.bindings.len() == models.len()
        && group.bindings.iter().zip(models).all(|(binding, model)| {
            binding.entry.identity == model.identity()
                && binding.profile.tx_bytes == GROUP_TX_BYTES
                && binding.profile.rx_bytes == GROUP_RX_BYTES
        })
}

pub(super) fn require_valid_mapping(
    group: &InputGroup,
    wire: &mut VirtualWire,
) -> Result<MappingReview> {
    let (fmmu, sync_manager, topology) = capture_registers(wire)?;
    ensure!(
        topology.valid,
        "virtual group topology preflight failed before cyclic reads"
    );
    let mapping = review(group, fmmu, sync_manager, topology)?;
    ensure!(
        mapping.valid(),
        "virtual group FMMU or SyncManager preflight failed before cyclic reads"
    );
    Ok(mapping)
}

fn review(
    group: &InputGroup,
    fmmu: fmmu::Snapshot,
    sm: sync_manager::Snapshot,
    topology: topology::Check,
) -> Result<MappingReview> {
    let fmmu_hash = snapshot_hash(&fmmu)?;
    let sm_hash = snapshot_hash(&sm)?;
    let fmmu = fmmu::review_snapshot(fmmu, fmmu_hash, &group.bindings)?;
    let sync_managers = sync_manager::review_snapshot(sm, sm_hash, &fmmu)?;
    let mut mapping = MappingReview {
        fmmu,
        sync_managers: Some(sync_managers),
        pdo: None,
        topology: Some(topology),
    };
    mapping.compare_stations(&GROUP_STATIONS);
    Ok(mapping)
}

fn snapshot_hash(snapshot: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(snapshot)?)))
}

fn capture_registers(
    wire: &mut VirtualWire,
) -> Result<(fmmu::Snapshot, sync_manager::Snapshot, topology::Check)> {
    let mut fmmu = fmmu::Snapshot {
        schema: 1,
        devices: Vec::with_capacity(GROUP_STATIONS.len()),
    };
    let mut sm = sync_manager::Snapshot {
        schema: 1,
        devices: Vec::with_capacity(GROUP_STATIONS.len()),
    };
    let mut index = 0u8;
    let before = topology::read(wire, &mut index, &GROUP_STATIONS)?;
    for station in GROUP_STATIONS {
        let (count, slots) = read_bank::<16>(
            wire,
            &mut index,
            station,
            0x0004,
            0x0600,
            fmmu::MAX_CHANNELS,
        )?;
        fmmu.devices.push(fmmu::Station {
            station_address: station,
            count,
            slots,
        });
        let (count, slots) = read_bank::<8>(
            wire,
            &mut index,
            station,
            0x0005,
            0x0800,
            sync_manager::MAX_CHANNELS,
        )?;
        sm.devices.push(sync_manager::Station {
            station_address: station,
            count,
            slots,
        });
    }
    let after = topology::read(wire, &mut index, &GROUP_STATIONS)?;
    Ok((fmmu, sm, topology::Check::new(before, after)))
}

type ChannelReads<const N: usize> = (Read<u8>, Vec<Read<[u8; N]>>);

fn read_bank<const N: usize>(
    wire: &mut VirtualWire,
    index: &mut u8,
    station: u16,
    count_register: u16,
    start: u16,
    max_channels: usize,
) -> Result<ChannelReads<N>> {
    let Read {
        value: [value],
        wkc,
    } = read_register(wire, index, station, count_register)?;
    let count = Read { value, wkc };
    let mut slots = Vec::new();
    if count.wkc == 1 && usize::from(count.value) <= max_channels {
        for slot in 0..count.value {
            let offset = start + u16::from(slot) * N as u16;
            slots.push(read_register(wire, index, station, offset)?);
        }
    }
    Ok((count, slots))
}

fn read_register<const N: usize>(
    wire: &mut VirtualWire,
    index: &mut u8,
    station: u16,
    offset: u16,
) -> Result<Read<[u8; N]>> {
    let frame = Frame::new(*index, [Datagram::register(FPRD, station, offset, N)]);
    *index = index.wrapping_add(1);
    wire.send(frame.bytes())?;
    let [(bytes, wkc)] = wire.receive().and_then(|reply| frame.reply(reply))
        .with_context(|| format!("missing matching virtual register reply for station {station:#06x}, register {offset:#06x}"))?;
    Ok(Read {
        wkc,
        value: bytes
            .try_into()
            .context("unexpected register reply width")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_reordered_chain_even_when_mapping_and_cyclic_wkc_match() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/input-group.json");
        let group = InputGroup::load(&path).unwrap();
        for scenario in [
            GroupMappingScenario::SwappedStations,
            GroupMappingScenario::SwapDuringReadback,
        ] {
            let mut wire = VirtualWire::for_group_replay();
            wire.apply_group_mapping_scenario(scenario);
            let Err(error) = require_valid_mapping(&group, &mut wire) else {
                panic!("reordered chain passed the preflight");
            };
            assert!(error.to_string().contains("topology preflight failed"));
            assert!(wire.chain_audits().iter().all(|esc| esc.logical_reads == 0));

            let (fmmu, sync_managers, topology) = capture_registers(&mut wire).unwrap();
            let mapping = review(&group, fmmu, sync_managers, topology).unwrap();
            assert!(mapping.fmmu.valid);
            assert!(mapping.sync_managers.unwrap().valid);

            let frame = group.expected_frame(32, &GROUP_STATIONS).unwrap();
            wire.send(frame.bytes()).unwrap();
            let input = group
                .inspect_reply(32, &GROUP_STATIONS, wire.receive().unwrap(), None)
                .unwrap();
            let frame = input.frame.unwrap();
            assert!(frame.lrd_wkc_matches && frame.valid);
        }
    }

    #[test]
    fn rejects_bad_slot_before_a_matching_full_wkc_reply_can_be_used() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/input-group.json");
        let group = InputGroup::load(&path).unwrap();
        let mut wire = VirtualWire::for_group_replay();
        wire.apply_group_mapping_scenario(GroupMappingScenario::LogicalShift);

        let Err(error) = require_valid_mapping(&group, &mut wire) else {
            panic!("shifted slot passed the preflight");
        };
        assert!(
            error
                .to_string()
                .contains("preflight failed before cyclic reads")
        );
        assert!(wire.chain_audits().iter().all(|esc| esc.logical_reads == 0));

        // Show what LRD and AL alone would report for this shifted map.
        let frame = group.expected_frame(19, &GROUP_STATIONS).unwrap();
        wire.send(frame.bytes()).unwrap();
        let inspected = group
            .inspect_reply(19, &GROUP_STATIONS, wire.receive().unwrap(), None)
            .unwrap();
        let frame = inspected.frame.unwrap();
        assert!(frame.lrd_wkc_matches && frame.valid);
    }
}

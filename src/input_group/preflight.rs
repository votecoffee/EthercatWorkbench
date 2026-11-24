//! Read and verify the grouped station order and register layout before cyclic input.
pub(super) mod pdos;
pub(crate) mod topology;
use super::{
    InputGroup, Inspection, MappingReview, decode_frame_hex, fmmu, fmmu::Read, pdo_readback,
    sync_manager,
};
pub use crate::virtual_esc::GroupMappingScenario;
use crate::{
    review::check_cancel,
    virtual_esc::{GROUP_PAIR, GROUP_THREE, GroupFixture, VirtualStats, VirtualWire},
    wire::{Datagram, FPRD, Frame},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::AtomicBool;

#[derive(Serialize)]
pub struct Report<'a> {
    schema: u32,
    source: &'static str,
    scenario: GroupMappingScenario,
    valid: bool,
    fmmu_snapshot: fmmu::Snapshot,
    sync_manager_snapshot: sync_manager::Snapshot,
    mapping_replies: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pdo_snapshot: Option<pdo_readback::Snapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pdo_exchanges: Option<Vec<pdos::Exchange>>,
    inspection: Inspection<'a>,
    wire_audit: Vec<VirtualStats>,
}

#[derive(Deserialize)]
pub(super) struct ReadbackReport {
    pdo_snapshot: Option<pdo_readback::Snapshot>,
    inspection: ReadbackInspection,
    mapping_replies: Vec<String>,
    pdo_exchanges: Option<Vec<pdos::Exchange>>,
}

#[derive(Deserialize)]
struct ReadbackInspection {
    topology: topology::ReadbackProbes,
}

impl ReadbackReport {
    pub(super) fn rebuild(
        self,
        group: &InputGroup,
        stop: Option<&AtomicBool>,
    ) -> Result<(pdo_readback::Snapshot, usize)> {
        let declared = self
            .pdo_snapshot
            .context("virtual group readback report has no PDO snapshot")?;
        let saved = self
            .pdo_exchanges
            .context("virtual group readback report has no PDO exchanges")?;
        let fixture = virtual_group(group)?;
        let topology = self
            .inspection
            .topology
            .verify(fixture.stations)
            .context("PDO report setup topology")?;
        let [before, after] = topology.probe_indexes();
        let mapping = verify_recorded_mapping(
            group,
            fixture.stations,
            before,
            after,
            &self.mapping_replies,
            stop,
        )
        .context("PDO report setup mapping")?;
        let snapshot = pdos::rebuild(
            &saved,
            fixture,
            &mapping.sync_managers,
            after.wrapping_add(1),
            stop,
        )
        .context("rebuild PDO snapshot from saved exchanges")?;
        ensure!(
            snapshot == declared,
            "PDO snapshot differs from the saved exchanges"
        );
        Ok((snapshot, saved.len()))
    }
}

pub fn inspect_virtual(
    group: &InputGroup,
    scenario: GroupMappingScenario,
    read_pdos: bool,
) -> Result<Report<'_>> {
    ensure!(
        read_pdos
            || !matches!(
                scenario,
                GroupMappingScenario::CoePdoOrder | GroupMappingScenario::SiiPdoOrder
            ),
        "the PDO-order scenarios require --read-pdos"
    );
    let fixture = virtual_group(group)?;
    let mut wire = VirtualWire::with_group_layout(fixture);
    wire.apply_group_mapping_scenario(scenario, fixture.stations);
    let Captured {
        fmmu: fmmu_snapshot,
        sm: sync_manager_snapshot,
        topology,
        replies: mapping_replies,
    } = capture_registers(&mut wire, fixture.stations, 0)?;
    let next_index = topology.probe_indexes()[1].wrapping_add(1);
    let mut mapping = review(
        group,
        fixture.stations,
        fmmu_snapshot.clone(),
        sync_manager_snapshot.clone(),
        Some(topology),
    )?;
    let (pdo_snapshot, pdo_exchanges) = if read_pdos && mapping.valid() {
        wire.prepare_group_pdo_readback();
        let sync = mapping
            .sync_managers
            .as_ref()
            .context("missing virtual SyncManager review")?;
        let (snapshot, exchanges) = pdos::capture(&mut wire, fixture, sync, next_index)?;
        mapping.pdo = Some(pdo_readback::review_snapshot(
            snapshot.clone(),
            snapshot_hash(&snapshot)?,
            &group.bindings,
            &mapping.fmmu,
            sync,
        )?);
        (Some(snapshot), Some(exchanges))
    } else {
        (None, None)
    };
    let valid = mapping.valid();
    let mut inspection = group.inspect(None)?;
    mapping.attach(&mut inspection);
    Ok(Report {
        schema: 1,
        source: if read_pdos {
            "virtual_group_pdo_reads"
        } else {
            "virtual_group_register_reads"
        },
        scenario,
        valid,
        fmmu_snapshot,
        sync_manager_snapshot,
        mapping_replies,
        pdo_snapshot,
        pdo_exchanges,
        inspection,
        wire_audit: wire.chain_audits(),
    })
}

pub(super) fn virtual_group(group: &InputGroup) -> Result<GroupFixture> {
    [GROUP_PAIR, GROUP_THREE]
        .into_iter()
        .find(|fixture| matches_fixture(group, *fixture))
        .context("virtual group requires the authored CoE and SII identities in order with their fixture PDO lengths")
}

pub(super) fn matches_fixture(group: &InputGroup, fixture: GroupFixture) -> bool {
    group.bindings.len() == fixture.devices.len()
        && group
            .bindings
            .iter()
            .zip(fixture.devices)
            .all(|(binding, device)| {
                binding.entry.identity == device.model.identity()
                    && (binding.profile.tx_bytes, binding.profile.rx_bytes)
                        == device.image_lengths()
            })
}

pub(super) fn require_valid_mapping(
    group: &InputGroup,
    wire: &mut VirtualWire,
    stations: &[u16],
    first_index: u8,
) -> Result<(MappingReview, Vec<String>)> {
    let Captured {
        fmmu,
        sm,
        topology,
        replies,
    } = capture_registers(wire, stations, first_index)?;
    ensure!(
        topology.valid,
        "virtual group topology preflight failed before cyclic reads"
    );
    let mapping = review(group, stations, fmmu, sm, Some(topology))?;
    ensure!(
        mapping.valid(),
        "virtual group FMMU or SyncManager preflight failed before cyclic reads"
    );
    Ok((mapping, replies))
}

#[derive(Serialize)]
pub(super) struct RegisterReview {
    pub(super) fmmu: fmmu::Review,
    pub(super) sync_managers: sync_manager::Review,
}

pub(super) fn verify_recorded_mapping(
    group: &InputGroup,
    stations: &[u16],
    before: u8,
    after: u8,
    replies: &[String],
    stop: Option<&AtomicBool>,
) -> Result<RegisterReview> {
    ensure!(
        after.checked_sub(before).map(usize::from) == Some(replies.len() + 1),
        "mapping reply count differs from the setup probe indexes"
    );
    let mut index = before + 1;
    let mut replies = replies.iter();
    let (fmmu, sm) = read_registers(stations, &mut index, &mut |_| {
        check_cancel(stop)?;
        decode_frame_hex(
            replies
                .next()
                .context("missing setup mapping register reply")?,
        )
    })?;
    ensure!(
        index == after && replies.next().is_none(),
        "unexpected setup mapping register replies"
    );
    let mapping = review(group, stations, fmmu, sm, None)?;
    ensure!(
        mapping.valid(),
        "recorded FMMU or SyncManager mapping failed setup verification"
    );
    Ok(RegisterReview {
        fmmu: mapping.fmmu,
        sync_managers: mapping.sync_managers.expect("setup SyncManager review"),
    })
}

pub(super) fn record_pdo_setup(
    group: &InputGroup,
    wire: &mut VirtualWire,
    fixture: GroupFixture,
    mapping: &MappingReview,
    recording: &mut topology::Recording,
) -> Result<()> {
    let sync = mapping
        .sync_managers
        .as_ref()
        .context("missing setup SyncManagers")?;
    wire.prepare_group_pdo_readback();
    let next_index = recording.probe_indexes()[1].wrapping_add(1);
    let (snapshot, exchanges) = pdos::capture(wire, fixture, sync, next_index)?;
    pdo_readback::review_snapshot(
        snapshot,
        snapshot_hash(&exchanges)?,
        &group.bindings,
        &mapping.fmmu,
        sync,
    )?
    .require_valid()
    .context("virtual TxPDO setup failed before cyclic reads")?;
    recording.pdo_exchanges = Some(exchanges);
    Ok(())
}

pub(super) fn verify_recorded_pdos(
    group: &InputGroup,
    recording: &topology::Recording,
    mapping: &RegisterReview,
    stop: Option<&AtomicBool>,
) -> Result<pdo_readback::Review> {
    let exchanges = recording
        .pdo_exchanges
        .as_deref()
        .context("missing setup PDO exchanges")?;
    let fixture = virtual_group(group)?;
    let snapshot = pdos::rebuild(
        exchanges,
        fixture,
        &mapping.sync_managers,
        recording.probe_indexes()[1].wrapping_add(1),
        stop,
    )?;
    let mut review = pdo_readback::review_snapshot(
        snapshot,
        snapshot_hash(&exchanges)?,
        &group.bindings,
        &mapping.fmmu,
        &mapping.sync_managers,
    )?;
    review.require_valid()?;
    review.verified_exchanges = Some(exchanges.len());
    Ok(review)
}

fn review(
    group: &InputGroup,
    stations: &[u16],
    fmmu: fmmu::Snapshot,
    sm: sync_manager::Snapshot,
    topology: Option<topology::Check>,
) -> Result<MappingReview> {
    let fmmu_hash = snapshot_hash(&fmmu)?;
    let sm_hash = snapshot_hash(&sm)?;
    let fmmu = fmmu::review_snapshot(fmmu, fmmu_hash, &group.bindings)?;
    let sync_managers = sync_manager::review_snapshot(sm, sm_hash, &fmmu)?;
    let mut mapping = MappingReview {
        fmmu,
        sync_managers: Some(sync_managers),
        pdo: None,
        topology,
    };
    mapping.compare_stations(stations);
    Ok(mapping)
}

fn snapshot_hash(snapshot: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(snapshot)?)))
}

struct Captured {
    fmmu: fmmu::Snapshot,
    sm: sync_manager::Snapshot,
    topology: topology::Check,
    replies: Vec<String>,
}

fn capture_registers(wire: &mut VirtualWire, stations: &[u16], mut index: u8) -> Result<Captured> {
    let before = topology::read(wire, &mut index, stations)?;
    let mut replies = Vec::new();
    let (fmmu, sm) = read_registers(stations, &mut index, &mut |frame| {
        wire.send(frame.bytes())?;
        let reply = wire.receive().context("missing virtual register reply")?;
        replies.push(hex::encode(reply));
        Ok(reply.to_vec())
    })?;
    let after = topology::read(wire, &mut index, stations)?;
    Ok(Captured {
        fmmu,
        sm,
        topology: topology::Check::new(before, after),
        replies,
    })
}

fn read_registers(
    stations: &[u16],
    index: &mut u8,
    exchange: &mut impl FnMut(&Frame<1>) -> Result<Vec<u8>>,
) -> Result<(fmmu::Snapshot, sync_manager::Snapshot)> {
    let mut fmmu = fmmu::Snapshot {
        schema: 1,
        devices: Vec::with_capacity(stations.len()),
    };
    let mut sm = sync_manager::Snapshot {
        schema: 1,
        devices: Vec::with_capacity(stations.len()),
    };
    for &station in stations {
        let (count, slots) =
            read_bank::<16>(exchange, index, station, 0x0004, 0x0600, fmmu::MAX_CHANNELS)?;
        fmmu.devices.push(fmmu::Station {
            station_address: station,
            count,
            slots,
        });
        let (count, slots) = read_bank::<8>(
            exchange,
            index,
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
    Ok((fmmu, sm))
}

type ChannelReads<const N: usize> = (Read<u8>, Vec<Read<[u8; N]>>);

fn read_bank<const N: usize>(
    exchange: &mut impl FnMut(&Frame<1>) -> Result<Vec<u8>>,
    index: &mut u8,
    station: u16,
    count_register: u16,
    start: u16,
    max_channels: usize,
) -> Result<ChannelReads<N>> {
    let Read {
        value: [value],
        wkc,
    } = read_register(exchange, index, station, count_register)?;
    let count = Read { value, wkc };
    let mut slots = Vec::new();
    if count.wkc == 1 && usize::from(count.value) <= max_channels {
        for slot in 0..count.value {
            let offset = start + u16::from(slot) * N as u16;
            slots.push(read_register(exchange, index, station, offset)?);
        }
    }
    Ok((count, slots))
}

fn read_register<const N: usize>(
    exchange: &mut impl FnMut(&Frame<1>) -> Result<Vec<u8>>,
    index: &mut u8,
    station: u16,
    offset: u16,
) -> Result<Read<[u8; N]>> {
    let frame = Frame::new(*index, [Datagram::register(FPRD, station, offset, N)]);
    *index = index.wrapping_add(1);
    let label = || format!("register {offset:#06x} at station {station:#06x}");
    let reply = exchange(&frame).with_context(label)?;
    let [(bytes, wkc)] = frame
        .reply(&reply)
        .with_context(|| format!("reply does not match {}", label()))?;
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
    use crate::virtual_esc::GROUP_STATIONS;

    #[test]
    fn rejects_reordered_chain_even_when_mapping_and_cyclic_wkc_match() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/input-group.json");
        let group = InputGroup::load(&path).unwrap();
        for scenario in [
            GroupMappingScenario::SwappedStations,
            GroupMappingScenario::SwapDuringReadback,
        ] {
            let mut wire = VirtualWire::with_group_layout(GROUP_PAIR);
            wire.apply_group_mapping_scenario(scenario, &GROUP_STATIONS);
            let Err(error) = require_valid_mapping(&group, &mut wire, &GROUP_STATIONS, 0) else {
                panic!("reordered chain passed the preflight");
            };
            assert!(error.to_string().contains("topology preflight failed"));
            assert!(wire.chain_audits().iter().all(|esc| esc.logical_reads == 0));

            let Captured {
                fmmu, sm, topology, ..
            } = capture_registers(&mut wire, &GROUP_STATIONS, 0).unwrap();
            let mapping = review(&group, &GROUP_STATIONS, fmmu, sm, Some(topology)).unwrap();
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
        let mut wire = VirtualWire::with_group_layout(GROUP_PAIR);
        wire.apply_group_mapping_scenario(GroupMappingScenario::LogicalShift, &GROUP_STATIONS);

        let Err(error) = require_valid_mapping(&group, &mut wire, &GROUP_STATIONS, 0) else {
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

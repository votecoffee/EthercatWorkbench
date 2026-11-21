//! Authored EtherCAT ESCs and in-memory transport for discovery and process data.
use crate::model::Identity;
use crate::wire::{APRD, BRD, FRMW, LWR};
use anyhow::{Context, Result, bail, ensure};
use clap::ValueEnum;
use serde::Serialize;
use std::{collections::VecDeque, time::Instant};

const MAILBOX_IN: usize = 0x1000;
const MAILBOX_OUT: usize = 0x1040;
const MAILBOX_BYTES: usize = 64;
const OUTPUTS: usize = 0x1100;
const INPUTS: usize = 0x1200;
pub(crate) const PD_WATCHDOG_STATUS: u16 = 0x0440;
pub(crate) const DC_TIME: u16 = 0x0910;
pub(crate) const DC_ACTIVATION: u16 = 0x0981;
pub(crate) const DC_START: u16 = 0x0990;
pub(crate) const DC_SYNC0_CYCLE: u16 = 0x09a0;
pub(crate) const DC_SYNC1_DELAY: u16 = 0x09a4;
const VIRTUAL_DC_STARTING_TIME: u64 = 1_000_000_000;
pub(crate) const DC_TIME_DIFFERENCE: u16 = 0x092c;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VirtualModel {
    #[default]
    Coe,
    Sii,
    CoeDc,
    CoeNormal,
    CoeSegmented,
}

impl VirtualModel {
    pub(crate) fn identity(self) -> Identity {
        Identity {
            vendor: 0x00ff_1000,
            product: match self {
                Self::Coe => 1,
                Self::Sii => 2,
                Self::CoeDc => 3,
                Self::CoeNormal => 4,
                Self::CoeSegmented => 5,
            },
            revision: 1,
        }
    }

    pub fn has_coe(self) -> bool {
        self != Self::Sii
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanCase {
    #[default]
    Normal,
    PortErrors,
    CountersUnavailable,
    InformationUnavailable,
    CoreWkc,
    CoreTimeout,
    DiagnosticsTimeout,
    TwoDevices,
    SecondDeviceDiagnosticsTimeout,
    SecondDeviceCoreTimeout,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleInventoryCase {
    #[default]
    Matched,
    DetectedDiffers,
    ConfiguredUnavailable,
    DetectedEntryAbort,
    MalformedCount,
    EmptyDetected,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum VirtualFault {
    #[default]
    None,
    PdoOrder,
    SafeopReject,
    MailboxAbort,
    ReadbackUnavailable,
    CleanupReject,
    SetupTimeout,
    IoTimeout,
    IoBurst,
    IoLost,
    TransportError,
    TransportLost,
    DcActive,
    DcReadbackUnavailable,
    SegmentToggle,
    SegmentSize,
    SegmentTimeout,
    SegmentAbort,
    MailboxCounter,
    SegmentInitialData,
    SyncTimingUnavailable,
    SyncTimingSize,
    InitNormalUpload,
    InitSegmentedUpload,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InitialUploadForm {
    Normal,
    SegmentedInitiation,
}

#[derive(Clone, Debug, Serialize)]
pub struct InitialMappingUpload {
    pub object_index: u16,
    pub subindex: u8,
    pub declared_bytes: u32,
    pub form: InitialUploadForm,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct VirtualStats {
    pub model: VirtualModel,
    pub datagrams: u64,
    pub register_writes: u64,
    pub dropped_replies: u64,
    pub transport_errors: u64,
    pub sii_reads: u64,
    pub coe_uploads: u64,
    pub coe_downloads: u64,
    pub coe_normal_uploads: u64,
    pub coe_segmented_uploads: u64,
    pub coe_segments: u64,
    pub coe_duplicate_requests: u64,
    pub mailbox_counter_errors: u64,
    pub dc_latches: u64,
    pub dc_offset_writes: u64,
    pub dc_delay_writes: u64,
    pub dc_activation_writes: u64,
    pub dc_enable_requests: u64,
    pub dc_clock_distribution: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dc_program_writes: Vec<DcProgramWrite>,
    pub sync_manager_writes: u64,
    pub fmmu_writes: u64,
    pub logical_reads: u64,
    pub logical_writes: u64,
    pub physical_output_writes: u64,
    pub error_acknowledgements: u64,
    pub op_requests: u64,
    pub state_requests: Vec<u8>,
    pub final_al_status: u16,
    pub final_al_code: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_mapping_upload: Option<InitialMappingUpload>,
}

struct Upload {
    index: u16,
    sub: u8,
    data: Vec<u8>,
    offset: usize,
    toggle: bool,
}

pub(crate) const GROUP_STATIONS: [u16; 2] = [0x1000, 0x1001];
const GROUP_TX_BYTES: usize = 8;
const GROUP_RX_BYTES: usize = 2;

#[derive(Clone, Copy)]
pub(crate) struct GroupDevice {
    pub(crate) model: VirtualModel,
    process_data: bool,
}

impl GroupDevice {
    const fn with_pdos(model: VirtualModel) -> Self {
        Self {
            model,
            process_data: true,
        }
    }

    pub(crate) const fn image_lengths(self) -> (usize, usize) {
        if self.process_data {
            (GROUP_TX_BYTES, GROUP_RX_BYTES)
        } else {
            (0, 0)
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct GroupFixture {
    pub(crate) stations: &'static [u16],
    pub(crate) devices: &'static [GroupDevice],
}

pub(crate) const GROUP_PAIR: GroupFixture = GroupFixture {
    stations: &GROUP_STATIONS,
    devices: &[
        GroupDevice::with_pdos(VirtualModel::Coe),
        GroupDevice::with_pdos(VirtualModel::Sii),
    ],
};

pub(crate) const GROUP_THREE: GroupFixture = GroupFixture {
    stations: &[0x1000, 0x1001, 0x1002],
    devices: &[
        GroupDevice::with_pdos(VirtualModel::Coe),
        GroupDevice {
            model: VirtualModel::Sii,
            process_data: false,
        },
        GroupDevice::with_pdos(VirtualModel::Sii),
    ],
};

pub(crate) const GROUP_DC: GroupFixture = GroupFixture {
    stations: &GROUP_STATIONS,
    devices: &[GroupDevice::with_pdos(VirtualModel::CoeDc); 2],
};

pub(crate) const GROUP_DC_THREE: GroupFixture = GroupFixture {
    stations: GROUP_THREE.stations,
    devices: &[
        GroupDevice::with_pdos(VirtualModel::CoeDc),
        GroupDevice {
            model: VirtualModel::CoeDc,
            process_data: false,
        },
        GroupDevice::with_pdos(VirtualModel::CoeDc),
    ],
};

#[derive(Default)]
pub(crate) enum GroupCycleState {
    #[default]
    Clean,
    Preop,
    AlError,
    MovedStation,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupMappingScenario {
    #[default]
    Clean,
    LogicalShift,
    PhysicalShift,
    StationMissing,
    ExcessChannels,
    SwappedStations,
    SwapDuringReadback,
    ExtraStation,
    DuplicateStation,
    PositionWkc,
    CoePdoOrder,
    SiiPdoOrder,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputRehearsalCase {
    #[default]
    Normal,
    PreloadWkc,
    OpReject,
    WriteReplyLost,
    SafeStopReplyLost,
    WatchdogExpires,
    WatchdogExpiresInOp,
    WatchdogUnavailable,
    InitReject,
}

#[derive(Default, Serialize)]
pub(crate) struct OutputAudit {
    pub(crate) preload_writes: u64,
    pub(crate) op_writes: u64,
    pub(crate) last_applied: Option<[u8; 2]>,
    // OP entry and the two bounded OP writes. The last applied value is always retained.
    pub(crate) applied_in_order: Vec<[u8; 2]>,
    pub(crate) outputs_active: bool,
    pub(crate) watchdog_expired_at_us: Option<u128>,
}

impl OutputAudit {
    fn applied(&mut self, bytes: [u8; 2]) {
        if self.applied_in_order.len() < 3 {
            self.applied_in_order.push(bytes);
        }
        self.last_applied = Some(bytes);
    }
}

struct OutputRehearsal {
    case: OutputRehearsalCase,
    preload: Option<[u8; 2]>,
    watchdog_us: Option<u64>,
    last_output_us: Option<u128>,
    now_us: u128,
    audit: OutputAudit,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DcRehearsalCase {
    #[default]
    Normal,
    ActivationMismatch,
    CycleWriteWkc,
    ReferenceWkc,
    InputWkc,
    DisableRejected,
}

#[derive(Clone, Debug, Serialize)]
pub struct DcProgramWrite {
    register: u16,
    payload: Vec<u8>,
    wkc: u16,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum, serde::Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupClockCase {
    #[default]
    Normal,
    FollowerWkc,
    FollowerStale,
    FollowerOffset,
    DifferenceReadWkc,
    ReferenceRegression,
    MiddleFollowerStale,
    TopologyChange,
    TopologyReconnect,
}

struct GroupClock {
    reference: bool,
    case: GroupClockCase,
    nominal_difference_ns: i32,
    fault_cycle: u64,
}

struct DcRehearsal {
    case: DcRehearsalCase,
    reference_ns: u64,
}

pub(crate) struct VirtualWire {
    devices: Vec<VirtualEsc>,
    replies: VecDeque<Vec<u8>>,
    current: Option<Vec<u8>>,
    swap_after_next_frame: bool,
}

impl VirtualWire {
    pub fn new(model: VirtualModel, fault: VirtualFault) -> Self {
        Self::single(VirtualEsc::new(model, fault))
    }

    pub(crate) fn for_dc_rehearsal(case: DcRehearsalCase) -> Self {
        let mut esc = VirtualEsc::new(VirtualModel::CoeDc, VirtualFault::None);
        esc.dc_rehearsal = Some(DcRehearsal {
            case,
            reference_ns: VIRTUAL_DC_STARTING_TIME,
        });
        Self::single(esc)
    }

    pub(crate) fn for_output_rehearsal(
        model: VirtualModel,
        case: OutputRehearsalCase,
        watchdog_us: Option<u64>,
    ) -> Self {
        let mut esc = VirtualEsc::new(model, VirtualFault::None);
        esc.output_rehearsal = Some(OutputRehearsal {
            case,
            preload: None,
            watchdog_us,
            last_output_us: None,
            now_us: 0,
            audit: OutputAudit::default(),
        });
        Self::single(esc)
    }

    pub(crate) fn advance_output_time(&mut self, now_us: u128) {
        self.devices[0].advance_output_time(now_us);
    }

    pub(crate) fn output_audit(&mut self) -> OutputAudit {
        std::mem::take(
            &mut self.devices[0]
                .output_rehearsal
                .as_mut()
                .expect("rehearsal")
                .audit,
        )
    }

    pub fn single(device: VirtualEsc) -> Self {
        Self {
            devices: vec![device],
            replies: VecDeque::new(),
            current: None,
            swap_after_next_frame: false,
        }
    }

    pub fn for_module_inventory(case: ModuleInventoryCase) -> Self {
        let mut esc = VirtualEsc::new(VirtualModel::Coe, VirtualFault::None);
        // Identity for the authored fixed-slot ESI, independent of the normal CoE fixture.
        esc.eeprom[0x14..0x18].copy_from_slice(&11u32.to_le_bytes());
        esc.eeprom[0x1c..0x20].copy_from_slice(&14_785u32.to_le_bytes());
        esc.module_inventory = Some(case);
        Self::single(esc)
    }

    pub fn for_scan(model: VirtualModel, case: ScanCase) -> Self {
        let downstream = match case {
            ScanCase::TwoDevices => ScanCase::Normal,
            ScanCase::SecondDeviceDiagnosticsTimeout => ScanCase::DiagnosticsTimeout,
            ScanCase::SecondDeviceCoreTimeout => ScanCase::CoreTimeout,
            _ => return Self::single(VirtualEsc::for_scan(model, case)),
        };
        let mut first = VirtualEsc::for_scan(model, ScanCase::Normal);
        first.registers[0x0010..0x0014].copy_from_slice(&[0x00, 0x10, 0x42, 0x00]);
        first.registers[7] = 0x0f; // Both links use the MII family.
        first.registers[0x0110] |= 0x20;
        first.registers[0x0111] = 0x5a; // Ports 0–1 open with signal; unused ports closed.

        let mut second = VirtualEsc::for_scan(model, downstream);
        second.registers[0] = 0x12;
        second.registers[0x0010..0x0014].copy_from_slice(&[0x01, 0x10, 0x43, 0x00]);
        second.registers[0x0130] = 2; // Authored PREOP observation.
        second.registers[0x0300] = 7;
        let mut wire = Self::single(first);
        wire.devices.push(second);
        wire
    }

    pub(crate) fn for_group_dc(
        fixture: GroupFixture,
        case: GroupClockCase,
        period_ns: u32,
        fault_cycle: u64,
    ) -> Self {
        let mut wire = Self::with_group_layout(fixture);
        let fault_station = match case {
            GroupClockCase::ReferenceRegression => 0,
            GroupClockCase::MiddleFollowerStale => 1,
            _ => fixture.stations.len() - 1,
        };
        for (index, esc) in wire.devices.iter_mut().enumerate() {
            esc.group_clock = Some(GroupClock {
                reference: index == 0,
                case: if index == fault_station {
                    case
                } else {
                    GroupClockCase::Normal
                },
                nominal_difference_ns: if index == 2 { 350 } else { -250 },
                fault_cycle,
            });
            esc.registers[usize::from(DC_ACTIVATION)] = 3;
            let cycle = usize::from(DC_SYNC0_CYCLE);
            esc.registers[cycle..cycle + 4].copy_from_slice(&period_ns.to_le_bytes());
            let time = usize::from(DC_TIME);
            esc.registers[time..time + 8].copy_from_slice(&VIRTUAL_DC_STARTING_TIME.to_le_bytes());
        }
        wire
    }

    pub(crate) fn with_group_layout(fixture: GroupFixture) -> Self {
        let mut wire = Self::single(VirtualEsc::for_scan(
            fixture.devices[0].model,
            ScanCase::Normal,
        ));
        wire.devices.extend(
            fixture.devices[1..]
                .iter()
                .map(|device| VirtualEsc::for_scan(device.model, ScanCase::Normal)),
        );
        let mut next_input = 0u32;
        let mut next_output = fixture
            .devices
            .iter()
            .map(|device| device.image_lengths().0 as u32)
            .sum::<u32>();
        for (index, esc) in wire.devices.iter_mut().enumerate() {
            // Seed the authored SAFEOP layout without register-write datagrams.
            let (tx, rx) = fixture.devices[index].image_lengths();
            let input_start = next_input;
            let output_start = next_output;
            next_input += tx as u32;
            next_output += rx as u32;
            esc.logical_starts = (input_start, output_start);
            esc.registers[0x0010..0x0012].copy_from_slice(&fixture.stations[index].to_le_bytes());
            esc.registers[0x0012] = 0x42 + index as u8;
            esc.registers[0x0130] = 4;
            esc.logical_counter_offset = index as u16;
            if tx == 0 && rx == 0 {
                continue;
            }
            let (input_sm, output_sm, input_fmmu, output_fmmu) = if esc.model.has_coe() {
                (3, 2, 0, 1)
            } else {
                (1, 0, 1, 0)
            };
            for (sm, fmmu, logical, physical, length, mode) in [
                (input_sm, input_fmmu, input_start, INPUTS, tx as u16, 1),
                (output_sm, output_fmmu, output_start, OUTPUTS, rx as u16, 2),
            ] {
                let physical = u16::try_from(physical).unwrap().to_le_bytes();
                let length = length.to_le_bytes();
                let base = 0x0800 + sm * 8;
                esc.registers[base..base + 7].copy_from_slice(&[
                    physical[0],
                    physical[1],
                    length[0],
                    length[1],
                    if mode == 1 { 0 } else { 4 },
                    0,
                    1,
                ]);
                let base = 0x0600 + fmmu * 16;
                esc.registers[base..base + 4].copy_from_slice(&logical.to_le_bytes());
                esc.registers[base + 4..base + 13].copy_from_slice(&[
                    length[0],
                    length[1],
                    0,
                    7,
                    physical[0],
                    physical[1],
                    0,
                    mode,
                    1,
                ]);
            }
        }
        wire
    }

    pub(crate) fn prepare_group_pdo_readback(&mut self) {
        for esc in &mut self.devices {
            esc.pdo_readback = true;
            if !esc.model.has_coe() {
                continue;
            }
            for (base, address, control) in
                [(0x0800, MAILBOX_IN, 0x26), (0x0808, MAILBOX_OUT, 0x22)]
            {
                esc.registers[base..base + 2].copy_from_slice(&(address as u16).to_le_bytes());
                esc.registers[base + 2..base + 4]
                    .copy_from_slice(&(MAILBOX_BYTES as u16).to_le_bytes());
                esc.registers[base + 4] = control;
                esc.registers[base + 6] = 1;
            }
        }
    }

    pub(crate) fn apply_group_mapping_scenario(
        &mut self,
        scenario: GroupMappingScenario,
        stations: &[u16],
    ) {
        let last = self.devices.len() - 1;
        let esc = &mut self.devices[last];
        match scenario {
            GroupMappingScenario::Clean => {}
            GroupMappingScenario::LogicalShift => {
                let start = esc.logical_starts.0 - 1;
                esc.logical_starts.0 = start;
                esc.registers[0x0610..0x0614].copy_from_slice(&start.to_le_bytes());
            }
            GroupMappingScenario::PhysicalShift => esc.registers[0x0618] = 1,
            GroupMappingScenario::StationMissing => {
                self.set_group_cycle_state(stations, last, GroupCycleState::MovedStation);
            }
            GroupMappingScenario::ExcessChannels => {
                esc.registers[4] = u8::MAX;
                esc.registers[5] = u8::MAX;
            }
            GroupMappingScenario::SwappedStations => self.swap_group_stations(),
            GroupMappingScenario::SwapDuringReadback => self.swap_after_next_frame = true,
            GroupMappingScenario::ExtraStation => {
                let mut extra = VirtualEsc::for_scan(VirtualModel::Coe, ScanCase::Normal);
                let address = stations[last] + 1;
                extra.registers[0x0010..0x0012].copy_from_slice(&address.to_le_bytes());
                self.devices.push(extra);
            }
            GroupMappingScenario::DuplicateStation => {
                esc.registers[0x0010..0x0012].copy_from_slice(&stations[0].to_le_bytes());
            }
            GroupMappingScenario::PositionWkc => esc.scan_case = ScanCase::CoreWkc,
            GroupMappingScenario::CoePdoOrder => self.devices[0].fault = VirtualFault::PdoOrder,
            GroupMappingScenario::SiiPdoOrder => {
                esc.eeprom = eeprom(esc.model, VirtualFault::PdoOrder);
            }
        }
    }

    pub(crate) fn swap_group_stations(&mut self) {
        let last = self.devices.len() - 1;
        self.devices.swap(last - 1, last);
    }

    pub(crate) fn set_group_cycle_state(
        &mut self,
        stations: &[u16],
        position: usize,
        condition: GroupCycleState,
    ) {
        let esc = &mut self.devices[position];
        let planned = stations[position];
        let (state, code, station) = match condition {
            GroupCycleState::Clean => (4, 0, planned),
            GroupCycleState::Preop => (2, 0, planned),
            GroupCycleState::AlError => (4, 0x1e, planned),
            GroupCycleState::MovedStation => (4, 0, stations[stations.len() - 1] + 1),
        };
        esc.registers[0x0130] = state;
        esc.registers[0x0134] = code;
        esc.registers[0x0010..0x0012].copy_from_slice(&station.to_le_bytes());
    }

    pub fn stats(&self) -> VirtualStats {
        self.devices[0].stats()
    }

    pub fn chain_audits(&self) -> Vec<VirtualStats> {
        if self.devices.len() > 1 {
            self.devices.iter().map(VirtualEsc::stats).collect()
        } else {
            Vec::new()
        }
    }

    pub fn receive(&mut self) -> Option<&[u8]> {
        self.current = self.replies.pop_front();
        self.current.as_deref()
    }

    pub fn send(&mut self, bytes: &[u8]) -> Result<()> {
        let mut reply = bytes.to_vec();
        let mut drop_reply = false;
        for device in &mut self.devices {
            drop_reply |= device.forward(&mut reply)?;
        }
        if !drop_reply {
            reply[6] |= 2;
            self.replies.push_back(reply);
        }
        if std::mem::take(&mut self.swap_after_next_frame) {
            self.swap_group_stations();
        }
        Ok(())
    }
}

pub(crate) struct VirtualEsc {
    scan_case: ScanCase,
    read_only: bool,
    pdo_readback: bool,
    module_inventory: Option<ModuleInventoryCase>,
    registers: Box<[u8; 65_536]>,
    eeprom: Vec<u8>,
    mailbox: Option<[u8; MAILBOX_BYTES]>,
    stats: VirtualStats,
    fault: VirtualFault,
    model: VirtualModel,
    logical_starts: (u32, u32),
    logical_counter_offset: u16,
    output_rehearsal: Option<OutputRehearsal>,
    dc_rehearsal: Option<DcRehearsal>,
    group_clock: Option<GroupClock>,
    clock_started: Instant,
    transport_lost: bool,
    upload: Option<Upload>,
    last_request: Option<Vec<u8>>,
    last_response: Option<[u8; MAILBOX_BYTES]>,
    #[cfg(test)]
    sii_status_stall: Option<std::time::Duration>,
}

impl VirtualEsc {
    pub fn new(model: VirtualModel, fault: VirtualFault) -> Self {
        let mut registers = Box::new([0u8; 65_536]);
        registers[0] = 0x11;
        registers[4] = 2; // FMMU channels.
        registers[5] = if model.has_coe() { 4 } else { 2 }; // SyncManager channels.
        registers[6] = 8; // Authored process RAM capacity in KiB.
        registers[7] = 3; // Port 0 MII family; remaining ports not implemented.
        if model == VirtualModel::CoeDc {
            registers[0x0008..0x000a].copy_from_slice(&0x010cu16.to_le_bytes());
        }
        registers[0x0110] = 0x13; // One linked port, PDI operational, watchdog OK.
        registers[0x0111] = 0x56; // Port 0 open with signal; unused ports closed.
        registers[0x0130] = 1; // INIT.
        Self {
            scan_case: ScanCase::Normal,
            read_only: false,
            pdo_readback: false,
            module_inventory: None,
            registers,
            eeprom: eeprom(model, fault),
            mailbox: None,
            stats: VirtualStats {
                model,
                ..VirtualStats::default()
            },
            fault,
            model,
            logical_starts: (0, 8),
            logical_counter_offset: 0,
            output_rehearsal: None,
            dc_rehearsal: None,
            group_clock: None,
            clock_started: Instant::now(),
            transport_lost: false,
            upload: None,
            last_request: None,
            last_response: None,
            #[cfg(test)]
            sii_status_stall: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn stall_first_sii_status(&mut self, duration: std::time::Duration) {
        self.sii_status_stall = Some(duration);
    }

    fn for_scan(model: VirtualModel, case: ScanCase) -> Self {
        let mut esc = Self::new(model, VirtualFault::None);
        esc.scan_case = case;
        esc.read_only = true;
        if case == ScanCase::PortErrors {
            esc.registers[1] = 1;
            esc.registers[2..4].copy_from_slice(&0x1234u16.to_le_bytes());
            esc.registers[7] = 0xfb;
            esc.registers[0x0110..0x0112].copy_from_slice(&0x9eb6u16.to_le_bytes());
            esc.registers[0x0130] = 0x14;
            esc.registers[0x0134..0x0136].copy_from_slice(&0x001du16.to_le_bytes());
            esc.registers[0x0300..0x0314].copy_from_slice(&[
                1, 2, 255, 3, 0, 0, 0, 0, 4, 5, 0, 0, 6, 7, 0x34, 0x12, 8, 9, 10, 255,
            ]);
        }
        esc
    }

    pub fn stats(&self) -> VirtualStats {
        let mut stats = self.stats.clone();
        stats.final_al_status = word(&self.registers[0x0130..]);
        stats.final_al_code = word(&self.registers[0x0134..]);
        stats
    }

    fn forward(&mut self, reply: &mut [u8]) -> Result<bool> {
        if self.transport_lost {
            self.stats.transport_errors += 1;
            bail!("virtual Ethernet transport remains unavailable");
        }
        ensure!(
            reply.len() >= 16 && reply[12..14] == [0x88, 0xa4],
            "virtual ESC requires Ethernet II EtherCAT"
        );
        let payload_len = usize::from(word(&reply[14..]) & 0x07ff);
        let end = 16 + payload_len;
        ensure!(
            end <= reply.len(),
            "truncated EtherCAT frame sent to virtual ESC"
        );
        let mut offset = 16;
        let mut drop_reply = false;
        while offset < end {
            ensure!(offset + 12 <= end, "truncated virtual ESC datagram");
            let command = reply[offset];
            let station = word(&reply[offset + 2..]);
            let register = word(&reply[offset + 4..]);
            let flags = word(&reply[offset + 6..]);
            let len = usize::from(flags & 0x07ff);
            let data_start = offset + 10;
            let data_end = data_start + len;
            ensure!(data_end + 2 <= end, "invalid virtual ESC datagram length");
            let addressed = match command {
                0x01 | 0x02 => station == 0,
                0x04 | 0x05 => station == word(&self.registers[0x0010..]),
                0x07 | 0x08 | 0x0a => true,
                LWR if self.output_rehearsal.is_some() => true,
                FRMW => {
                    self.stats.dc_clock_distribution += 1;
                    ensure!(
                        self.dc_rehearsal.is_some() || self.group_clock.is_some(),
                        "virtual fixture rejects cyclic DC clock distribution"
                    );
                    let reference = if self.group_clock.is_some() {
                        GROUP_STATIONS[0]
                    } else {
                        word(&self.registers[0x0010..])
                    };
                    ensure!(
                        station == reference && register == DC_TIME && len == 8,
                        "virtual DC rehearsal expects the designated reference-clock address"
                    );
                    true
                }
                0x0b | 0x0c => {
                    self.stats.logical_writes += 1;
                    bail!("virtual fixture rejects logical output writes")
                }
                _ => bail!("virtual fixture does not implement EtherCAT command {command:#04x}"),
            };
            self.stats.datagrams += 1;
            let mut wkc = 0;
            if addressed {
                let data = &mut reply[data_start..data_end];
                wkc = match command {
                    0x01 | 0x04 | 0x07 => {
                        if command == BRD {
                            let mut register_data = [0u8; 0x07ff];
                            self.read(usize::from(register), &mut register_data[..len])?;
                            for (byte, value) in data.iter_mut().zip(register_data) {
                                *byte |= value;
                            }
                        } else {
                            self.read(usize::from(register), data)?;
                        }
                        let dc_unavailable = self.fault == VirtualFault::DcReadbackUnavailable
                            && (0x0980..=0x0981).contains(&register);
                        let watchdog_unavailable = register == PD_WATCHDOG_STATUS
                            && self.output_rehearsal.as_ref().is_some_and(|output| {
                                output.case == OutputRehearsalCase::WatchdogUnavailable
                            });
                        let difference_unavailable = register == DC_TIME_DIFFERENCE
                            && self.group_clock.as_ref().is_some_and(|clock| {
                                !clock.reference
                                    && clock.case == GroupClockCase::DifferenceReadWkc
                                    && self.stats.dc_clock_distribution == clock.fault_cycle
                            });
                        u16::from(
                            !(dc_unavailable || watchdog_unavailable || difference_unavailable),
                        )
                    }
                    0x05 if self.dc_rehearsal.is_some()
                        && matches!(
                            register,
                            DC_ACTIVATION | DC_START | DC_SYNC0_CYCLE | DC_SYNC1_DELAY
                        ) =>
                    {
                        self.dc_program_write(register, data)?
                    }
                    0x02 | 0x05 | 0x08 => {
                        self.write(usize::from(register), data)?;
                        u16::from(register != 0x0900 || self.model == VirtualModel::CoeDc)
                    }
                    0x0a => {
                        let address = u32::from(station) | (u32::from(register) << 16);
                        self.logical_read(address, data)?
                    }
                    FRMW if self.group_clock.is_some() => self.distribute_group_clock(data)?,
                    FRMW => self.reference_clock(data)?,
                    LWR => {
                        let address = u32::from(station) | (u32::from(register) << 16);
                        let written = self.logical_output(address, data);
                        if written
                            && word(&self.registers[0x0130..]) == 8
                            && self.output_rehearsal.as_ref().is_some_and(|output| {
                                match output.case {
                                    OutputRehearsalCase::WriteReplyLost => {
                                        output.audit.op_writes == 1
                                    }
                                    OutputRehearsalCase::SafeStopReplyLost => {
                                        output.audit.op_writes == 2
                                    }
                                    _ => false,
                                }
                            })
                        {
                            drop_reply = true;
                        }
                        u16::from(written)
                    }
                    _ => unreachable!(),
                };
            }
            if self.fault == VirtualFault::SetupTimeout
                && command == 0x04
                && register == 0x0508
                && self.stats.dropped_replies == 0
            {
                drop_reply = true;
            }
            if command == APRD && addressed {
                match (self.scan_case, register, len) {
                    (ScanCase::CoreWkc, 0x0010, 4) => wkc = 2,
                    (ScanCase::CountersUnavailable, 0x0300, 20)
                    | (ScanCase::InformationUnavailable, 0x0000, 16) => wkc = 0,
                    (ScanCase::CoreTimeout, 0x0010, 4)
                    | (ScanCase::DiagnosticsTimeout, 0x0000, 16) => drop_reply = true,
                    _ => {}
                }
            }
            if command == 0x0a
                && match self.fault {
                    VirtualFault::IoTimeout => self.stats.logical_reads.is_multiple_of(7),
                    VirtualFault::IoBurst => (9..=48).contains(&self.stats.logical_reads),
                    VirtualFault::IoLost => self.stats.logical_reads >= 9,
                    _ => false,
                }
            {
                drop_reply = true;
            }
            if matches!(command, 0x01 | 0x02 | 0x07 | 0x08) {
                reply[offset + 2..offset + 4]
                    .copy_from_slice(&station.wrapping_add(1).to_le_bytes());
            }
            let accumulated = word(&reply[data_end..]).wrapping_add(wkc);
            reply[data_end..data_end + 2].copy_from_slice(&accumulated.to_le_bytes());
            offset = data_end + 2;
            ensure!(
                (flags & 0x8000 != 0) == (offset < end),
                "inconsistent virtual ESC datagram chain"
            );
        }
        if drop_reply {
            self.stats.dropped_replies += 1;
        }
        Ok(drop_reply)
    }

    fn read(&mut self, register: usize, data: &mut [u8]) -> Result<()> {
        #[cfg(test)]
        if register == 0x0502
            && self.stats.sii_reads > 0
            && let Some(duration) = self.sii_status_stall.take()
        {
            std::thread::sleep(duration);
        }

        let end = register
            .checked_add(data.len())
            .filter(|end| *end <= self.registers.len());
        ensure!(end.is_some(), "virtual ESC register read outside memory");
        if register <= 0x0981
            && end.is_some_and(|end| end > 0x0981)
            && self.fault == VirtualFault::DcActive
        {
            data.fill(0);
            data[0x0981 - register] = 3; // Authored unexpected device activation, no enable write was sent.
        } else if register == usize::from(DC_TIME)
            && data.len() == 8
            && let Some(dc) = &self.dc_rehearsal
        {
            data.copy_from_slice(&dc.reference_ns.to_le_bytes());
        } else if register == 0x0508 {
            let word_address = usize::from(word(&self.registers[0x0504..]));
            let start = word_address * 2;
            let source = self
                .eeprom
                .get(start..start + data.len())
                .ok_or_else(|| anyhow::anyhow!("virtual EEPROM read outside image"))?;
            data.copy_from_slice(source);
        } else if register == MAILBOX_OUT {
            data.fill(0);
            if let Some(mailbox) = self.mailbox.take() {
                let len = data.len().min(mailbox.len());
                data[..len].copy_from_slice(&mailbox[..len]);
            }
            self.registers[0x080d] &= !0x08;
        } else {
            data.copy_from_slice(&self.registers[register..end.expect("checked")]);
        }
        Ok(())
    }

    fn dc_program_write(&mut self, register: u16, data: &[u8]) -> Result<u16> {
        let width = match register {
            DC_ACTIVATION => 1,
            DC_START => 8,
            DC_SYNC0_CYCLE | DC_SYNC1_DELAY => 4,
            _ => unreachable!("checked DC programming register"),
        };
        ensure!(
            data.len() == width,
            "virtual DC register {register:#06x} requires a {width}-byte write, got {}",
            data.len()
        );
        let rejected = register == DC_SYNC1_DELAY
            && self
                .dc_rehearsal
                .as_ref()
                .is_some_and(|dc| dc.case == DcRehearsalCase::CycleWriteWkc);
        if !rejected {
            self.write(usize::from(register), data)?;
        }
        let wkc = u16::from(!rejected);
        self.stats.dc_program_writes.push(DcProgramWrite {
            register,
            payload: data.to_vec(),
            wkc,
        });
        Ok(wkc)
    }

    fn distribute_group_clock(&mut self, data: &mut [u8]) -> Result<u16> {
        ensure!(
            word(&self.registers[0x0130..]) == 4 && self.registers[usize::from(DC_ACTIVATION)] == 3,
            "group clock fixture requires SYNC0 in SAFEOP"
        );
        let clock = self.group_clock.as_ref().expect("group clock configured");
        let cycle = self.stats.dc_clock_distribution;
        let fault_cycle = cycle == clock.fault_cycle;
        let time = usize::from(DC_TIME);
        if clock.reference {
            let period = u64::from(dword(&self.registers[usize::from(DC_SYNC0_CYCLE)..]));
            let timestamp = if fault_cycle && clock.case == GroupClockCase::ReferenceRegression {
                VIRTUAL_DC_STARTING_TIME + period - 1
            } else {
                VIRTUAL_DC_STARTING_TIME + period * cycle
            };
            self.registers[time..time + 8].copy_from_slice(&timestamp.to_le_bytes());
            data.copy_from_slice(&timestamp.to_le_bytes());
        } else {
            if fault_cycle {
                match clock.case {
                    GroupClockCase::FollowerWkc => return Ok(0),
                    GroupClockCase::FollowerStale | GroupClockCase::MiddleFollowerStale => {
                        return Ok(1);
                    }
                    _ => {}
                }
            }
            // The follower's local reading and filter result are authored responses.
            let difference_ns: i32 = if fault_cycle && clock.case == GroupClockCase::FollowerOffset
            {
                2_500
            } else {
                clock.nominal_difference_ns
            };
            let reference = u64::from_le_bytes(data.try_into().expect("eight-byte FRMW payload"));
            let timestamp = reference.saturating_add_signed(-i64::from(difference_ns));
            self.registers[time..time + 8].copy_from_slice(&timestamp.to_le_bytes());
            let encoded =
                difference_ns.unsigned_abs() | if difference_ns < 0 { 1 << 31 } else { 0 };
            let register = usize::from(DC_TIME_DIFFERENCE);
            self.registers[register..register + 4].copy_from_slice(&encoded.to_le_bytes());
        }
        Ok(1)
    }

    fn reference_clock(&mut self, data: &mut [u8]) -> Result<u16> {
        ensure!(
            word(&self.registers[0x0130..]) == 4
                && matches!(self.registers[usize::from(DC_ACTIVATION)] & 7, 3 | 7),
            "virtual reference clock requires active DC in SAFEOP"
        );
        let dc = self.dc_rehearsal.as_mut().expect("checked DC rehearsal");
        if dc.case == DcRehearsalCase::ReferenceWkc && self.stats.dc_clock_distribution == 2 {
            return Ok(0);
        }
        let period = dword(&self.registers[usize::from(DC_SYNC0_CYCLE)..]);
        dc.reference_ns += u64::from(period);
        data.copy_from_slice(&dc.reference_ns.to_le_bytes());
        Ok(1)
    }

    fn allows_pdo_read_command(&self, register: usize, data: &[u8]) -> bool {
        self.pdo_readback
            && match (register, data) {
                (0x0502, [0, 1, _, _, 0, 0]) => true,
                (
                    MAILBOX_IN,
                    [
                        10,
                        0,
                        0,
                        0,
                        0,
                        counter,
                        0,
                        0x20,
                        0x40,
                        lo,
                        hi,
                        _,
                        padding @ ..,
                    ],
                ) => {
                    self.model.has_coe()
                        && data.len() == MAILBOX_BYTES
                        && counter & 0x8f == 3
                        && counter & 0x70 != 0
                        && matches!(u16::from_le_bytes([*lo, *hi]), 0x1c10..=0x1c1f | 0x1a00..=0x1bff)
                        && padding.iter().all(|byte| *byte == 0)
                }
                _ => false,
            }
    }

    fn write(&mut self, register: usize, data: &[u8]) -> Result<()> {
        self.stats.register_writes += 1;
        ensure!(
            !self.read_only || self.allows_pdo_read_command(register, data),
            "read-only scan fixture rejects register writes"
        );
        let end = register
            .checked_add(data.len())
            .filter(|end| *end <= self.registers.len())
            .ok_or_else(|| anyhow::anyhow!("virtual ESC register write outside memory"))?;
        if end > OUTPUTS && register < OUTPUTS + 2 {
            self.stats.physical_output_writes += 1;
            bail!("virtual fixture rejects physical output data writes");
        }
        if self.model == VirtualModel::CoeDc {
            match register {
                0x0900 => {
                    self.stats.dc_latches += 1;
                    let time = 1_000_000_000 + self.clock_started.elapsed().as_nanos() as u64;
                    self.registers[0x0918..0x0920].copy_from_slice(&time.to_le_bytes());
                    self.registers[0x0900..0x0904].copy_from_slice(&(time as u32).to_le_bytes());
                    return Ok(());
                }
                0x0920 => self.stats.dc_offset_writes += 1,
                0x0928 => self.stats.dc_delay_writes += 1,
                0x0981 => {
                    self.stats.dc_activation_writes += 1;
                    if data[0] & 7 != 0 {
                        self.stats.dc_enable_requests += 1;
                        let dc = self
                            .dc_rehearsal
                            .as_ref()
                            .context("virtual fixture rejects DC enable requests")?;
                        ensure!(
                            data.len() == 1
                                && matches!(data[0], 3 | 7)
                                && word(&self.registers[0x0130..]) == 2
                                && dword(&self.registers[usize::from(DC_SYNC0_CYCLE)..]) != 0,
                            "virtual DC rehearsal expects a configured SYNC option in PREOP"
                        );
                        self.registers[register] = if dc.case == DcRehearsalCase::ActivationMismatch
                        {
                            data[0] & !2
                        } else {
                            data[0]
                        };
                        return Ok(());
                    }
                    if self.registers[register] & 7 != 0
                        && self
                            .dc_rehearsal
                            .as_ref()
                            .is_some_and(|dc| dc.case == DcRehearsalCase::DisableRejected)
                    {
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
        self.registers[register..end].copy_from_slice(data);
        match register {
            0x0120 => {
                let requested = data[0] & 0x0f;
                self.stats.state_requests.push(requested);
                let acknowledge = data[0] & 0x10 != 0;
                if acknowledge {
                    self.stats.error_acknowledgements += 1;
                }
                if self.registers[0x0130] & 0x10 != 0 && !acknowledge {
                    return Ok(());
                }
                if requested == 8 {
                    self.stats.op_requests += 1;
                    return self.enter_rehearsal_op();
                }
                if requested == 1
                    && self.output_rehearsal.as_ref().is_some_and(|output| {
                        output.audit.outputs_active
                            && output.case == OutputRehearsalCase::InitReject
                    })
                {
                    return Ok(());
                }
                if requested == 1
                    && word(&self.registers[0x0130..]) & 0x0f == 4
                    && self.fault == VirtualFault::CleanupReject
                {
                    self.registers[0x0130..0x0132].copy_from_slice(&0x0014u16.to_le_bytes());
                    self.registers[0x0134..0x0136].copy_from_slice(&0x0011u16.to_le_bytes());
                    return Ok(());
                }
                if requested == 4 {
                    let valid = self.process_configuration_valid();
                    if !valid || self.fault == VirtualFault::SafeopReject {
                        self.registers[0x0130..0x0132].copy_from_slice(&0x0014u16.to_le_bytes());
                        self.registers[0x0134..0x0136].copy_from_slice(&0x001du16.to_le_bytes());
                        return Ok(());
                    }
                }
                ensure!(
                    matches!(requested, 1 | 2 | 4),
                    "unsupported virtual state request {requested}"
                );
                self.registers[0x0130..0x0132].copy_from_slice(&u16::from(requested).to_le_bytes());
                self.registers[0x0134..0x0136].fill(0);
                if let Some(output) = &mut self.output_rehearsal {
                    output.audit.outputs_active = false;
                    output.preload = None;
                    output.last_output_us = None;
                }
                if requested == 1 {
                    self.mailbox = None;
                    self.upload = None;
                    self.last_request = None;
                    self.last_response = None;
                    self.registers[0x080d] = 0;
                }
            }
            0x0502 if data.len() >= 6 && data[1] & 1 != 0 => {
                self.stats.sii_reads += 1;
                self.registers[0x0502..0x0504].fill(0); // Four-byte chunks, ready immediately.
            }
            MAILBOX_IN => self.coe_request(data)?,
            0x0600..=0x06ff => self.stats.fmmu_writes += 1,
            0x0800..=0x087f => self.stats.sync_manager_writes += 1,
            _ => {}
        }
        Ok(())
    }

    fn advance_output_time(&mut self, now_us: u128) {
        let output = self
            .output_rehearsal
            .as_mut()
            .expect("output rehearsal clock");
        debug_assert!(now_us >= output.now_us);
        output.now_us = now_us;
        if let Some((last, period)) = output.last_output_us.zip(output.watchdog_us)
            && now_us - last >= u128::from(period)
        {
            self.registers[usize::from(PD_WATCHDOG_STATUS)] = 0;
            if output.audit.outputs_active {
                output.audit.outputs_active = false;
                output.audit.watchdog_expired_at_us = Some(last + u128::from(period));
                if output.case != OutputRehearsalCase::WatchdogExpiresInOp {
                    self.registers[0x0130..0x0132].copy_from_slice(&0x14u16.to_le_bytes());
                    self.registers[0x0134..0x0136].copy_from_slice(&0x1bu16.to_le_bytes());
                }
            }
        }
    }

    fn enter_rehearsal_op(&mut self) -> Result<()> {
        let valid = self.process_configuration_valid()
            && word(&self.registers[0x0130..]) == 4
            && word(&self.registers[0x0134..]) == 0;
        let output = self
            .output_rehearsal
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("virtual fixture rejects OP entry"))?;
        if let Some(bytes) = output.preload
            && valid
            && output.case != OutputRehearsalCase::OpReject
            && self.registers[usize::from(PD_WATCHDOG_STATUS)] & 1 != 0
        {
            self.registers[0x0130..0x0132].copy_from_slice(&8u16.to_le_bytes());
            output.audit.outputs_active = true;
            output.audit.applied(bytes);
        } else {
            self.registers[0x0130..0x0132].copy_from_slice(&0x14u16.to_le_bytes());
            self.registers[0x0134..0x0136].copy_from_slice(&0x19u16.to_le_bytes());
        }
        Ok(())
    }

    fn logical_output(&mut self, address: u32, data: &[u8]) -> bool {
        self.stats.logical_writes += 1;
        if address != self.logical_starts.1 || !self.process_configuration_valid() {
            return false;
        }
        let Ok(bytes) = <[u8; 2]>::try_from(data) else {
            return false;
        };
        let state = word(&self.registers[0x0130..]);
        if word(&self.registers[0x0134..]) != 0 {
            return false;
        }
        let output = self.output_rehearsal.as_mut().expect("enabled for output");
        match state {
            4 if output.case != OutputRehearsalCase::PreloadWkc => {
                output.preload = Some(bytes);
                output.audit.preload_writes += 1;
            }
            8 if output.audit.outputs_active => {
                output.audit.op_writes += 1;
                output.audit.applied(bytes);
            }
            _ => return false,
        }
        output.last_output_us = Some(output.now_us);
        self.registers[usize::from(PD_WATCHDOG_STATUS)] = 1;
        self.registers[OUTPUTS..OUTPUTS + 2].copy_from_slice(data);
        true
    }

    fn process_configuration_valid(&self) -> bool {
        // Independently verify the SM/FMMU layout required by this authored fixture.
        let sms = match self.model {
            VirtualModel::Coe
            | VirtualModel::CoeDc
            | VirtualModel::CoeNormal
            | VirtualModel::CoeSegmented => [(2, OUTPUTS, 2, 4), (3, INPUTS, 8, 0)],
            VirtualModel::Sii => [(0, OUTPUTS, 2, 4), (1, INPUTS, 8, 0)],
        };
        let sms_ok = sms.into_iter().all(|(index, physical, len, direction)| {
            let sm = &self.registers[0x0800 + index * 8..];
            usize::from(word(sm)) == physical
                && usize::from(word(&sm[2..])) == len
                && sm[4] & 0x0f == direction
                && sm[6] & 1 == 1
        });
        let (input_start, output_start) = self.logical_starts;
        let fmmus = match self.model {
            VirtualModel::Coe
            | VirtualModel::CoeDc
            | VirtualModel::CoeNormal
            | VirtualModel::CoeSegmented => [
                (0, input_start, INPUTS, 8, 1),
                (1, output_start, OUTPUTS, 2, 2),
            ],
            VirtualModel::Sii => [
                (1, input_start, INPUTS, 8, 1),
                (0, output_start, OUTPUTS, 2, 2),
            ],
        };
        sms_ok
            && fmmus
                .into_iter()
                .all(|(index, logical, physical, len, mode)| {
                    let fmmu = &self.registers[0x0600 + index * 16..];
                    dword(fmmu) == logical
                        && usize::from(word(&fmmu[4..])) == len
                        && fmmu[6] == 0
                        && fmmu[7] == 7
                        && usize::from(word(&fmmu[8..])) == physical
                        && fmmu[10] == 0
                        && fmmu[11] == mode
                        && fmmu[12] & 1 == 1
                })
    }

    fn coe_request(&mut self, request: &[u8]) -> Result<()> {
        ensure!(
            request.len() >= 16 && request[5] & 15 == 3 && request[7] >> 4 == 2,
            "virtual fixture expects a CoE upload request"
        );
        let counter = (request[5] >> 4) & 7;
        ensure!(
            counter != 0,
            "virtual fixture requires mailbox counters 1–7"
        );
        if let Some(last) = &self.last_request
            && (last[5] >> 4) & 7 == counter
        {
            if last == request {
                self.stats.coe_duplicate_requests += 1;
                self.mailbox = self.last_response;
                if self.mailbox.is_some() {
                    self.registers[0x080d] |= 8;
                }
                return Ok(());
            }
            self.stats.mailbox_counter_errors += 1;
            bail!("virtual fixture detected a repeated mailbox counter with different data");
        }
        let mut response = [0u8; MAILBOX_BYTES];
        response[0] = 10;
        response[5] = request[5];
        response[7] = 0x30;
        let command = request[8] & 0xe0;
        let abort = |r: &mut [u8; MAILBOX_BYTES], index: u16, sub: u8, code: u32| {
            r[0] = 10;
            r[8] = 0x80;
            r[9..11].copy_from_slice(&index.to_le_bytes());
            r[11] = sub;
            r[12..16].copy_from_slice(&code.to_le_bytes());
        };
        if command == 0x40 {
            self.stats.coe_uploads += 1;
            let index = word(&request[9..]);
            let sub = request[11];
            response[9..12].copy_from_slice(&request[9..12]);
            self.upload = None;
            let data = if self.fault == VirtualFault::MailboxAbort
                || (self.fault == VirtualFault::ReadbackUnavailable
                    && self.process_configuration_valid())
                || (self.fault == VirtualFault::SyncTimingUnavailable
                    && self.process_configuration_valid()
                    && matches!(index, 0x1c32 | 0x1c33)
                    && matches!(sub, 2 | 5))
            {
                None
            } else if self.fault == VirtualFault::SyncTimingSize
                && self.process_configuration_valid()
                && index == 0x1c33
                && sub == 2
            {
                Some(vec![0, 0])
            } else if index == 0x1008 && sub == 0 {
                Some(b"Workbench CoE transfer fixture".to_vec())
            } else if index == 0x2000 && sub == 0 {
                Some(vec![0x11, 0x22, 0x33, 0x44])
            } else {
                self.object(index, sub)
                    .map(|(v, n)| v.to_le_bytes()[..usize::from(n)].to_vec())
            };
            if let Some(data) = data {
                let early_mapping = !self.process_configuration_valid()
                    && matches!(index, 0x1c12 | 0x1c13 | 0x1600 | 0x1a00);
                let early_normal = early_mapping && self.fault == VirtualFault::InitNormalUpload;
                let early_segmented =
                    early_mapping && self.fault == VirtualFault::InitSegmentedUpload;
                if (early_normal || early_segmented) && self.stats.initial_mapping_upload.is_none()
                {
                    self.stats.initial_mapping_upload = Some(InitialMappingUpload {
                        object_index: index,
                        subindex: sub,
                        declared_bytes: data.len() as u32,
                        form: if early_segmented {
                            InitialUploadForm::SegmentedInitiation
                        } else {
                            InitialUploadForm::Normal
                        },
                    });
                }
                let segmented = early_segmented
                    || (self.model == VirtualModel::CoeSegmented
                        && self.process_configuration_valid());
                let normal = (self.model == VirtualModel::CoeNormal
                    && self.process_configuration_valid())
                    || early_normal
                    || data.len() > 4;
                if segmented {
                    self.stats.coe_segmented_uploads += 1;
                    let initial = if self.fault == VirtualFault::SegmentInitialData {
                        data.len().saturating_sub(1).min(3)
                    } else {
                        0
                    };
                    response[0] = 10 + initial as u8;
                    response[8] = 0x41;
                    let total = if self.fault == VirtualFault::SegmentSize && index == 0x1008 {
                        u32::MAX
                    } else {
                        data.len() as u32
                    };
                    response[12..16].copy_from_slice(&total.to_le_bytes());
                    response[16..16 + initial].copy_from_slice(&data[..initial]);
                    self.upload = Some(Upload {
                        index,
                        sub,
                        data,
                        offset: initial,
                        toggle: false,
                    });
                } else if normal {
                    self.stats.coe_normal_uploads += 1;
                    ensure!(
                        data.len() <= MAILBOX_BYTES - 16,
                        "virtual normal payload too large"
                    );
                    response[0] = 10 + data.len() as u8;
                    response[8] = 0x41;
                    response[12..16].copy_from_slice(&(data.len() as u32).to_le_bytes());
                    response[16..16 + data.len()].copy_from_slice(&data);
                } else {
                    response[8] = 0x43 | (((4 - data.len()) as u8) << 2);
                    response[12..12 + data.len()].copy_from_slice(&data);
                }
                if self.fault == VirtualFault::MailboxCounter && index == 0x1008 {
                    response[5] ^= 0x10;
                }
            } else {
                abort(&mut response, index, sub, 0x0602_0000);
            }
        } else if command == 0x60 {
            self.stats.coe_segments += 1;
            if let Some(mut upload) = self.upload.take() {
                if (request[8] & 0x10 != 0) != upload.toggle {
                    abort(&mut response, upload.index, upload.sub, 0x0503_0000);
                } else if self.fault == VirtualFault::SegmentAbort && upload.index == 0x1008 {
                    abort(&mut response, upload.index, upload.sub, 0x0800_0020);
                } else if self.fault == VirtualFault::SegmentTimeout && upload.index == 0x1008 {
                    self.last_request = Some(request.to_vec());
                    self.last_response = None;
                    return Ok(());
                } else {
                    let n = (upload.data.len() - upload.offset).min(7);
                    let last = upload.offset + n == upload.data.len();
                    let toggle = upload.toggle
                        ^ (self.fault == VirtualFault::SegmentToggle
                            && upload.index == 0x1008
                            && upload.offset >= 7);
                    response[8] = (u8::from(toggle) << 4)
                        | (u8::from(last))
                        | if last { ((7 - n) as u8) << 1 } else { 0 };
                    response[9..9 + n]
                        .copy_from_slice(&upload.data[upload.offset..upload.offset + n]);
                    upload.offset += n;
                    upload.toggle = !upload.toggle;
                    if !last {
                        self.upload = Some(upload);
                    }
                }
            } else {
                abort(&mut response, 0, 0, 0x0504_0001);
            }
        } else {
            self.stats.coe_downloads += 1;
            abort(&mut response, word(&request[9..]), request[11], 0x0601_0002);
        }
        self.last_request = Some(request.to_vec());
        self.last_response = Some(response);
        self.mailbox = Some(response);
        self.registers[0x080d] |= 8;
        Ok(())
    }

    fn object(&self, index: u16, sub: u8) -> Option<(u32, u8)> {
        use crate::esi::modular_preview::inventory::{CONFIGURED, DETECTED};
        use ModuleInventoryCase::*;

        if matches!(index, CONFIGURED | DETECTED) {
            let case = self.module_inventory?;
            return match (index, sub, case) {
                (CONFIGURED, _, ConfiguredUnavailable) | (DETECTED, 2, DetectedEntryAbort) => None,
                (CONFIGURED, 0, MalformedCount) => Some((2, 2)),
                (DETECTED, 0, EmptyDetected) => Some((0, 1)),
                (DETECTED, _, EmptyDetected) => None,
                (_, 0, _) => Some((2, 1)),
                (DETECTED, 2, DetectedDiffers) => Some((0x401, 4)),
                (_, 1 | 2, _) => Some((0x400, 4)),
                _ => None,
            };
        }
        let entries = if self.fault == VirtualFault::PdoOrder {
            [0x6000_0320, 0x6000_0201, 15, 0x6000_0110]
        } else {
            [0x6000_0110, 0x6000_0201, 15, 0x6000_0320]
        };
        Some(match (index, sub) {
            (0x1c12 | 0x1c13, 0) | (0x1600, 0) => (1, 1),
            (0x1c12, 1) => (0x1600, 2),
            (0x1c13, 1) => (0x1a00, 2),
            (0x1600, 1) => (0x7000_0110, 4),
            (0x1a00, 0) => (4, 1),
            (0x1a00, 1..=4) => (entries[usize::from(sub - 1)], 4),
            (0x1c32 | 0x1c33, 1) => (0, 2),
            (0x1c32, 2) => (1_000_000, 4),
            (0x1c33, 2) => (2_000_000, 4),
            (0x1c32, 5) => (250_000, 4),
            (0x1c33, 5) => (0, 4),
            _ => return None,
        })
    }

    fn logical_read(&mut self, address: u32, data: &mut [u8]) -> Result<u16> {
        self.stats.logical_reads += 1;
        if self.stats.logical_reads == 2
            && self
                .dc_rehearsal
                .as_ref()
                .is_some_and(|dc| dc.case == DcRehearsalCase::InputWkc)
        {
            return Ok(0);
        }
        if matches!(
            self.fault,
            VirtualFault::TransportError | VirtualFault::TransportLost
        ) && self.stats.logical_reads == 9
        {
            self.transport_lost = self.fault == VirtualFault::TransportLost;
            self.stats.transport_errors += 1;
            bail!("virtual Ethernet transport failed during cyclic input");
        }
        if word(&self.registers[0x0130..]) != 4 || !self.process_configuration_valid() {
            return Ok(0);
        }
        let step =
            (((self.stats.logical_reads - 1) / 4) as u16).wrapping_add(self.logical_counter_offset);
        self.registers[INPUTS..INPUTS + 2].copy_from_slice(&step.to_le_bytes());
        self.registers[INPUTS + 2] = (step & 1) as u8;
        self.registers[INPUTS + 4..INPUTS + 8]
            .copy_from_slice(&(f32::from(step) / 4.0).to_le_bytes());
        let requested_end = u64::from(address) + data.len() as u64;
        let mut matched = false;
        for index in 0..2 {
            let fmmu = &self.registers[0x0600 + index * 16..];
            if fmmu[12] & 1 == 0 || fmmu[11] & 1 == 0 {
                continue;
            }
            let logical = u64::from(dword(fmmu));
            let end = logical + u64::from(word(&fmmu[4..]));
            let start = u64::from(address).max(logical);
            let finish = requested_end.min(end);
            if start < finish {
                let physical = usize::from(word(&fmmu[8..])) + (start - logical) as usize;
                let size = (finish - start) as usize;
                let offset = (start - u64::from(address)) as usize;
                data[offset..offset + size]
                    .copy_from_slice(&self.registers[physical..physical + size]);
                matched = true;
            }
        }
        Ok(u16::from(matched))
    }
}

fn word(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn dword(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn eeprom(model: VirtualModel, fault: VirtualFault) -> Vec<u8> {
    let mut bytes = vec![0u8; 512];
    let identity = model.identity();
    for (offset, value) in [
        (0x10, identity.vendor),
        (0x14, identity.product),
        (0x18, identity.revision),
        (0x1c, 1),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[0x7c..0x7e].copy_from_slice(&3u16.to_le_bytes());
    if model.has_coe() {
        for (offset, value) in [
            (0x30, MAILBOX_IN as u16),
            (0x32, MAILBOX_BYTES as u16),
            (0x34, MAILBOX_OUT as u16),
            (0x36, MAILBOX_BYTES as u16),
            (0x38, 4),
        ] {
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
    }
    let mut categories = Vec::new();
    categories.extend_from_slice(&[40, 0, 1, 0, 2, 1]);
    let channels = match model {
        VirtualModel::Coe
        | VirtualModel::CoeDc
        | VirtualModel::CoeNormal
        | VirtualModel::CoeSegmented => vec![
            (MAILBOX_IN as u16, MAILBOX_BYTES as u16, 0x26, 1),
            (MAILBOX_OUT as u16, MAILBOX_BYTES as u16, 0x22, 2),
            (OUTPUTS as u16, 2, 0x04, 3),
            (INPUTS as u16, 8, 0x00, 4),
        ],
        VirtualModel::Sii => vec![(OUTPUTS as u16, 2, 0x04, 3), (INPUTS as u16, 8, 0x00, 4)],
    };
    categories.extend_from_slice(&41u16.to_le_bytes());
    categories.extend_from_slice(&((channels.len() * 4) as u16).to_le_bytes());
    for (address, length, control, usage) in channels {
        categories.extend_from_slice(&address.to_le_bytes());
        categories.extend_from_slice(&length.to_le_bytes());
        categories.extend_from_slice(&[control, 0, 1, usage]);
    }
    if model == VirtualModel::Sii {
        categories.extend_from_slice(&[42, 0, 3, 0, 1, 1, 0, 0, 0, 0]);
        let entries: [u32; 4] = if fault == VirtualFault::PdoOrder {
            [0x6000_0320, 0x6000_0201, 15, 0x6000_0110]
        } else {
            [0x6000_0110, 0x6000_0201, 15, 0x6000_0320]
        };
        for (category, pdo, sm, entries) in [
            (50u16, 0x1a00u16, 1, &entries[..]),
            (51, 0x1600, 0, &[0x7000_0110][..]),
        ] {
            categories.extend_from_slice(&category.to_le_bytes());
            categories.extend_from_slice(&((8 + entries.len() * 8) as u16 / 2).to_le_bytes());
            categories.extend_from_slice(&pdo.to_le_bytes());
            categories.extend_from_slice(&[entries.len() as u8, sm, 0, 0, 0, 0]);
            for entry in entries {
                categories.extend_from_slice(&((entry >> 16) as u16).to_le_bytes());
                categories.extend_from_slice(&[(entry >> 8) as u8, 0, 0, *entry as u8, 0, 0]);
            }
        }
    }
    categories.extend_from_slice(&[0xff, 0xff, 0, 0]);
    bytes[0x80..0x80 + categories.len()].copy_from_slice(&categories);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Datagram, FPRD, FPWR, Frame};

    #[test]
    fn group_pdo_readback_keeps_the_scan_write_guard_for_other_commands() {
        let mut wire = VirtualWire::with_group_layout(GROUP_PAIR);
        let mut request = [0; MAILBOX_BYTES];
        request[0] = 10;
        request[5] = 0x13;
        request[7] = 0x20;
        request[8] = 0x40;
        request[9..11].copy_from_slice(&0x1c13u16.to_le_bytes());
        assert!(wire.devices[0].write(MAILBOX_IN, &request).is_err());
        assert!(wire.devices[1].write(0x0502, &[0, 1, 8, 0, 0, 0]).is_err());

        wire.prepare_group_pdo_readback();
        assert!(wire.devices[0].write(MAILBOX_IN, &request).is_ok());
        assert!(wire.devices[1].write(0x0502, &[0, 1, 8, 0, 0, 0]).is_ok());
        request[8] = 0x2f;
        assert!(wire.devices[0].write(MAILBOX_IN, &request).is_err());
        assert!(wire.devices[1].write(0x0502, &[0, 2, 8, 0, 0, 0]).is_err());
        assert!(wire.devices[0].write(0x0120, &[8, 0]).is_err());
        assert!(wire.devices[0].write(0x0808, &[0; 8]).is_err());
        assert!(wire.devices[0].write(OUTPUTS, &[1, 0]).is_err());
        assert!(wire.devices[0].stats.state_requests.is_empty());
        assert_eq!(wire.devices[0].stats.coe_downloads, 0);
    }

    #[test]
    fn dc_rehearsal_rejects_a_cycle_write_that_reaches_latch_registers() {
        let mut wire = VirtualWire::for_dc_rehearsal(DcRehearsalCase::Normal);
        let sentinel = [2, 3, 0x5a, 0xa5];
        wire.devices[0].registers[0x09a8..0x09ac].copy_from_slice(&sentinel);
        let frame = Frame::new(1, [Datagram::register(FPRD, 0, DC_SYNC1_DELAY, 8)]);
        let mut oversized = frame.bytes().to_vec();
        oversized[16] = FPWR;
        let error = wire.send(&oversized).unwrap_err();
        assert!(error.to_string().contains("requires a 4-byte write, got 8"));
        assert!(wire.stats().dc_program_writes.is_empty());

        let frame = Frame::new(2, [Datagram::register(FPRD, 0, DC_SYNC1_DELAY, 4)]);
        let mut exact = frame.bytes().to_vec();
        exact[16] = FPWR;
        exact[26..30].copy_from_slice(&500_000u32.to_le_bytes());
        wire.send(&exact).unwrap();
        assert_eq!(wire.stats().dc_program_writes[0].wkc, 1);
        assert_eq!(dword(&wire.devices[0].registers[0x09a4..]), 500_000);
        assert_eq!(wire.devices[0].registers[0x09a8..0x09ac], sentinel);
    }

    #[test]
    fn two_devices_accumulate_broadcast_and_resolve_auto_increment_positions() {
        let mut wire = VirtualWire::for_scan(VirtualModel::Coe, ScanCase::TwoDevices);
        let request = Frame::new(
            1,
            [
                Datagram::register(BRD, 0, 0x0000, 2),
                Datagram::register(APRD, 0, 0x0010, 4),
                Datagram::register(APRD, u16::MAX, 0x0010, 4),
            ],
        );
        wire.send(request.bytes()).unwrap();
        let reply = wire.receive().unwrap();
        assert_eq!(
            request.reply(reply).unwrap(),
            [
                (&[0x13, 0][..], 2),
                (&[0, 0x10, 0x42, 0][..], 1),
                (&[1, 0x10, 0x43, 0][..], 1),
            ]
        );
        assert_eq!(
            [word(&reply[18..]), word(&reply[32..]), word(&reply[48..])],
            [2, 2, 1]
        );
    }

    #[test]
    fn grouped_lrd_and_al_reads_gate_scope_to_one_matching_reply() {
        use crate::input_group::{InputGroup, fmmu, sync_manager};
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/input-group.json");
        let group = InputGroup::load(&path).unwrap();
        let plan = group.inspect(None).unwrap();
        assert_eq!((plan.input_bytes, plan.expected_wkc), (16, 2));
        let stations = GROUP_STATIONS;
        let mut wire = VirtualWire::with_group_layout(GROUP_PAIR);
        let exchange = |wire: &mut VirtualWire, index| {
            let request = group.expected_frame(index, &stations).unwrap();
            wire.send(request.bytes()).unwrap();
            group
                .inspect_reply(index, &stations, wire.receive().unwrap(), None)
                .unwrap()
        };
        let review_fmmu = |wire: &mut VirtualWire, position: usize| {
            let station = stations[position];
            let request = Frame::new(
                0,
                [
                    Datagram::register(FPRD, station, 0x0004, 1),
                    Datagram::register(FPRD, station, 0x0600, 16),
                    Datagram::register(FPRD, station, 0x0610, 16),
                ],
            );
            wire.send(request.bytes()).unwrap();
            let [(count, count_wkc), first, second] =
                request.reply(wire.receive().unwrap()).unwrap();
            let evidence = fmmu::Station {
                station_address: station,
                count: fmmu::Read {
                    wkc: count_wkc,
                    value: count[0],
                },
                slots: [first, second]
                    .into_iter()
                    .map(|(bytes, wkc)| fmmu::Read {
                        wkc,
                        value: bytes.try_into().unwrap(),
                    })
                    .collect(),
            };
            let start = plan.devices[position].offset.unwrap() as u64;
            fmmu::check(evidence, position, Some(start..start + 8))
        };
        let review_sync_managers = |wire: &mut VirtualWire, position: usize| {
            let station_address = stations[position];
            let request = Frame::new(0, [Datagram::register(FPRD, station_address, 0x0005, 1)]);
            wire.send(request.bytes()).unwrap();
            let [(count, wkc)] = request.reply(wire.receive().unwrap()).unwrap();
            let count = fmmu::Read {
                wkc,
                value: count[0],
            };
            let slots = (0..count.value)
                .map(|slot| {
                    let address = 0x0800 + u16::from(slot) * 8;
                    let request = Frame::new(
                        slot,
                        [Datagram::register(FPRD, station_address, address, 8)],
                    );
                    wire.send(request.bytes()).unwrap();
                    let [(bytes, wkc)] = request.reply(wire.receive().unwrap()).unwrap();
                    fmmu::Read {
                        wkc,
                        value: bytes.try_into().unwrap(),
                    }
                })
                .collect();
            let evidence = sync_manager::Station {
                station_address,
                count,
                slots,
            };
            let fmmu = review_fmmu(wire, position);
            assert!(fmmu.issues.is_empty());
            sync_manager::check(evidence, position, &fmmu)
        };
        assert!(review_sync_managers(&mut wire, 0).issues.is_empty());
        assert!(review_sync_managers(&mut wire, 1).issues.is_empty());
        wire.devices[1].registers[0x0618] = 1; // Shift only the SII device's physical input start.
        let wrong_physical = review_sync_managers(&mut wire, 1);
        assert!(
            wrong_physical
                .issues
                .iter()
                .any(|issue| issue.contains("physical coverage differs"))
        );
        wire.devices[1].registers[0x0618] = 0;
        let decoded = exchange(&mut wire, 1);
        assert!(decoded.frame.unwrap().valid);
        assert!(
            decoded
                .devices
                .iter()
                .all(|device| device.al.as_ref().unwrap().actual_wkc == 1)
        );
        assert_eq!(
            decoded.devices[0].input.as_ref().unwrap().raw_hex,
            "0000000000000000"
        );
        assert_eq!(
            decoded.devices[1].input.as_ref().unwrap().raw_hex,
            "010001000000803e"
        );

        wire.devices[1].registers[0x0134] = 0x1e;
        let dirty = exchange(&mut wire, 2);
        let frame = dirty.frame.unwrap();
        assert!(frame.lrd_wkc_matches && !frame.valid);
        assert_eq!(
            dirty.devices[1]
                .al
                .as_ref()
                .unwrap()
                .status
                .as_ref()
                .unwrap()
                .code,
            0x1e
        );
        assert!(dirty.devices.iter().all(|device| device.input.is_none()));

        wire.devices[1].registers[0x0134] = 0;
        wire.devices[1].registers[0x0130] = 2; // The downstream ESC stops contributing process data.
        let partial = exchange(&mut wire, 3);
        let frame = partial.frame.unwrap();
        assert!(!frame.lrd_wkc_matches && !frame.valid);
        assert_eq!(
            partial.devices[1]
                .al
                .as_ref()
                .unwrap()
                .status
                .as_ref()
                .unwrap()
                .state,
            "PREOP"
        );
        assert!(partial.devices.iter().all(|device| device.input.is_none()));

        wire.devices[1].registers[0x0130] = 4;
        wire.devices[1].registers[0x0010] = 2; // The requested station no longer answers.
        let missing = exchange(&mut wire, 4);
        let frame = missing.frame.unwrap();
        assert!(frame.lrd_wkc_matches && !frame.valid);
        let al = missing.devices[1].al.as_ref().unwrap();
        assert_eq!(al.actual_wkc, 0);
        assert!(al.status.is_none());
        assert!(missing.devices.iter().all(|device| device.input.is_none()));

        wire.devices[1].registers[0x0010] = 1;
        // The second ESC now contributes to the LRD one byte before its expected slot.
        wire.devices[1].logical_starts.0 = 7;
        wire.devices[1].registers[0x0610] = 7;
        assert!(exchange(&mut wire, 5).frame.unwrap().valid);
        assert!(
            review_fmmu(&mut wire, 1)
                .issues
                .iter()
                .any(|issue| issue.contains("outside planned input"))
        );
        for audit in wire.chain_audits() {
            assert_eq!(
                audit.register_writes + audit.logical_writes + audit.physical_output_writes,
                0
            );
            assert!(audit.state_requests.is_empty());
        }
    }

    #[test]
    fn scan_fixture_rejects_a_register_write_before_changing_state() {
        let mut esc = VirtualWire::for_scan(VirtualModel::Coe, ScanCase::Normal);
        let mut frame = Frame::new(1, [Datagram::register(FPRD, 0, 0x0120, 2)])
            .bytes()
            .to_vec();
        frame[16] = 5;
        frame[26] = 8;
        assert!(
            esc.send(&frame)
                .unwrap_err()
                .to_string()
                .contains("read-only scan")
        );
        assert_eq!(esc.stats().register_writes, 1);
        assert_eq!(esc.stats().final_al_status, 1);
        assert!(esc.stats().state_requests.is_empty());
    }

    #[test]
    fn rejects_output_commands_and_requires_valid_fmmus_for_safeop() {
        let mut esc = VirtualWire::new(VirtualModel::Coe, VirtualFault::None);
        let mut write = Frame::new(1, [Datagram::register(FPRD, 0, 0x0120, 2)])
            .bytes()
            .to_vec();
        write[16] = 5;
        write[26] = 4; // SAFEOP request with no configured SMs/FMMUs.
        esc.send(&write).unwrap();
        assert_eq!(esc.stats().final_al_status, 0x14);
        assert_eq!(esc.stats().final_al_code, 0x1d);
        write[26] = 1; // An unacknowledged request retains the error.
        esc.send(&write).unwrap();
        assert_eq!(esc.stats().final_al_status, 0x14);
        write[26] = 0x11;
        esc.send(&write).unwrap();
        assert_eq!(esc.stats().final_al_status, 1);
        write[26] = 8;
        assert!(
            esc.send(&write)
                .unwrap_err()
                .to_string()
                .contains("OP entry")
        );
        assert_eq!(esc.stats().op_requests, 1);
        write[16] = 0x0c;
        assert!(
            esc.send(&write)
                .unwrap_err()
                .to_string()
                .contains("output writes")
        );
        assert_eq!(esc.stats().logical_writes, 1);
    }

    #[test]
    fn reports_sdo_download_attempt_and_preserves_the_authored_mapping() {
        let mut esc = VirtualEsc::new(VirtualModel::Coe, VirtualFault::None);
        let mut request = [0u8; MAILBOX_BYTES];
        request[5] = 0x13;
        request[7] = 0x20;
        request[8] = 0x23; // SDO expedited download, four bytes.
        request[9..11].copy_from_slice(&0x1a00u16.to_le_bytes());
        request[11] = 1;
        let before = esc.object(0x1a00, 1);
        esc.coe_request(&request).unwrap();
        assert_eq!(esc.stats.coe_downloads, 1);
        assert_eq!(esc.object(0x1a00, 1), before);
        assert_eq!(esc.mailbox.unwrap()[8], 0x80);
    }
}

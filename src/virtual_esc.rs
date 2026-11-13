//! Authored, in-memory EtherCAT ESC fixture for the Workbench's one-device setup path.
use anyhow::{Result, bail, ensure};
use clap::ValueEnum;
use serde::Serialize;
use std::{collections::VecDeque, time::Instant};

const MAILBOX_IN: usize = 0x1000;
const MAILBOX_OUT: usize = 0x1040;
const MAILBOX_BYTES: usize = 64;
const OUTPUTS: usize = 0x1100;
const INPUTS: usize = 0x1200;

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
}

struct Upload {
    index: u16,
    sub: u8,
    data: Vec<u8>,
    offset: usize,
    toggle: bool,
}

pub(crate) struct VirtualEsc {
    scan_case: ScanCase,
    read_only: bool,
    registers: Box<[u8; 65_536]>,
    eeprom: Vec<u8>,
    replies: VecDeque<Vec<u8>>,
    current: Option<Vec<u8>>,
    mailbox: Option<[u8; MAILBOX_BYTES]>,
    stats: VirtualStats,
    fault: VirtualFault,
    model: VirtualModel,
    clock_started: Instant,
    transport_lost: bool,
    upload: Option<Upload>,
    last_request: Option<Vec<u8>>,
    last_response: Option<[u8; MAILBOX_BYTES]>,
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
            registers,
            eeprom: eeprom(model, fault),
            replies: VecDeque::new(),
            current: None,
            mailbox: None,
            stats: VirtualStats {
                model,
                ..VirtualStats::default()
            },
            fault,
            model,
            clock_started: Instant::now(),
            transport_lost: false,
            upload: None,
            last_request: None,
            last_response: None,
        }
    }

    pub fn for_scan(model: VirtualModel, case: ScanCase) -> Self {
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

    pub fn receive(&mut self) -> Option<&[u8]> {
        self.current = self.replies.pop_front();
        self.current.as_deref()
    }

    pub fn send(&mut self, bytes: &[u8]) -> Result<()> {
        if self.transport_lost {
            self.stats.transport_errors += 1;
            bail!("virtual Ethernet transport remains unavailable");
        }
        ensure!(
            bytes.len() >= 16 && bytes[12..14] == [0x88, 0xa4],
            "virtual ESC requires Ethernet II EtherCAT"
        );
        let payload_len = usize::from(word(&bytes[14..]) & 0x07ff);
        let end = 16 + payload_len;
        ensure!(
            end <= bytes.len(),
            "truncated EtherCAT frame sent to virtual ESC"
        );
        let mut reply = bytes.to_vec();
        reply[6] |= 2;
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
                0x0e => {
                    self.stats.dc_clock_distribution += 1;
                    bail!("virtual fixture rejects cyclic DC clock distribution")
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
                        self.read(usize::from(register), data)?;
                        u16::from(
                            !(self.fault == VirtualFault::DcReadbackUnavailable
                                && (0x0980..=0x0981).contains(&register)),
                        )
                    }
                    0x02 | 0x05 | 0x08 => {
                        self.write(usize::from(register), data)?;
                        u16::from(register != 0x0900 || self.model == VirtualModel::CoeDc)
                    }
                    0x0a => {
                        let address = u32::from(station) | (u32::from(register) << 16);
                        self.logical_read(address, data)?
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
            if command == 0x01 {
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
            reply[data_end..data_end + 2].copy_from_slice(&wkc.to_le_bytes());
            offset = data_end + 2;
            ensure!(
                (flags & 0x8000 != 0) == (offset < end),
                "inconsistent virtual ESC datagram chain"
            );
        }
        if drop_reply {
            self.stats.dropped_replies += 1;
        } else {
            self.replies.push_back(reply);
        }
        Ok(())
    }

    fn read(&mut self, register: usize, data: &mut [u8]) -> Result<()> {
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

    fn write(&mut self, register: usize, data: &[u8]) -> Result<()> {
        self.stats.register_writes += 1;
        ensure!(
            !self.read_only,
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
                        bail!("virtual fixture rejects DC enable requests");
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
                    bail!("virtual fixture rejects OP entry");
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
        let fmmus = match self.model {
            VirtualModel::Coe
            | VirtualModel::CoeDc
            | VirtualModel::CoeNormal
            | VirtualModel::CoeSegmented => [(0, 0u32, INPUTS, 8, 1), (1, 8, OUTPUTS, 2, 2)],
            VirtualModel::Sii => [(1, 0u32, INPUTS, 8, 1), (0, 8, OUTPUTS, 2, 2)],
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
                let segmented =
                    self.model == VirtualModel::CoeSegmented && self.process_configuration_valid();
                let normal = (self.model == VirtualModel::CoeNormal
                    && self.process_configuration_valid())
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
        let step = ((self.stats.logical_reads - 1) / 4) as u16;
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
    for (offset, value) in [
        (0x10, 0x00ff_1000u32),
        (
            0x14,
            match model {
                VirtualModel::Coe => 1,
                VirtualModel::Sii => 2,
                VirtualModel::CoeDc => 3,
                VirtualModel::CoeNormal => 4,
                VirtualModel::CoeSegmented => 5,
            },
        ),
        (0x18, 1),
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
    use crate::wire::{Datagram, FPRD, Frame};

    #[test]
    fn scan_fixture_rejects_a_register_write_before_changing_state() {
        let mut esc = VirtualEsc::for_scan(VirtualModel::Coe, ScanCase::Normal);
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
        let mut esc = VirtualEsc::new(VirtualModel::Coe, VirtualFault::None);
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

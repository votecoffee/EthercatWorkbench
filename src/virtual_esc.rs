//! Authored, in-memory EtherCAT ESC fixture for the Workbench's one-device setup path.
use anyhow::{Result, bail, ensure};
use clap::ValueEnum;
use serde::Serialize;
use std::collections::VecDeque;

const MAILBOX_IN: usize = 0x1000;
const MAILBOX_OUT: usize = 0x1040;
const MAILBOX_BYTES: usize = 64;
const OUTPUTS: usize = 0x1100;
const INPUTS: usize = 0x1200;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum VirtualFault {
    #[default]
    None,
    PdoOrder,
    SafeopReject,
    MailboxAbort,
    ReadbackUnavailable,
    CleanupReject,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct VirtualStats {
    pub datagrams: u64,
    pub sii_reads: u64,
    pub coe_uploads: u64,
    pub coe_downloads: u64,
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

pub(crate) struct VirtualEsc {
    registers: Box<[u8; 65_536]>,
    eeprom: Vec<u8>,
    replies: VecDeque<Vec<u8>>,
    current: Option<Vec<u8>>,
    mailbox: Option<[u8; MAILBOX_BYTES]>,
    stats: VirtualStats,
    fault: VirtualFault,
}

impl VirtualEsc {
    pub fn new(fault: VirtualFault) -> Self {
        let mut registers = Box::new([0u8; 65_536]);
        registers[0] = 0x11;
        registers[4] = 2; // FMMU channels.
        registers[5] = 4; // SyncManager channels.
        registers[0x0110] = 0x13; // One linked port, PDI operational, watchdog OK.
        registers[0x0130] = 1; // INIT.
        Self {
            registers,
            eeprom: eeprom(),
            replies: VecDeque::new(),
            current: None,
            mailbox: None,
            stats: VirtualStats::default(),
            fault,
        }
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
                        1
                    }
                    0x02 | 0x05 | 0x08 => {
                        self.write(usize::from(register), data)?;
                        // The virtual device declares no Distributed Clock support.
                        u16::from(register != 0x0900)
                    }
                    0x0a => {
                        let address = u32::from(station) | (u32::from(register) << 16);
                        self.logical_read(address, data)?
                    }
                    _ => unreachable!(),
                };
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
        self.replies.push_back(reply);
        Ok(())
    }

    fn read(&mut self, register: usize, data: &mut [u8]) -> Result<()> {
        let end = register
            .checked_add(data.len())
            .filter(|end| *end <= self.registers.len());
        ensure!(end.is_some(), "virtual ESC register read outside memory");
        if register == 0x0508 {
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
        let end = register
            .checked_add(data.len())
            .filter(|end| *end <= self.registers.len())
            .ok_or_else(|| anyhow::anyhow!("virtual ESC register write outside memory"))?;
        if end > OUTPUTS && register < OUTPUTS + 2 {
            self.stats.physical_output_writes += 1;
            bail!("virtual fixture rejects physical output data writes");
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
        let sms = [(2, OUTPUTS, 2, 4), (3, INPUTS, 8, 0)];
        let sms_ok = sms.into_iter().all(|(index, physical, len, direction)| {
            let sm = &self.registers[0x0800 + index * 8..];
            usize::from(word(sm)) == physical
                && usize::from(word(&sm[2..])) == len
                && sm[4] & 0x0f == direction
                && sm[6] & 1 == 1
        });
        let fmmus = [(0, 0u32, INPUTS, 8, 1), (1, 8, OUTPUTS, 2, 2)];
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
            request.len() >= 16 && request[5] & 0x0f == 3,
            "virtual fixture expects a CoE mailbox request"
        );
        let mut response = [0u8; MAILBOX_BYTES];
        response[0] = 10;
        response[5] = request[5]; // Echo mailbox counter and CoE type.
        response[7] = 0x30; // SDO response.
        response[9..12].copy_from_slice(&request[9..12]);
        let index = word(&request[9..]);
        let sub = request[11];
        let value = if request[8] & 0xe0 == 0x40 {
            self.stats.coe_uploads += 1;
            if self.fault == VirtualFault::MailboxAbort
                || (self.fault == VirtualFault::ReadbackUnavailable
                    && self.process_configuration_valid())
            {
                None
            } else {
                self.object(index, sub)
            }
        } else {
            self.stats.coe_downloads += 1;
            None
        };
        if let Some((value, size)) = value {
            response[8] = 0x43 | ((4 - size) << 2);
            response[12..16].copy_from_slice(&value.to_le_bytes());
        } else {
            response[8] = 0x80;
            response[12..16].copy_from_slice(&0x0602_0000u32.to_le_bytes());
        }
        self.mailbox = Some(response);
        self.registers[0x080d] |= 0x08;
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
            _ => return None,
        })
    }

    fn logical_read(&mut self, address: u32, data: &mut [u8]) -> Result<u16> {
        self.stats.logical_reads += 1;
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

fn eeprom() -> Vec<u8> {
    let mut bytes = vec![0u8; 512];
    for (offset, value) in [(0x10, 0x00ff_1000u32), (0x14, 1), (0x18, 1), (0x1c, 1)] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [
        (0x30, MAILBOX_IN as u16),
        (0x32, MAILBOX_BYTES as u16),
        (0x34, MAILBOX_OUT as u16),
        (0x36, MAILBOX_BYTES as u16),
        (0x38, 4),
        (0x7c, 3),
    ] {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    let mut categories = Vec::new();
    // FMMU usage in SII category 40, input then output.
    categories.extend_from_slice(&[40, 0, 1, 0, 2, 1]);
    // Four SII SyncManager descriptors, category 41.
    categories.extend_from_slice(&[41, 0, 16, 0]);
    for (address, length, control, usage) in [
        (MAILBOX_IN as u16, MAILBOX_BYTES as u16, 0x26, 1),
        (MAILBOX_OUT as u16, MAILBOX_BYTES as u16, 0x22, 2),
        (OUTPUTS as u16, 2, 0x04, 3),
        (INPUTS as u16, 8, 0x00, 4),
    ] {
        categories.extend_from_slice(&address.to_le_bytes());
        categories.extend_from_slice(&length.to_le_bytes());
        categories.extend_from_slice(&[control, 0, 1, usage]);
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
    fn rejects_output_commands_and_requires_valid_fmmus_for_safeop() {
        let mut esc = VirtualEsc::new(VirtualFault::None);
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
        let mut esc = VirtualEsc::new(VirtualFault::None);
        let mut request = [0u8; MAILBOX_BYTES];
        request[5] = 0x13;
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

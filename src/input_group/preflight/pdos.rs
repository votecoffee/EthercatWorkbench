//! Capture TxPDO descriptors from the authored ESCs using the in-memory wire.
use super::super::{decode_frame_hex, pdo_readback, sync_manager};
use crate::{
    model::Identity,
    pdo::{Layout, MappingSource, Pdo, SyncManager},
    review::check_cancel,
    sii::{MAX_CATEGORIES_BYTES, SiiPdos},
    virtual_esc::{GroupFixture, VirtualWire},
    wire::{Datagram, FPRD, FPWR, Frame},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicBool;

const MAX_PDOS: usize = 64;
const MAX_ENTRIES: usize = 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Exchange {
    request_hex: String,
    reply_hex: String,
}

pub(super) fn capture(
    wire: &mut VirtualWire,
    fixture: GroupFixture,
    sync_managers: &sync_manager::Review,
    first_index: u8,
) -> Result<(pdo_readback::Snapshot, Vec<Exchange>)> {
    let mut exchanges = Vec::new();
    let mut reader = Reader {
        next_index: first_index,
        transfer: |frame: &Frame<1>| {
            wire.send(frame.bytes())?;
            let reply = wire
                .receive()
                .context("missing virtual PDO readback reply")?;
            exchanges.push(Exchange {
                request_hex: hex::encode(frame.bytes()),
                reply_hex: hex::encode(reply),
            });
            Ok(reply.to_vec())
        },
    };
    let snapshot = reader.capture_snapshot(fixture, sync_managers, false)?;
    Ok((snapshot, exchanges))
}

pub(super) fn rebuild(
    exchanges: &[Exchange],
    fixture: GroupFixture,
    sync_managers: &sync_manager::Review,
    first_index: u8,
    stop: Option<&AtomicBool>,
) -> Result<pdo_readback::Snapshot> {
    let mut saved = exchanges.iter().enumerate();
    let mut reader = Reader {
        next_index: first_index,
        transfer: |frame: &Frame<1>| {
            check_cancel(stop)?;
            let (index, exchange) = saved.next().context("missing saved PDO exchange")?;
            let request = decode_frame_hex(&exchange.request_hex)?;
            let reply = decode_frame_hex(&exchange.reply_hex)?;
            ensure!(
                request == frame.bytes(),
                "saved PDO exchange {} request differs from the expected frame",
                index + 1
            );
            ensure!(
                reply.len() == request.len(),
                "saved PDO exchange {} reply length differs from the request",
                index + 1
            );
            Ok(reply)
        },
    };
    let snapshot = reader.capture_snapshot(fixture, sync_managers, true)?;
    ensure!(saved.next().is_none(), "unexpected trailing PDO exchanges");
    Ok(snapshot)
}

struct Reader<F> {
    next_index: u8,
    transfer: F,
}

impl<F: FnMut(&Frame<1>) -> Result<Vec<u8>>> Reader<F> {
    fn capture_snapshot(
        &mut self,
        fixture: GroupFixture,
        sync_managers: &sync_manager::Review,
        strict: bool,
    ) -> Result<pdo_readback::Snapshot> {
        let mut devices = Vec::with_capacity(fixture.stations.len());
        for ((&station, model), sync_manager) in fixture
            .stations
            .iter()
            .zip(fixture.devices)
            .zip(&sync_managers.devices)
        {
            let identity = Identity {
                vendor: self.sii_word(station, 0x0008).map(u32::from_le_bytes)?,
                product: self.sii_word(station, 0x000a).map(u32::from_le_bytes)?,
                revision: self.sii_word(station, 0x000c).map(u32::from_le_bytes)?,
            };
            let inputs: Vec<_> = sync_manager
                .input_buffers()
                .map(|(slot, range)| (slot as u8, range.len()))
                .collect();
            let layout = if model.model.has_coe() {
                self.coe_layout(station, &inputs)
            } else {
                self.sii_categories(station)
                    .and_then(|raw| SiiPdos::parse(&raw))
                    .map(|sii| sii.layout(true, &inputs))
            };
            let (tx, tx_unavailable) = match layout {
                Ok(layout) => (
                    Some(pdo_readback::TxLayout {
                        mapping_source: layout.mapping_source,
                        sync_managers: layout.sync_managers,
                    }),
                    None,
                ),
                Err(error) if strict => {
                    return Err(error)
                        .with_context(|| format!("PDO exchanges at station {station:#06x}"));
                }
                Err(error) => (None, Some(format!("{error:#}"))),
            };
            devices.push(pdo_readback::Station {
                station_address: station,
                identity,
                tx,
                tx_unavailable,
            });
        }
        Ok(pdo_readback::Snapshot { schema: 1, devices })
    }

    fn exchange(&mut self, frame: Frame<1>) -> Result<Vec<u8>> {
        self.next_index = self.next_index.wrapping_add(1);
        let reply = (self.transfer)(&frame)?;
        let [(bytes, wkc)] = frame
            .reply(&reply)
            .context("virtual PDO readback reply does not match its request")?;
        ensure!(
            wkc == 1,
            "virtual PDO readback needs Working Counter 1, received {wkc}"
        );
        Ok(bytes.to_vec())
    }

    fn read(&mut self, station: u16, register: u16, width: usize) -> Result<Vec<u8>> {
        self.exchange(Frame::new(
            self.next_index,
            [Datagram::register(FPRD, station, register, width)],
        ))
    }

    fn command(&mut self, station: u16, register: u16, payload: &[u8]) -> Result<()> {
        let echo = self.exchange(Frame::write(
            self.next_index,
            FPWR,
            station,
            register,
            payload,
        ))?;
        ensure!(echo == payload, "virtual PDO read command echo differs");
        Ok(())
    }

    fn sii_word(&mut self, station: u16, word_address: u16) -> Result<[u8; 4]> {
        let [low, high] = word_address.to_le_bytes();
        self.command(station, 0x0502, &[0, 1, low, high, 0, 0])?;
        ensure!(
            self.read(station, 0x0502, 2)? == [0, 0],
            "virtual EEPROM read did not finish in the expected 32-bit mode"
        );
        Ok(self
            .read(station, 0x0508, 4)?
            .try_into()
            .expect("four-byte frame matched"))
    }

    fn sii_categories(&mut self, station: u16) -> Result<Vec<u8>> {
        let mut address = 0x0040;
        let mut bytes = Vec::new();
        loop {
            ensure!(
                bytes.len() + 4 <= MAX_CATEGORIES_BYTES,
                "SII category headers exceed 16 KiB"
            );
            let header = self.sii_word(station, address)?;
            bytes.extend_from_slice(&header);
            if header[..2] == [0xff, 0xff] {
                return Ok(bytes);
            }
            let words = u16::from_le_bytes([header[2], header[3]]);
            let len = usize::from(words) * 2;
            ensure!(
                bytes.len() + len <= MAX_CATEGORIES_BYTES,
                "SII categories exceed 16 KiB"
            );
            address += 2;
            for offset in (0..len).step_by(4) {
                let data = self.sii_word(station, address + (offset / 2) as u16)?;
                bytes.extend_from_slice(&data[..(len - offset).min(4)]);
            }
            address += words;
        }
    }

    fn coe_layout(&mut self, station: u16, inputs: &[(u8, usize)]) -> Result<Layout> {
        let mailbox = self.discover_mailboxes(station)?;
        let mut counter = 0;
        let mut total_pdos = 0;
        let mut total_entries = 0;
        let mut sync_managers = Vec::new();
        for &(channel, bytes) in inputs {
            let assignment = 0x1c10 + u16::from(channel);
            let count = self.upload(station, &mailbox, &mut counter, (assignment, 0), 1)? as u8;
            total_pdos += usize::from(count);
            ensure!(
                total_pdos <= MAX_PDOS,
                "virtual CoE assignment exceeds {MAX_PDOS} PDOs"
            );
            let mut pdos = Vec::with_capacity(usize::from(count));
            for sub in 1..=count {
                let index =
                    self.upload(station, &mailbox, &mut counter, (assignment, sub), 2)? as u16;
                ensure!(
                    (0x1a00..=0x1bff).contains(&index),
                    "virtual CoE returned an invalid TxPDO index {index:#06x}"
                );
                let entries = self.upload(station, &mailbox, &mut counter, (index, 0), 1)? as u8;
                total_entries += usize::from(entries);
                ensure!(
                    total_entries <= MAX_ENTRIES,
                    "virtual CoE mapping exceeds {MAX_ENTRIES} entries"
                );
                let entries = (1..=entries)
                    .map(|sub| self.upload(station, &mailbox, &mut counter, (index, sub), 4))
                    .collect::<Result<_>>()?;
                pdos.push(Pdo { index, entries });
            }
            sync_managers.push(SyncManager {
                index: channel,
                configured_bytes: Some(bytes),
                pdos,
            });
        }
        Ok(Layout {
            mapping_source: MappingSource::Coe,
            sync_managers,
        })
    }

    fn upload(
        &mut self,
        station: u16,
        mailbox: &Mailboxes,
        counter: &mut u8,
        (object, sub): (u16, u8),
        width: usize,
    ) -> Result<u32> {
        for slot in [mailbox.write.slot, mailbox.read.slot] {
            let status = self.read(station, 0x0805 + u16::from(slot) * 8, 1)?[0];
            ensure!(
                status & 8 == 0,
                "unexpected pending virtual CoE mailbox data"
            );
        }
        *counter = *counter % 7 + 1;
        let mut request = vec![0; mailbox.write.bytes];
        request[0] = 10;
        request[5] = 3 | (*counter << 4);
        request[7] = 0x20;
        request[8] = 0x40;
        request[9..11].copy_from_slice(&object.to_le_bytes());
        request[11] = sub;
        self.command(station, mailbox.write.address, &request)?;
        ensure!(
            self.read(station, 0x0805 + u16::from(mailbox.read.slot) * 8, 1)?[0] & 8 != 0,
            "virtual CoE upload did not produce a response"
        );
        let reply = self.read(station, mailbox.read.address, mailbox.read.bytes)?;
        ensure!(
            reply[..2] == [10, 0]
                && reply[5] == request[5]
                && reply[7] >> 4 == 3
                && reply[9..12] == request[9..12]
                && reply[8] == 0x43 | (((4 - width) as u8) << 2),
            "expected a complete expedited virtual CoE response for {object:#06x}:{sub:02x}"
        );
        let mut value = [0; 4];
        value[..width].copy_from_slice(&reply[12..12 + width]);
        Ok(u32::from_le_bytes(value))
    }
}

struct Mailbox {
    slot: u8,
    address: u16,
    bytes: usize,
}

struct Mailboxes {
    read: Mailbox,
    write: Mailbox,
}

impl<F: FnMut(&Frame<1>) -> Result<Vec<u8>>> Reader<F> {
    fn discover_mailboxes(&mut self, station: u16) -> Result<Mailboxes> {
        let count = self.read(station, 0x0005, 1)?[0];
        ensure!(
            usize::from(count) <= sync_manager::MAX_CHANNELS,
            "virtual CoE mailbox inventory exceeds 16 SyncManagers"
        );
        let mut channels = [None, None];
        for slot in 0..count {
            let raw = self.read(station, 0x0800 + u16::from(slot) * 8, 8)?;
            if raw[4] & 3 != 2 || raw[6] & 1 == 0 || raw[7] & 1 != 0 {
                continue;
            }
            let direction = (raw[4] >> 2) & 3;
            let address = u16::from_le_bytes([raw[0], raw[1]]);
            let bytes = usize::from(u16::from_le_bytes([raw[2], raw[3]]));
            let channel = channels
                .get_mut(usize::from(direction))
                .context("unsupported virtual CoE mailbox direction")?;
            ensure!(
                channel.is_none()
                    && address >= 0x1000
                    && (16..=1024).contains(&bytes)
                    && usize::from(address) + bytes <= 0x10000,
                "invalid or duplicate virtual CoE mailbox window"
            );
            *channel = Some(Mailbox {
                slot,
                address,
                bytes,
            });
        }
        let [read, write] = channels;
        let read = read.context("missing virtual CoE read mailbox")?;
        let write = write.context("missing virtual CoE write mailbox")?;
        let read_end = usize::from(read.address) + read.bytes;
        let write_end = usize::from(write.address) + write.bytes;
        ensure!(
            read_end <= usize::from(write.address) || write_end <= usize::from(read.address),
            "overlapping virtual CoE mailbox windows"
        );
        Ok(Mailboxes { read, write })
    }
}

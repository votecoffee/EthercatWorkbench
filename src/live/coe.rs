//! Bounded, serialized, read-only CoE uploads after EtherCrab's PDI setup.
use anyhow::{Context, Result, ensure};
use ethercrab::{Command, MainDevice, SubDevice, SubDeviceRef};
use std::{
    ops::Deref,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

const MAX_MAILBOX: usize = 1024;
const OBJECT_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_SEGMENTS: usize = 128;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Mailbox {
    address: u16,
    len: u16,
    sm: u8,
}

pub(super) struct Client {
    read: Mailbox,
    write: Mailbox,
    counter: u8,
    failed: Option<String>,
}

#[derive(Debug)]
struct ServerAbort {
    index: u16,
    sub: u8,
    code: u32,
}
impl std::fmt::Display for ServerAbort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CoE upload aborted at {:#06x}:{:02x}, code {:#010x}",
            self.index, self.sub, self.code
        )
    }
}
impl std::error::Error for ServerAbort {}

struct Upload {
    index: u16,
    sub: u8,
    max: usize,
    exact: Option<usize>,
}

impl Client {
    pub fn same_mailboxes(&self, other: &Self) -> bool {
        self.read == other.read && self.write == other.write
    }
    pub fn write_address(&self) -> u16 {
        self.write.address
    }
    pub fn seed(&mut self, last_counter: u8) {
        self.counter = last_counter;
    }
    pub fn healthy(&self) -> Result<()> {
        ensure!(
            self.failed.is_none(),
            "CoE readback integrity failed: {}",
            self.failed.as_deref().unwrap_or("")
        );
        Ok(())
    }

    pub async fn discover<S: Deref<Target = SubDevice>>(
        sd: &SubDeviceRef<'_, S>,
        stop: &AtomicBool,
    ) -> Result<Self> {
        let count: u8 = sd.register_read(0x0005u16).await?;
        ensure!(count <= 16, "mailbox discovery exceeds 16 SyncManagers");
        let (mut read, mut write) = (None, None);
        let mut process = Vec::new();
        for sm in 0..count {
            super::check_cancel(Some(stop))?;
            let r: [u8; 8] = sd.register_read(0x0800 + u16::from(sm) * 8).await?;
            let address = u16::from_le_bytes([r[0], r[1]]);
            let len = u16::from_le_bytes([r[2], r[3]]);
            if r[6] & 1 == 0 || len == 0 {
                continue;
            }
            let end = usize::from(address) + usize::from(len);
            ensure!(
                address >= 0x1000 && end <= 0x10000,
                "enabled SM range overlaps ESC registers or exceeds memory"
            );
            if r[4] & 3 == 2 {
                ensure!(
                    (16..=MAX_MAILBOX).contains(&usize::from(len)),
                    "mailbox size outside 16–1024 bytes"
                );
                let target = match (r[4] >> 2) & 3 {
                    0 => &mut read,
                    1 => &mut write,
                    _ => anyhow::bail!("unsupported mailbox direction"),
                };
                ensure!(
                    target.is_none(),
                    "multiple mailboxes in one direction are unsupported"
                );
                *target = Some(Mailbox { address, len, sm });
            } else {
                process.push((usize::from(address), end));
            }
        }
        let read = read.context("CoE read mailbox unavailable")?;
        let write = write.context("CoE write mailbox unavailable")?;
        let overlap = |a: Mailbox, start, end| {
            usize::from(a.address) < end && start < usize::from(a.address) + usize::from(a.len)
        };
        ensure!(
            !overlap(
                read,
                usize::from(write.address),
                usize::from(write.address) + usize::from(write.len)
            ),
            "CoE mailboxes overlap"
        );
        ensure!(
            !process
                .iter()
                .any(|&(a, b)| overlap(read, a, b) || overlap(write, a, b)),
            "CoE mailbox overlaps process data"
        );
        Ok(Self {
            read,
            write,
            counter: 0,
            failed: None,
        })
    }

    fn check(&self, stop: &AtomicBool, start: Instant) -> Result<()> {
        super::check_cancel(Some(stop))?;
        ensure!(
            start.elapsed() < OBJECT_TIMEOUT,
            "CoE upload exceeded 500 ms"
        );
        Ok(())
    }

    async fn status<S: Deref<Target = SubDevice>>(
        sd: &SubDeviceRef<'_, S>,
        sm: u8,
    ) -> Result<bool> {
        let value: u8 = sd.register_read(0x0805 + u16::from(sm) * 8).await?;
        Ok(value & 8 != 0)
    }

    async fn exchange<S: Deref<Target = SubDevice>>(
        &mut self,
        sd: &SubDeviceRef<'_, S>,
        main: &MainDevice<'_>,
        stop: &AtomicBool,
        start: Instant,
        command: u8,
        object: (u16, u8),
    ) -> Result<Vec<u8>> {
        let (index, sub) = object;
        self.check(stop, start)?;
        // No other mailbox owner is active after the observed EtherCrab counter handoff.
        ensure!(
            !Self::status(sd, self.read.sm).await?,
            "unexpected pending mailbox response before upload"
        );
        while Self::status(sd, self.write.sm).await? {
            self.check(stop, start)?;
        }
        self.counter = if self.counter >= 7 {
            1
        } else {
            self.counter + 1
        };
        let mut request = [0u8; MAX_MAILBOX];
        request[0] = 10;
        request[5] = 3 | (self.counter << 4);
        request[7] = 0x20;
        request[8] = command;
        if command == 0x40 {
            request[9..11].copy_from_slice(&index.to_le_bytes());
            request[11] = sub;
        }
        Command::fpwr(sd.configured_address(), self.write.address)
            .send(main, &request[..usize::from(self.write.len)])
            .await?;
        while !Self::status(sd, self.read.sm).await? {
            self.check(stop, start)?;
        }
        self.check(stop, start)?;
        let response = Command::fprd(sd.configured_address(), self.read.address)
            .receive_slice(main, self.read.len)
            .await?;
        let declared = usize::from(u16::from_le_bytes([response[0], response[1]]));
        ensure!(
            declared >= 3 && declared + 6 <= usize::from(self.read.len),
            "invalid CoE mailbox declared length"
        );
        let data = response
            .get(..declared + 6)
            .context("truncated CoE mailbox response")?;
        ensure!(
            data[5] & 0x0f == 3 && (data[5] >> 4) & 7 == self.counter,
            "CoE mailbox type or counter mismatch"
        );
        ensure!(
            u16::from_le_bytes([data[6], data[7]]) >> 12 == 3,
            "unexpected CoE service (including emergency)"
        );
        if data[8] == 0x80 {
            ensure!(
                data.len() >= 16 && data[9..11] == index.to_le_bytes() && data[11] == sub,
                "invalid CoE abort identity/length"
            );
            return Err(ServerAbort {
                index,
                sub,
                code: u32::from_le_bytes(data[12..16].try_into().expect("length checked")),
            }
            .into());
        }
        if command == 0x40 {
            ensure!(
                data.len() >= 12
                    && data[8] & 0xe0 == 0x40
                    && data[9..11] == index.to_le_bytes()
                    && data[11] == sub,
                "CoE upload response command or object identity mismatch"
            );
        } else {
            ensure!(
                data[8] & 0xe0 == 0 && data[8] & 0x10 == command & 0x10,
                "CoE segment command or toggle mismatch"
            );
        }
        Ok(data.to_vec())
    }

    async fn upload<S: Deref<Target = SubDevice>>(
        &mut self,
        sd: &SubDeviceRef<'_, S>,
        main: &MainDevice<'_>,
        stop: &AtomicBool,
        target: Upload,
    ) -> Result<Vec<u8>> {
        self.healthy()?;
        let result = self.upload_inner(sd, main, stop, target).await;
        if let Err(error) = &result
            && !error.is::<ServerAbort>()
            && !error.is::<super::SetupCancelled>()
        {
            self.failed = Some(format!("{error:#}"));
        }
        result
    }

    async fn upload_inner<S: Deref<Target = SubDevice>>(
        &mut self,
        sd: &SubDeviceRef<'_, S>,
        main: &MainDevice<'_>,
        stop: &AtomicBool,
        target: Upload,
    ) -> Result<Vec<u8>> {
        let Upload {
            index,
            sub,
            max,
            exact,
        } = target;
        ensure!(
            (1..=4096).contains(&max),
            "CoE object bound outside 1–4096 bytes"
        );
        let start = Instant::now();
        let first = self
            .exchange(sd, main, stop, start, 0x40, (index, sub))
            .await?;
        let command = first[8];
        let mut result;
        if command & 2 != 0 {
            ensure!(first.len() >= 16, "truncated expedited CoE payload");
            let len = if command & 1 != 0 {
                4 - usize::from((command >> 2) & 3)
            } else {
                exact.unwrap_or(4)
            };
            ensure!(
                len <= max && len <= 4,
                "expedited CoE payload exceeds bound"
            );
            result = first[12..12 + len].to_vec();
        } else {
            ensure!(
                command & 1 != 0 && first.len() >= 16,
                "normal/segmented CoE upload needs a declared size"
            );
            let total =
                u32::from_le_bytes(first[12..16].try_into().expect("length checked")) as usize;
            ensure!(
                total <= max && exact.is_none_or(|n| n == total),
                "CoE declared size exceeds or differs from object bound"
            );
            ensure!(
                first.len() - 16 <= total,
                "CoE initial data exceeds declared size"
            );
            result = Vec::with_capacity(total);
            result.extend_from_slice(&first[16..]);
            let mut toggle = false;
            let mut segments = 0;
            while result.len() < total {
                ensure!(segments < MAX_SEGMENTS, "CoE upload exceeds 128 segments");
                segments += 1;
                let part = self
                    .exchange(
                        sd,
                        main,
                        stop,
                        start,
                        0x60 | if toggle { 0x10 } else { 0 },
                        (index, sub),
                    )
                    .await?;
                let last = part[8] & 1 != 0;
                let unused = usize::from((part[8] >> 1) & 7);
                let payload = &part[9..];
                ensure!(
                    payload.len() >= 7 && (payload.len() == 7 || unused == 0),
                    "invalid CoE segment payload size/padding"
                );
                ensure!(last || unused == 0, "unused bytes in non-final CoE segment");
                let len = payload.len() - unused;
                ensure!(
                    len > 0 && result.len() + len <= total,
                    "CoE segment exceeds declared transfer size"
                );
                result.extend_from_slice(&payload[..len]);
                ensure!(
                    last == (result.len() == total),
                    "CoE final segment does not match declared size"
                );
                toggle = !toggle;
            }
        }
        ensure!(
            exact.is_none_or(|n| n == result.len()),
            "CoE payload size differs from requested type"
        );
        Ok(result)
    }

    pub async fn bytes<S: Deref<Target = SubDevice>>(
        &mut self,
        sd: &SubDeviceRef<'_, S>,
        main: &MainDevice<'_>,
        stop: &AtomicBool,
        index: u16,
        sub: u8,
        max: usize,
    ) -> Result<Vec<u8>> {
        self.upload(
            sd,
            main,
            stop,
            Upload {
                index,
                sub,
                max,
                exact: None,
            },
        )
        .await
    }
    pub async fn u8<S: Deref<Target = SubDevice>>(
        &mut self,
        sd: &SubDeviceRef<'_, S>,
        main: &MainDevice<'_>,
        stop: &AtomicBool,
        index: u16,
        sub: u8,
    ) -> Result<u8> {
        Ok(self
            .upload(
                sd,
                main,
                stop,
                Upload {
                    index,
                    sub,
                    max: 1,
                    exact: Some(1),
                },
            )
            .await?[0])
    }
    pub async fn u16<S: Deref<Target = SubDevice>>(
        &mut self,
        sd: &SubDeviceRef<'_, S>,
        main: &MainDevice<'_>,
        stop: &AtomicBool,
        index: u16,
        sub: u8,
    ) -> Result<u16> {
        Ok(u16::from_le_bytes(
            self.upload(
                sd,
                main,
                stop,
                Upload {
                    index,
                    sub,
                    max: 2,
                    exact: Some(2),
                },
            )
            .await?
            .try_into()
            .expect("exact length checked"),
        ))
    }
    pub async fn u32<S: Deref<Target = SubDevice>>(
        &mut self,
        sd: &SubDeviceRef<'_, S>,
        main: &MainDevice<'_>,
        stop: &AtomicBool,
        index: u16,
        sub: u8,
    ) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.upload(
                sd,
                main,
                stop,
                Upload {
                    index,
                    sub,
                    max: 4,
                    exact: Some(4),
                },
            )
            .await?
            .try_into()
            .expect("exact length checked"),
        ))
    }
}

/// Track the last successfully injected mailbox counter without relying on private EtherCrab state.
pub(super) fn outgoing_counter(frame: &[u8], station: u16, address: u16) -> Option<u8> {
    if frame.get(12..14)? != [0x88, 0xa4] {
        return None;
    }
    let end = 16 + usize::from(u16::from_le_bytes(frame.get(14..16)?.try_into().ok()?) & 0x07ff);
    if end > frame.len() {
        return None;
    }
    let mut offset = 16;
    let mut found = None;
    while offset + 12 <= end {
        let header = frame.get(offset..offset + 10)?;
        let len = usize::from(u16::from_le_bytes([header[6], header[7]]) & 0x07ff);
        let data = frame.get(offset + 10..offset + 10 + len)?;
        if offset + 12 + len > end {
            return None;
        }
        if header[0] == 5
            && header[2..4] == station.to_le_bytes()
            && header[4..6] == address.to_le_bytes()
            && data.len() >= 16
            && data[5] & 0x0f == 3
            && (data[5] >> 4) & 7 != 0
            && data[7] & 0xf0 == 0x20
        {
            found = Some((data[5] >> 4) & 7);
        }
        offset += len + 12;
    }
    (offset == end).then_some(found).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Datagram, FPRD, Frame};

    #[test]
    fn counter_handoff_uses_only_complete_matching_mailbox_requests() {
        let mut frame = Frame::new(1, [Datagram::register(FPRD, 0x1000, 0x1200, 16); 2])
            .bytes()
            .to_vec();
        for (offset, counter) in [(16, 1), (44, 7)] {
            frame[offset] = 5; // FPWR, only in this authored test frame.
            frame[offset + 15] = 3 | (counter << 4);
            frame[offset + 17] = 0x20;
        }
        assert_eq!(outgoing_counter(&frame, 0x1000, 0x1200), Some(7));
        assert_eq!(outgoing_counter(&frame, 0x1001, 0x1200), None);
        assert_eq!(outgoing_counter(&frame, 0x1000, 0x1240), None);
        frame[44] = FPRD;
        assert_eq!(outgoing_counter(&frame, 0x1000, 0x1200), Some(1));
        frame[31] = 3; // Counter zero is not a valid sequence handoff.
        assert_eq!(outgoing_counter(&frame, 0x1000, 0x1200), None);
        frame[31] = 0x13;
        frame[33] = 0x30; // A response is not an outgoing CoE request.
        assert_eq!(outgoing_counter(&frame, 0x1000, 0x1200), None);
        assert_eq!(outgoing_counter(&frame[..40], 0x1000, 0x1200), None);
    }
}

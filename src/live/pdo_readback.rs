use crate::{
    pdo::{Layout, MappingSource, Pdo, Readback, SyncManager},
    sii::{MAX_CATEGORIES_BYTES, SiiPdos},
};
use anyhow::{Context, Result, ensure};
use ethercrab::{MainDevice, SubDevice, SubDeviceRef};
use std::{
    ops::Deref,
    sync::atomic::{AtomicBool, Ordering::Relaxed},
    time::{Duration, Instant},
};

const BUDGET: Duration = Duration::from_secs(10);
const MAX_ENTRIES: usize = 1024;

#[derive(Clone, Copy)]
struct Channel {
    index: u8,
    tx: bool,
    bytes: usize,
}

pub async fn readback<S: Deref<Target = SubDevice>>(
    sd: &SubDeviceRef<'_, S>,
    main: &MainDevice<'_>,
    mut coe: Option<&mut super::coe::Client>,
    stop: &AtomicBool,
) -> Readback {
    let started = Instant::now();
    let channels = channels(sd, stop, started).await;
    let channels = match channels {
        Ok(channels) => channels,
        Err(error) => {
            return Readback {
                tx: None,
                rx: None,
                tx_unavailable: Some(format!("{error:#}")),
                rx_unavailable: Some(format!("{error:#}")),
            };
        }
    };
    if coe.is_none() {
        return match sii_categories(sd, main, stop, started)
            .await
            .and_then(|bytes| SiiPdos::parse(&bytes))
        {
            Ok(sii) => {
                let configured = |tx| {
                    channels
                        .iter()
                        .filter(|c| c.tx == tx)
                        .map(|c| (c.index, c.bytes))
                        .collect::<Vec<_>>()
                };
                Readback {
                    tx: Some(sii.layout(true, &configured(true))),
                    rx: Some(sii.layout(false, &configured(false))),
                    tx_unavailable: None,
                    rx_unavailable: None,
                }
            }
            Err(error) => unavailable(format!("SII PDO readback: {error:#}")),
        };
    }
    let tx = layout(
        sd,
        main,
        coe.as_deref_mut().expect("CoE client"),
        &channels,
        true,
        stop,
        started,
    )
    .await;
    let rx = layout(
        sd,
        main,
        coe.as_mut().expect("CoE client"),
        &channels,
        false,
        stop,
        started,
    )
    .await;
    Readback {
        tx_unavailable: tx.as_ref().err().map(|error| format!("{error:#}")),
        rx_unavailable: rx.as_ref().err().map(|error| format!("{error:#}")),
        tx: tx.ok(),
        rx: rx.ok(),
    }
}

fn check(stop: &AtomicBool, start: Instant) -> Result<()> {
    ensure!(!stop.load(Relaxed), "PDO readback cancelled");
    ensure!(start.elapsed() < BUDGET, "PDO readback exceeded 10 seconds");
    Ok(())
}

async fn channels<S: Deref<Target = SubDevice>>(
    sd: &SubDeviceRef<'_, S>,
    stop: &AtomicBool,
    start: Instant,
) -> Result<Vec<Channel>> {
    check(stop, start)?;
    let count: u8 = sd
        .register_read(0x0005u16)
        .await
        .context("read ESC SyncManager count")?;
    ensure!(count <= 16, "ESC reports {count} SyncManagers, limit is 16");
    let mut channels = Vec::new();
    for index in 0..count {
        check(stop, start)?;
        let registers: [u8; 8] = sd.register_read(0x0800 + u16::from(index) * 8).await?;
        let bytes = usize::from(u16::from_le_bytes([registers[2], registers[3]]));
        // Control bits 1..0 select normal buffered mode. Mailbox channels are excluded.
        if registers[4] & 3 != 0 || registers[6] & 1 == 0 || bytes == 0 {
            continue;
        }
        let direction = (registers[4] >> 2) & 3;
        ensure!(
            direction <= 1,
            "SM{index} has an unsupported process direction"
        );
        channels.push(Channel {
            index,
            tx: direction == 0,
            bytes,
        });
    }
    Ok(channels)
}

async fn layout<S: Deref<Target = SubDevice>>(
    sd: &SubDeviceRef<'_, S>,
    main: &MainDevice<'_>,
    coe: &mut super::coe::Client,
    channels: &[Channel],
    tx: bool,
    stop: &AtomicBool,
    start: Instant,
) -> Result<Layout> {
    let mut sync_managers = Vec::new();
    let mut total_entries = 0;
    for channel in channels.iter().filter(|channel| channel.tx == tx) {
        let assignment = 0x1c10 + u16::from(channel.index);
        check(stop, start)?;
        let count: u8 = coe
            .u8(sd, main, stop, assignment, 0)
            .await
            .with_context(|| format!("read CoE {assignment:#06x}:00"))?;
        let mut pdos = Vec::new();
        for sub in 1..=count {
            check(stop, start)?;
            let index: u16 = coe.u16(sd, main, stop, assignment, sub).await?;
            check(stop, start)?;
            let count: u8 = coe.u8(sd, main, stop, index, 0).await?;
            total_entries += usize::from(count);
            ensure!(
                total_entries <= MAX_ENTRIES,
                "CoE mapping exceeds {MAX_ENTRIES} entries"
            );
            let mut entries = Vec::with_capacity(usize::from(count));
            for sub in 1..=count {
                check(stop, start)?;
                let entry: u32 = coe.u32(sd, main, stop, index, sub).await?;
                entries.push(entry);
            }
            pdos.push(Pdo { index, entries });
        }
        sync_managers.push(SyncManager {
            index: channel.index,
            configured_bytes: Some(channel.bytes),
            pdos,
        });
    }
    let layout = Layout {
        mapping_source: MappingSource::Coe,
        sync_managers,
    };
    Ok(layout)
}

fn unavailable(reason: String) -> Readback {
    Readback {
        tx: None,
        rx: None,
        tx_unavailable: Some(reason.clone()),
        rx_unavailable: Some(reason),
    }
}

async fn sii_categories<S: Deref<Target = SubDevice>>(
    sd: &SubDeviceRef<'_, S>,
    main: &MainDevice<'_>,
    stop: &AtomicBool,
    started: Instant,
) -> Result<Vec<u8>> {
    let mut word_address = 0x0040u16;
    let mut bytes = Vec::new();
    loop {
        check(stop, started)?;
        let header: [u8; 4] = sd.eeprom_read(main, word_address).await?;
        ensure!(
            bytes.len() + 4 <= MAX_CATEGORIES_BYTES,
            "SII categories exceed 16 KiB"
        );
        bytes.extend_from_slice(&header);
        if header[..2] == [0xff, 0xff] {
            return Ok(bytes);
        }
        let words = u16::from_le_bytes([header[2], header[3]]);
        let length = usize::from(words) * 2;
        ensure!(
            bytes.len() + length <= MAX_CATEGORIES_BYTES,
            "SII categories exceed 16 KiB"
        );
        word_address = word_address
            .checked_add(2)
            .context("SII category address overflow")?;
        for offset in (0..length).step_by(4) {
            check(stop, started)?;
            let address = word_address
                .checked_add((offset / 2) as u16)
                .context("SII category address overflow")?;
            let chunk: [u8; 4] = sd.eeprom_read(main, address).await?;
            bytes.extend_from_slice(&chunk[..(length - offset).min(4)]);
        }
        word_address = word_address
            .checked_add(words)
            .context("SII category address overflow")?;
    }
}

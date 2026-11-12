use crate::pdo::{Layout, Pdo, Readback, SyncManager};
use anyhow::{Context, Result, ensure};
use ethercrab::{SubDevice, SubDeviceRef};
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
    let tx = layout(sd, &channels, true, stop, started).await;
    let rx = layout(sd, &channels, false, stop, started).await;
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
        let count: u8 = sd
            .sdo_read(assignment, 0u8)
            .await
            .with_context(|| format!("read CoE {assignment:#06x}:00"))?;
        let mut pdos = Vec::new();
        for sub in 1..=count {
            check(stop, start)?;
            let index: u16 = sd.sdo_read(assignment, sub).await?;
            check(stop, start)?;
            let count: u8 = sd.sdo_read(index, 0u8).await?;
            total_entries += usize::from(count);
            ensure!(
                total_entries <= MAX_ENTRIES,
                "CoE mapping exceeds {MAX_ENTRIES} entries"
            );
            let mut entries = Vec::with_capacity(usize::from(count));
            for sub in 1..=count {
                check(stop, start)?;
                let entry: u32 = sd.sdo_read(index, sub).await?;
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
    let layout = Layout { sync_managers };
    Ok(layout)
}

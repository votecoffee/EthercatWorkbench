//! Collect fixed-slot inventory through the bounded CoE client on the in-memory transport.
use super::{
    AL_STATUS, PacketIo, Transport, coe::Client, ethercat_now, request_init, setup_timeouts,
};
use crate::{
    esi::modular_preview::inventory::{CONFIGURED, DETECTED, Object, Snapshot, Source, Upload},
    model::Identity,
    virtual_esc::{VirtualStats, VirtualWire},
};
use anyhow::{Context, Result, ensure};
use ethercrab::{Command, MainDevice, MainDeviceConfig, PduStorage, SubDevice, SubDeviceRef};
use serde::Serialize;
use std::{ops::Deref, sync::atomic::AtomicBool};

pub use crate::virtual_esc::ModuleInventoryCase;

#[derive(Serialize)]
pub struct Report {
    scenario: ModuleInventoryCase,
    pub inventory: Snapshot,
    preop_al: (u16, u16),
    stopped_al: (u16, u16),
    audit: VirtualStats,
}

pub fn read(scenario: ModuleInventoryCase) -> Result<Report> {
    let mut port = Transport {
        io: PacketIo::Virtual(Box::new(VirtualWire::for_module_inventory(scenario))),
        seq: 0,
        ignored_frames: 0,
        mailbox_watch: None,
        mailbox_counter: None,
    };
    let storage = PduStorage::<8, { PduStorage::element_size(1400) }>::new();
    let (mut tx, mut rx, pdu) = storage
        .try_split()
        .map_err(|_| anyhow::anyhow!("PDU storage in use"))?;
    let main = MainDevice::new(
        pdu,
        setup_timeouts(true),
        MainDeviceConfig {
            dc_static_sync_iterations: 0,
            ..MainDeviceConfig::default()
        },
    );
    let stop = AtomicBool::new(false);
    let result = (|| {
        let group = port
            .drive(
                &mut tx,
                &mut rx,
                Some(&stop),
                main.init_single_group::<2, 16>(ethercat_now),
            )
            .context("initialize virtual SubDevice in PREOP")?;
        ensure!(group.len() == 1, "expected one virtual SubDevice");
        let device = group.subdevice(&main, 0)?;
        let identity = device.identity();
        let station = device.configured_address();
        port.drive(&mut tx, &mut rx, Some(&stop), async {
            let [status, _, code] = Command::fprd(station, AL_STATUS)
                .receive::<[u16; 3]>(&main)
                .await?;
            ensure!(
                status & 0x1f == 2 && code == 0,
                "module upload requires clean PREOP: AL {status:#06x}, code {code:#06x}"
            );
            let mut client = Client::discover(&device, &stop).await?;
            // EtherCrab's mailbox-only PREOP setup has not started any CoE transaction.
            let configured = upload_list(&mut client, &device, &main, &stop, CONFIGURED).await;
            let detected = upload_list(&mut client, &device, &main, &stop, DETECTED).await;
            Ok::<_, anyhow::Error>((
                Snapshot {
                    schema: 1,
                    identity: Identity {
                        vendor: identity.vendor_id,
                        product: identity.product_id,
                        revision: identity.revision,
                    },
                    serial: Some(identity.serial),
                    source: Some(Source::VirtualCoe),
                    objects: vec![configured, detected],
                },
                (status, code),
            ))
        })
    })();
    let cleanup = request_init(&mut port, &mut tx, &mut rx, &main);
    let ((inventory, preop_al), stopped_al) = match (result, cleanup) {
        (Ok(result), Ok(stopped_al)) => (result, stopped_al),
        (Err(error), Err(cleanup)) => {
            return Err(error.context(format!("virtual INIT cleanup also failed: {cleanup:#}")));
        }
        (Err(error), _) | (_, Err(error)) => return Err(error),
    };
    let PacketIo::Virtual(wire) = &port.io else {
        unreachable!("virtual module inventory transport")
    };
    Ok(Report {
        scenario,
        inventory,
        preop_al,
        stopped_al,
        audit: wire.stats(),
    })
}

async fn upload_list<S: Deref<Target = SubDevice>>(
    client: &mut Client,
    device: &SubDeviceRef<'_, S>,
    main: &MainDevice<'_>,
    stop: &AtomicBool,
    index: u16,
) -> Object {
    let result = async {
        let count = client.u8(device, main, stop, index, 0).await?;
        let mut uploads = Vec::with_capacity(usize::from(count) + 1);
        uploads.push(Upload {
            subindex: 0,
            data_hex: hex::encode([count]),
        });
        for subindex in 1..=count {
            let value = client.u32(device, main, stop, index, subindex).await?;
            uploads.push(Upload {
                subindex,
                data_hex: hex::encode(value.to_le_bytes()),
            });
        }
        Ok::<_, anyhow::Error>(uploads)
    }
    .await;
    let (uploads, unavailable) = match result {
        Ok(uploads) => (uploads, None),
        Err(error) => (Vec::new(), Some(format!("{error:#}"))),
    };
    Object {
        index,
        uploads,
        unavailable,
    }
}

mod pdo_readback;

use crate::wire::{APRD, BRD, Datagram, ETHERCRAB_REPLY, Frame, input_datagrams, input_reply};
use crate::{
    model::{Identity, MAX_PAYLOAD, Profile},
    run::{BenchApproval, Bus, DeviceInfo, Exchange, Report, Snapshot},
};
use anyhow::{Context, Result, bail, ensure};
use ethercrab::{Command, MainDevice, MainDeviceConfig, PduRx, PduStorage, PduTx, Timeouts};
use pcap::{Active, Capture, Device, Linktype};
use serde::Serialize;
use std::{
    future::Future,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering::Relaxed},
    },
    task::{Context as PollContext, Poll, Waker},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{
    System::LibraryLoader::{
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
    },
    System::SystemInformation::GetSystemDirectoryW,
};

const AL_CONTROL: u16 = 0x0120;
const AL_STATUS: u16 = 0x0130;
const MAX_DISCOVERY: u16 = 16;
const SETUP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Serialize)]
pub struct Nic {
    pub id: String,
    pub description: String,
}

fn ensure_npcap() -> Result<()> {
    static LOADED: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    let loaded = LOADED.get_or_init(|| {
        let mut buffer = [0u16; 260];
        // SAFETY: buffer is writable for its declared length.
        let len = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
        if len == 0 || len >= buffer.len() {
            return Err("could not resolve the Windows system directory".into());
        }
        let path = PathBuf::from(std::ffi::OsString::from_wide(&buffer[..len]))
            .join("Npcap")
            .join("wpcap.dll");
        let wide: Vec<_> = path.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: wide is NUL-terminated. Only the installed Npcap directory and System32
        // are eligible for dependency loading. Keep this reference for MSVC delay imports.
        let handle = unsafe {
            LoadLibraryExW(
                wide.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if handle.is_null() {
            return Err(format!(
                "load {}: {}. Install current x64 Npcap separately.",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    });
    loaded
        .as_ref()
        .map_err(|message| anyhow::anyhow!("{message}"))
        .copied()
}

fn devices() -> Result<Vec<Device>> {
    ensure_npcap()?;
    Ok(Device::list()
        .context("list Npcap adapters")?
        .into_iter()
        .filter(|device| {
            device.name.starts_with(r"\Device\NPF_{")
                && device.name.ends_with('}')
                && !device.flags.is_loopback()
        })
        .collect())
}

pub fn nics() -> Result<Vec<Nic>> {
    Ok(devices()?
        .into_iter()
        .map(|device| Nic {
            id: device.name,
            description: device.desc.unwrap_or_default(),
        })
        .collect())
}

struct Transport {
    io: PacketIo,
    seq: u8,
    ignored_frames: u64,
}

impl Transport {
    fn open(nic: &str) -> Result<Self> {
        ensure!(!nic.is_empty(), "select an explicit isolated bench NIC");
        let device = devices()?
            .into_iter()
            .find(|dev| dev.name.eq_ignore_ascii_case(nic))
            .context("selected NIC is absent from Npcap")?;
        let mut cap = Capture::from_device(device)?
            .promisc(true)
            .snaplen(1518)
            .immediate_mode(true)
            .open()
            .context("open Npcap adapter; check driver access policy")?
            .setnonblock()?;
        ensure!(
            cap.get_datalink() == Linktype::ETHERNET,
            "NIC must expose Ethernet II frames"
        );
        cap.filter("ether proto 0x88a4", true)?;
        Ok(Self {
            io: PacketIo::Nic(cap),
            seq: 0,
            ignored_frames: 0,
        })
    }

    fn read<const N: usize, T>(
        &mut self,
        datagrams: [Datagram; N],
        timeout: Duration,
        parse: impl FnOnce([(&[u8], u16); N], Instant) -> T,
    ) -> Result<(Instant, Option<T>)> {
        self.seq = self.seq.wrapping_add(1);
        let frame = Frame::new(self.seq, datagrams);
        let sent = Instant::now();
        self.io
            .send(frame.bytes())
            .context("inject EtherCAT read frame")?;
        while sent.elapsed() < timeout {
            match self.io.receive()? {
                Some(packet) => {
                    let received = Instant::now();
                    if let Some(data) = frame.reply(packet) {
                        return Ok((sent, Some(parse(data, received))));
                    }
                    self.ignored_frames += 1;
                }
                None => std::hint::spin_loop(),
            }
        }
        Ok((sent, None))
    }

    fn scan(&mut self) -> Result<Vec<DeviceInfo>> {
        let (_, count) = self.read(
            [Datagram::register(BRD, 0, 0x0000, 2)],
            Duration::from_millis(30),
            |[(_, wkc)], _| wkc,
        )?;
        let count = count.context("no EtherCAT broadcast response on the selected NIC")?;
        ensure!(
            count > 0 && count <= MAX_DISCOVERY,
            "unexpected SubDevice count {count} (scan limit {MAX_DISCOVERY})"
        );
        (0..count)
            .map(|position| {
                let address = 0u16.wrapping_sub(position);
                let (_, info) = self.read(
                    [
                        Datagram::register(APRD, address, 0x0010, 4),
                        Datagram::register(APRD, address, 0x0110, 2),
                        Datagram::register(APRD, address, AL_STATUS, 6),
                    ],
                    Duration::from_millis(30),
                    |[(addresses, a), (links, b), (al, c)], _| {
                        (a == 1 && b == 1 && c == 1).then(|| DeviceInfo {
                            position,
                            station_address: word(addresses),
                            alias: word(&addresses[2..]),
                            link_ports: std::array::from_fn(|port| {
                                links[0] & (1 << (port + 4)) != 0
                            }),
                            al_status: word(al),
                            al_code: word(&al[4..]),
                            ..DeviceInfo::default()
                        })
                    },
                )?;
                info.flatten().with_context(|| {
                    format!("missing or ambiguous register response at bus position {position}")
                })
            })
            .collect()
    }

    // Drive EtherCrab's PDU storage on the same OS thread that owns Npcap.
    // Setup/teardown futures use EtherCrab's own timeout and retry policy.
    fn drive<T, E: Into<anyhow::Error>>(
        &mut self,
        tx: &mut PduTx<'_>,
        rx: &mut PduRx<'_>,
        future: impl Future<Output = Result<T, E>>,
    ) -> Result<T> {
        let mut future = std::pin::pin!(future);
        let mut cx = PollContext::from_waker(Waker::noop());
        let start = Instant::now();
        loop {
            if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
                return result.map_err(Into::into);
            }
            ensure!(
                start.elapsed() < SETUP_TIMEOUT,
                "EtherCrab setup or teardown exceeded its time budget"
            );
            while let Some(frame) = tx.next_sendable_frame() {
                let mut inject_error = None;
                let sent = frame.send_blocking(|bytes| match self.io.send(bytes) {
                    Ok(()) => Ok(bytes.len()),
                    Err(error) => {
                        inject_error = Some(error);
                        Err(ethercrab::error::Error::Internal)
                    }
                });
                if let Some(error) = inject_error {
                    return Err(error).context("inject EtherCrab setup frame");
                }
                sent?;
            }
            for _ in 0..64 {
                match self.io.receive()? {
                    Some(packet) if packet.get(6..12) == Some(&ETHERCRAB_REPLY) => {
                        // Delayed or duplicate replies can target an expired PDU slot.
                        // The pending command's own WKC and timeout still determine success.
                        let _ = rx.receive_frame(packet);
                    }
                    Some(_) => {}
                    None => break,
                }
            }
            std::thread::yield_now();
        }
    }
}

fn word(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

pub fn scan(nic: &str) -> Result<Vec<DeviceInfo>> {
    Transport::open(nic)?.scan()
}

fn ethercat_now() -> u64 {
    const EPOCH_NS: u64 = 946_684_800_000_000_000;
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64)
        .saturating_sub(EPOCH_NS)
}

pub fn safeop(
    profile: &Profile,
    _approved: &BenchApproval,
    stop: &AtomicBool,
    view: &Mutex<Snapshot>,
    report: &mut Report,
    run: impl FnOnce(LiveBus<'_, '_>, &mut Report) -> Result<()>,
) -> Result<()> {
    ensure!(
        profile.expected_identity.is_some(),
        "live profile needs exact vendor, product and revision"
    );
    let mut port = Transport::open(&profile.nic)?;
    safeop_on(profile, stop, view, report, &mut port, run)
}

pub fn virtual_safeop(
    profile: &Profile,
    model: crate::virtual_esc::VirtualModel,
    fault: crate::virtual_esc::VirtualFault,
    stop: &AtomicBool,
    view: &Mutex<Snapshot>,
    report: &mut Report,
    run: impl FnOnce(LiveBus<'_, '_>, &mut Report) -> Result<()>,
) -> Result<()> {
    let mut port = Transport {
        io: PacketIo::Virtual(Box::new(crate::virtual_esc::VirtualEsc::new(model, fault))),
        seq: 0,
        ignored_frames: 0,
    };
    let result = safeop_on(profile, stop, view, report, &mut port, run);
    if let PacketIo::Virtual(esc) = &port.io {
        report.virtual_esc = Some(esc.stats());
    }
    result
}

fn safeop_on(
    profile: &Profile,
    stop: &AtomicBool,
    view: &Mutex<Snapshot>,
    report: &mut Report,
    port: &mut Transport,
    run: impl FnOnce(LiveBus<'_, '_>, &mut Report) -> Result<()>,
) -> Result<()> {
    let expected = profile
        .expected_identity
        .as_ref()
        .context("live profile needs exact vendor, product and revision")?;
    report.devices = port.scan()?;
    ensure!(
        report.devices.len() == 1,
        "SAFEOP setup requires exactly one isolated SubDevice"
    );
    ensure!(
        matches!(report.devices[0].al_status & 0xf, 1 | 2 | 4),
        "SubDevice must start in INIT, PREOP, or SAFEOP"
    );
    if stop.load(Relaxed) {
        return Ok(());
    }
    if let Ok(mut snapshot) = view.try_lock() {
        snapshot.phase = "Approved ESC setup".into();
        snapshot.report.clone_from(report);
    }
    let storage = PduStorage::<8, { PduStorage::element_size(1400) }>::new();
    let (mut tx, mut rx, pdu) = storage
        .try_split()
        .map_err(|_| anyhow::anyhow!("PDU storage in use"))?;
    let main = MainDevice::new(
        pdu,
        Timeouts {
            pdu: Duration::from_millis(15),
            wait_loop_delay: Duration::ZERO,
            ..Timeouts::default()
        },
        MainDeviceConfig {
            dc_static_sync_iterations: 0,
            ..MainDeviceConfig::default()
        },
    );

    let setup = (|| {
        let group = port
            .drive(
                &mut tx,
                &mut rx,
                main.init_single_group::<2, { MAX_PAYLOAD * 2 }>(ethercat_now),
            )
            .context("EtherCrab INIT/PREOP setup")?;
        ensure!(group.len() == 1, "bus topology changed during setup");
        let sd = group.subdevice(&main, 0)?;
        let identity = sd.identity();
        let observed = Identity {
            vendor: identity.vendor_id,
            product: identity.product_id,
            revision: identity.revision,
        };
        let info = &mut report.devices[0];
        info.name = Some(sd.name().into());
        info.serial = Some(identity.serial);
        info.identity = Some(observed.clone());
        info.station_address = sd.configured_address();
        info.dc_support = Some(format!("{:?}", sd.dc_support()));
        ensure!(
            &observed == expected,
            "bus identity {observed} differs from profile {expected}"
        );

        let mut sync_modes = Vec::new();
        for (size, index, direction) in [
            (profile.tx_bytes, 0x1c33, "TxPDO"),
            (profile.rx_bytes, 0x1c32, "RxPDO"),
        ] {
            if size == 0 {
                continue;
            }
            let mode = port.drive(&mut tx, &mut rx, sd.sdo_read::<u16>(index, 1u8));
            sync_modes.push(match mode {
                Ok(mode) => format!("{direction} CoE {index:#06x}:01 = {mode:#06x}"),
                Err(_) => format!("{direction} CoE sync type unavailable"),
            });
        }
        report.device_sync = sync_modes.join(" / ");
        report.dc_sync = "SYNC0/SYNC1 disabled. EtherCrab initial clock setup if supported".into();

        ensure!(!stop.load(Relaxed), "cancelled during ESC setup");
        let group = port
            .drive(&mut tx, &mut rx, group.into_pre_op_pdi(&main))
            .context("configure FMMU/SyncManagers from discovered device mapping")?;
        let sd = group.subdevice(&main, 0)?;
        let station = sd.configured_address();
        let (input, output) = {
            let io = sd.io_raw();
            (io.inputs().len(), io.outputs().len())
        };
        let info = &mut report.devices[0];
        info.tx_bytes = Some(input);
        info.rx_bytes = Some(output);
        ensure!(
            input == profile.tx_bytes && output == profile.rx_bytes,
            "bus PDO lengths Tx {input} / Rx {output} differ from profile Tx {} / Rx {}",
            profile.tx_bytes,
            profile.rx_bytes
        );
        if let Ok(mut snapshot) = view.try_lock() {
            snapshot.phase = "Checking device PDO assignments".into();
            snapshot.report.clone_from(report);
        }
        let protocols = port.drive(&mut tx, &mut rx, sd.eeprom_read::<u16>(&main, 0x001c))?;
        let coe = protocols & 0x0004 != 0;
        if !coe {
            report.device_sync = "Device sync type unavailable (CoE absent)".into();
        }
        let readback = port.drive(&mut tx, &mut rx, async {
            Ok::<_, anyhow::Error>(pdo_readback::readback(&sd, &main, coe, stop).await)
        })?;
        let source = match (&port.io, coe) {
            (PacketIo::Nic(_), false) => "Bus SII PDO descriptors",
            (PacketIo::Virtual(_), false) => "Virtual ESC SII PDO descriptors",
            _ => port.io.source(),
        };
        report.pdo_verification = Some(Arc::new(readback.verify(profile, source)));
        let verified = report.pdo_verification.as_ref().expect("readback set");
        ensure!(
            verified.compatible(),
            "device PDO layout differs from profile: {}",
            verified
                .tx
                .errors
                .iter()
                .chain(&verified.rx.errors)
                .cloned()
                .collect::<Vec<_>>()
                .join(" / ")
        );
        ensure!(!stop.load(Relaxed), "cancelled during PDO readback");
        let _group = port
            .drive(&mut tx, &mut rx, group.into_safe_op(&main))
            .context("request SAFEOP")?;
        let al = port.drive(
            &mut tx,
            &mut rx,
            Command::fprd(station, AL_STATUS).receive::<[u16; 3]>(&main),
        )?;
        if let Some(device) = report.devices.first_mut() {
            device.al_status = al[0];
            device.al_code = al[2];
        }
        ensure!(
            al[0] & 0x1f == 4 && al[2] == 0,
            "SAFEOP confirmation failed, AL {:#06x} code {:#06x}",
            al[0],
            al[2]
        );
        let dc = port.drive(
            &mut tx,
            &mut rx,
            Command::fprd(station, 0x0981).receive::<u8>(&main),
        );
        if let Ok(activation) = dc {
            let cycles = port.drive(
                &mut tx,
                &mut rx,
                Command::fprd(station, 0x09a0).receive::<[u32; 2]>(&main),
            );
            report
                .dc_sync
                .push_str(&format!(". ESC activation {activation:#04x}"));
            if let Ok([sync0, sync1]) = cycles {
                report.dc_sync.push_str(&format!(
                    ", cycle registers SYNC0 {sync0} ns / SYNC1 {sync1} ns"
                ));
            }
        }
        Ok(station)
    })();

    match setup {
        Ok(station) => {
            report.expected_wkc = 1;
            run(
                LiveBus {
                    port,
                    tx: &mut tx,
                    rx: &mut rx,
                    main: &main,
                    station,
                    input: profile.tx_bytes,
                    timeout: Duration::from_micros(
                        (profile.requested_cycle_us * 2).clamp(2_000, 20_000),
                    ),
                },
                report,
            )
        }
        Err(error) => {
            if let Ok(al) = port.drive(
                &mut tx,
                &mut rx,
                Command::aprd(0, AL_STATUS).receive::<[u16; 3]>(&main),
            ) {
                report.setup_failure_al = Some((al[0], al[2]));
                if let Some(device) = report.devices.first_mut() {
                    device.al_status = al[0];
                    device.al_code = al[2];
                }
            }
            match request_init(port, &mut tx, &mut rx, &main) {
                Ok(al) => {
                    report.stopped_al = Some(al);
                    Err(error)
                }
                Err(cleanup) => {
                    Err(error.context(format!("INIT cleanup also failed: {cleanup:#}")))
                }
            }
        }
    }
}

fn request_init<'a>(
    port: &mut Transport,
    tx: &mut PduTx<'a>,
    rx: &mut PduRx<'a>,
    main: &MainDevice<'a>,
) -> Result<(u16, u16)> {
    port.drive(tx, rx, Command::apwr(0, AL_CONTROL).send(main, 0x0011u16))
        .context("request INIT on stop")?;
    let start = Instant::now();
    let mut last_al = None;
    while start.elapsed() < Duration::from_secs(2) {
        let al = port.drive(
            tx,
            rx,
            Command::aprd(0, AL_STATUS).receive::<[u16; 3]>(main),
        )?;
        last_al = Some((al[0], al[2]));
        if al[0] & 0x1f == 1 && al[2] == 0 {
            return Ok((al[0], al[2]));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let (status, code) = last_al.context("no AL response while confirming INIT cleanup")?;
    bail!(
        "SubDevice did not confirm error-free INIT during cleanup, AL {status:#06x} code {code:#06x}"
    )
}

pub struct LiveBus<'a, 's> {
    port: &'a mut Transport,
    tx: &'a mut PduTx<'s>,
    rx: &'a mut PduRx<'s>,
    main: &'a MainDevice<'s>,
    station: u16,
    input: usize,
    timeout: Duration,
}

impl Bus for LiveBus<'_, '_> {
    fn exchange(&mut self, _cycle: u64) -> Result<Option<Exchange>> {
        let before = self.port.ignored_frames;
        // The first group's input FMMUs start at logical zero.
        let (sent, reply) = self.port.read(
            input_datagrams(self.station, self.input),
            self.timeout,
            |parts, received| (input_reply(parts), received),
        )?;
        let ignored_frames = self.port.ignored_frames - before;
        let (received, wkc, status, data) = match reply {
            Some((input, at)) => (Some(at), input.wkc, input.status, input.data),
            None => (None, 0, None, [0; MAX_PAYLOAD]),
        };
        Ok(Some(Exchange {
            sent,
            received,
            wkc,
            status,
            data,
            ignored_frames,
        }))
    }

    fn stop(&mut self) -> Result<Option<(u16, u16)>> {
        request_init(self.port, self.tx, self.rx, self.main).map(Some)
    }
}

enum PacketIo {
    Nic(Capture<Active>),
    Virtual(Box<crate::virtual_esc::VirtualEsc>),
}

impl PacketIo {
    fn source(&self) -> &str {
        match self {
            Self::Nic(_) => "Bus CoE assignment reads",
            Self::Virtual(_) => "Virtual ESC CoE assignment reads",
        }
    }

    fn send(&mut self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Nic(cap) => cap
                .sendpacket(bytes)
                .context("inject EtherCAT frame through Npcap"),
            Self::Virtual(esc) => esc.send(bytes),
        }
    }

    fn receive(&mut self) -> Result<Option<&[u8]>> {
        match self {
            Self::Nic(cap) => match cap.next_packet() {
                Ok(packet) => Ok(Some(packet.data)),
                Err(pcap::Error::NoMorePackets | pcap::Error::TimeoutExpired) => Ok(None),
                Err(error) => Err(error).context("receive EtherCAT frame through Npcap"),
            },
            Self::Virtual(esc) => Ok(esc.receive()),
        }
    }
}

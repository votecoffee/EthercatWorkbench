//! Snapshot-only ESC diagnostics. No register writes or topology reconstruction.
use crate::sync::RegisterRead;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read, path::Path};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Bus,
    VirtualEsc,
    Authored,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema: u32,
    pub source: Source,
    pub started_utc: String,
    pub elapsed_us: u64,
    pub position: u16,
    pub station_address: u16,
    pub alias: u16,
    pub dl_status: u16,
    pub al_status: u16,
    pub al_code: u16,
    /// Raw 0x0000..0x000F, when implemented and read with WKC 1.
    pub information: RegisterRead<[u8; 16]>,
    /// Raw 0x0300..0x0313; no counters are reset.
    pub counters: RegisterRead<[u8; 20]>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AlStatus {
    pub raw: u16,
    pub state: &'static str,
    pub error: bool,
    pub uninterpreted_flags: u16,
    pub code: u16,
    pub description: &'static str,
}
pub fn al_status(raw: u16, code: u16) -> AlStatus {
    let state = match raw & 0x0f {
        1 => "INIT",
        2 => "PREOP",
        3 => "BOOT",
        4 => "SAFEOP",
        8 => "OP",
        _ => "Unknown state",
    };
    let description = match code {
        0x0000 => "No reported AL error",
        0x0001 => "Unspecified error",
        0x0002 => "Memory unavailable",
        0x0003 => "Device setup invalid",
        0x0011 => "Requested state transition rejected",
        0x0012 => "Requested state unknown",
        0x0013 => "Bootstrap unsupported",
        0x0014 => "Firmware unavailable",
        0x0015 | 0x0016 => "Mailbox configuration invalid",
        0x0017 => "SyncManager configuration invalid",
        0x0018 => "Valid inputs unavailable",
        0x0019 => "Valid outputs unavailable",
        0x001a => "Synchronization error",
        0x001b => "SyncManager watchdog",
        0x001c => "SyncManager types invalid",
        0x001d => "Output configuration invalid",
        0x001e => "Input configuration invalid",
        0x001f => "Watchdog configuration invalid",
        0x0020 => "Cold start required",
        0x0021 => "INIT required",
        0x0022 => "PREOP required",
        0x0023 => "SAFEOP required",
        0x0024 => "Input mapping invalid",
        0x0025 => "Output mapping invalid",
        0x0026 => "Settings inconsistent",
        0x0027 => "FreeRun unsupported",
        0x0028 => "SyncMode unsupported",
        0x0029 => "FreeRun needs three-buffer mode",
        0x002a => "Background watchdog",
        0x002b => "Valid inputs and outputs unavailable",
        0x002c => "Fatal synchronization error",
        0x002d => "No synchronization error",
        0x0030 => "DC SYNC configuration invalid",
        0x0031 => "DC latch configuration invalid",
        0x0032 => "PLL error",
        0x0033 => "DC SYNC I/O error",
        0x0034 => "DC SYNC timeout",
        0x0035 => "DC cycle invalid",
        0x0036 => "SYNC0 cycle invalid",
        0x0037 => "SYNC1 cycle invalid",
        0x0043 => "CoE mailbox error",
        0x0050 => "EEPROM inaccessible",
        0x0051 => "EEPROM error",
        0x0060 => "Device restarted locally",
        0x0061 => "Device identification updated",
        0x8000..=0xffff => "Vendor-specific AL code",
        _ => "Unmapped or reserved AL code",
    };
    AlStatus {
        raw,
        state,
        error: raw & 0x10 != 0,
        uninterpreted_flags: raw & !0x001f,
        code,
        description,
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Port {
    pub number: u8,
    pub physical_link: bool,
    pub loop_closed: bool,
    pub signal_detected: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct DataLink {
    pub raw: u16,
    pub pdi_operational: bool,
    pub watchdog_ok: bool,
    pub extended_link_detection: bool,
    pub uninterpreted_flags: u16,
    pub ports: [Port; 4],
}
pub fn data_link(raw: u16) -> DataLink {
    DataLink {
        raw,
        pdi_operational: raw & 1 != 0,
        watchdog_ok: raw & 2 != 0,
        extended_link_detection: raw & 4 != 0,
        uninterpreted_flags: raw & 8,
        ports: std::array::from_fn(|port| Port {
            number: port as u8,
            physical_link: raw & (1 << (4 + port)) != 0,
            loop_closed: raw & (1 << (8 + 2 * port)) != 0,
            signal_detected: raw & (1 << (9 + 2 * port)) != 0,
        }),
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Information {
    pub controller_type: u8,
    pub revision: u8,
    pub build: u16,
    pub fmmus: u8,
    pub sync_managers: u8,
    pub ram_kib: u8,
    pub port_types: [&'static str; 4],
    pub feature_bits: u16,
}

#[derive(Clone, Debug, Serialize)]
pub struct PortCounters {
    pub number: u8,
    pub invalid_frames: u8,
    pub rx_errors: u8,
    pub forwarded_errors: u8,
    pub lost_links: u8,
}
#[derive(Clone, Debug, Serialize)]
pub struct Counters {
    pub ports: [PortCounters; 4],
    pub processing_errors: u8,
    pub pdi_errors: u8,
    pub pdi_error_code: u16,
    pub at_byte_maximum: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Diagnosis {
    pub snapshot: Snapshot,
    pub al: AlStatus,
    pub data_link: DataLink,
    pub information: Option<Information>,
    pub counters: Option<Counters>,
    pub notes: Vec<String>,
}

fn check_read<T>(read: &RegisterRead<T>) -> Result<()> {
    ensure!(
        match (&read.value, &read.unavailable) {
            (Some(_), None) => true,
            (None, Some(reason)) => !reason.trim().is_empty(),
            _ => false,
        },
        "register read must have either a value or a nonempty unavailable reason"
    );
    Ok(())
}

impl Snapshot {
    pub fn decode(self) -> Result<Diagnosis> {
        ensure!(self.schema == 1, "unsupported ESC snapshot schema");
        let utc = chrono::DateTime::parse_from_rfc3339(&self.started_utc)
            .context("invalid ESC snapshot UTC anchor")?;
        ensure!(
            utc.offset().local_minus_utc() == 0,
            "ESC snapshot anchor must be UTC"
        );
        check_read(&self.information)?;
        check_read(&self.counters)?;
        let information = self.information.value.map(|bytes| Information {
            controller_type: bytes[0],
            revision: bytes[1],
            build: u16::from_le_bytes([bytes[2], bytes[3]]),
            fmmus: bytes[4],
            sync_managers: bytes[5],
            ram_kib: bytes[6],
            feature_bits: u16::from_le_bytes([bytes[8], bytes[9]]),
            port_types: std::array::from_fn(|port| match (bytes[7] >> (2 * port)) & 3 {
                0 => "Not implemented",
                1 => "Not configured",
                2 => "EBUS",
                _ => "MII / RMII / RGMII",
            }),
        });
        let counters = self.counters.value.map(|bytes| {
            let mut at_byte_maximum = Vec::new();
            let ports = std::array::from_fn(|port| {
                let counters = PortCounters {
                    number: port as u8,
                    invalid_frames: bytes[2 * port],
                    rx_errors: bytes[2 * port + 1],
                    forwarded_errors: bytes[8 + port],
                    lost_links: bytes[16 + port],
                };
                for (name, value) in [
                    ("invalid_frames", counters.invalid_frames),
                    ("rx_errors", counters.rx_errors),
                    ("forwarded_errors", counters.forwarded_errors),
                    ("lost_links", counters.lost_links),
                ] {
                    if value == 255 {
                        at_byte_maximum.push(format!("port{port}.{name}"));
                    }
                }
                counters
            });
            for (name, value) in [("processing_errors", bytes[12]), ("pdi_errors", bytes[13])] {
                if value == 255 {
                    at_byte_maximum.push(name.into());
                }
            }
            Counters {
                ports,
                processing_errors: bytes[12],
                pdi_errors: bytes[13],
                pdi_error_code: u16::from_le_bytes([bytes[14], bytes[15]]),
                at_byte_maximum,
            }
        });
        let mut notes=vec![
            "Discovery uses sequential reads; this is a snapshot, not an atomic or cyclic measurement.".into(),
            "Port numbers are ESC numbers, not socket labels or a reconstructed branch topology.".into(),
            "ESC type/revision/build is not the device's vendor/product/revision identity.".into(),
            "Counters may predate this session; PDI error-code meaning and supported counters depend on the ESC.".into(),
        ];
        if let Some(reason) = &self.information.unavailable {
            notes.push(format!("ESC information unavailable: {reason}"));
        }
        if let Some(reason) = &self.counters.unavailable {
            notes.push(format!("Error counters unavailable: {reason}"));
        }
        if counters
            .as_ref()
            .is_some_and(|c| !c.at_byte_maximum.is_empty())
        {
            notes.push("Some counters are 255; check ESC-specific saturation behavior before interpreting counts or rates.".into());
        }
        Ok(Diagnosis {
            al: al_status(self.al_status, self.al_code),
            data_link: data_link(self.dl_status),
            snapshot: self,
            information,
            counters,
            notes,
        })
    }
}

pub fn load(path: &Path) -> Result<Diagnosis> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 64 * 1024, "ESC snapshot exceeds 64 KiB");
    let snapshot: Snapshot =
        serde_json::from_slice(bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes))
            .context("parse ESC snapshot")?;
    snapshot.decode()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Snapshot {
        Snapshot {
            schema: 1,
            source: Source::Authored,
            started_utc: "2026-01-01T00:00:00Z".into(),
            elapsed_us: 100,
            position: 0,
            station_address: 0x1000,
            alias: 7,
            dl_status: 0x9eb6,
            al_status: 0x14,
            al_code: 0x1d,
            information: RegisterRead {
                value: Some([
                    0x11, 1, 0x34, 0x12, 2, 4, 8, 0xe4, 0x0c, 1, 0, 0, 0, 0, 0, 0,
                ]),
                unavailable: None,
            },
            counters: RegisterRead {
                value: Some([
                    1, 2, 255, 3, 0, 0, 0, 0, 4, 5, 0, 0, 6, 7, 0x34, 0x12, 8, 9, 10, 255,
                ]),
                unavailable: None,
            },
        }
    }
    #[test]
    fn separates_physical_link_loop_and_signal_for_each_esc_port() {
        let link = data_link(0x9eb6);
        assert!(!link.pdi_operational && link.watchdog_ok && link.extended_link_detection);
        assert_eq!(
            link.ports
                .map(|p| (p.physical_link, p.loop_closed, p.signal_detected)),
            [
                (true, false, true),
                (true, true, true),
                (false, true, false),
                (true, false, true)
            ]
        );
        assert_eq!(data_link(8).uninterpreted_flags, 8);
    }
    #[test]
    fn distinguishes_controller_information_from_device_identity() {
        let view = fixture().decode().unwrap();
        let info = view.information.unwrap();
        assert_eq!(
            (info.controller_type, info.revision, info.build),
            (0x11, 1, 0x1234)
        );
        assert_eq!(
            (
                info.fmmus,
                info.sync_managers,
                info.ram_kib,
                info.feature_bits
            ),
            (2, 4, 8, 0x10c)
        );
        assert_eq!(
            info.port_types,
            [
                "Not implemented",
                "Not configured",
                "EBUS",
                "MII / RMII / RGMII"
            ]
        );
    }
    #[test]
    fn decodes_separate_counter_banks_without_losing_pdi_code_or_byte_maxima() {
        let view = fixture().decode().unwrap();
        let c = view.counters.unwrap();
        assert_eq!(
            (
                c.ports[0].invalid_frames,
                c.ports[0].rx_errors,
                c.ports[0].forwarded_errors,
                c.ports[0].lost_links
            ),
            (1, 2, 4, 8)
        );
        assert_eq!(
            (
                c.ports[1].invalid_frames,
                c.ports[1].rx_errors,
                c.ports[1].forwarded_errors,
                c.ports[1].lost_links
            ),
            (255, 3, 5, 9)
        );
        assert_eq!(
            (c.processing_errors, c.pdi_errors, c.pdi_error_code),
            (6, 7, 0x1234)
        );
        assert_eq!(
            c.at_byte_maximum,
            ["port1.invalid_frames", "port3.lost_links"]
        );
    }
    #[test]
    fn retains_unknown_al_flags_states_and_vendor_codes() {
        let status = al_status(0x14, 0x1d);
        assert_eq!(status.state, "SAFEOP");
        assert!(status.error);
        assert_eq!(status.description, "Output configuration invalid");
        let status = al_status(0x2f, 0xabcd);
        assert_eq!(status.state, "Unknown state");
        assert_eq!(status.uninterpreted_flags, 0x20);
        assert_eq!(status.code, 0xabcd);
        assert_eq!(status.description, "Vendor-specific AL code");
        assert_eq!(
            al_status(1, 0x7777).description,
            "Unmapped or reserved AL code"
        );
    }
    #[test]
    fn validates_snapshot_schema_time_and_explicit_unavailable_reads() {
        let mut raw = fixture();
        raw.counters = RegisterRead {
            value: None,
            unavailable: Some("WKC 0".into()),
        };
        let view = raw.decode().unwrap();
        assert!(view.counters.is_none());
        assert!(view.notes.iter().any(|s| s.contains("WKC 0")));
        let mut raw = fixture();
        raw.information.unavailable = Some("contradiction".into());
        assert!(raw.decode().is_err());
        let mut raw = fixture();
        raw.schema = 2;
        assert!(raw.decode().is_err());
        let mut raw = fixture();
        raw.started_utc = "2026-01-01T00:00:00+01:00".into();
        assert!(raw.decode().is_err());
    }
}

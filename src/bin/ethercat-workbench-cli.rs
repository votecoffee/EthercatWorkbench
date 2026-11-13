use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use ethercat_workbench::{
    esi,
    model::{LogMode, Profile, Scheduler, payload_hex},
    run::{self, BenchApproval, Mode, RunOptions, Snapshot},
};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering::Relaxed},
    },
    time::Duration,
};

#[derive(Parser)]
#[command(version, about = "EtherCAT bench workbench (headless)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List Windows Npcap interface identifiers without transmitting.
    Nics,
    /// Read bus position, station address, port links and AL registers without configuration.
    Scan {
        #[arg(long)]
        nic: String,
    },
    /// Run the same read-only discovery parser against an authored virtual ESC. Never opens a NIC.
    ScanVirtual {
        #[arg(long, value_enum, default_value = "coe")]
        model: ethercat_workbench::virtual_esc::VirtualModel,
        #[arg(long, value_enum, default_value = "normal")]
        case: ethercat_workbench::virtual_esc::ScanCase,
    },
    /// Interpret an offline ESC register snapshot (no bus access).
    DecodeEsc { file: PathBuf },
    /// List products and revisions in an ESI XML.
    EsiList { file: PathBuf },
    /// Write a new profile from one zero-based ESI list selection.
    EsiImport {
        file: PathBuf,
        #[arg(long)]
        device: usize,
        #[arg(long)]
        out: PathBuf,
        /// Stage an ESI DC mode for offline review only (zero-based index).
        #[arg(long)]
        dc_mode: Option<usize>,
        /// Manual sync-unit period assumption for resolving ESI factors; does not set host or device timing.
        #[arg(long, requires = "dc_mode")]
        sync_unit_cycle_ns: Option<u32>,
        /// Replace this direction's default choices; repeat INDEX@SM in desired order, or use none.
        #[arg(long)]
        tx_pdo: Vec<String>,
        #[arg(long)]
        rx_pdo: Vec<String>,
    },
    /// Build a new offline profile from a retained ESI catalog. Sends no bus writes.
    SelectPdos {
        profile: PathBuf,
        #[arg(long)]
        tx_pdo: Vec<String>,
        #[arg(long)]
        rx_pdo: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Show the full expected offline assignment, including padding and SyncManagers.
    ReviewPdos { profile: PathBuf },
    /// Review a staged ESI DC mode, optionally comparing a saved run report. Performs no bus operations.
    ReviewSync {
        profile: PathBuf,
        #[arg(long)]
        readback: Option<PathBuf>,
    },
    /// Parse and validate a saved profile.
    Validate { profile: PathBuf },
    /// Compare saved CoE PDO readback with an ESI or manual profile.
    VerifyPdo { profile: PathBuf, readback: PathBuf },
    /// Compare saved timing trials with matching settings except for their scheduler. No bus operations.
    CompareRuns {
        #[arg(required = true, num_args = 2..=32)]
        reports: Vec<PathBuf>,
        /// Audit one CSV base per report, repeated in report order.
        #[arg(long)]
        csv: Vec<PathBuf>,
    },
    /// Audit the CSV parts declared by a saved run report, without bus operations.
    VerifyCapture { report: PathBuf, csv: PathBuf },
    /// Decode an offline payload using the profile.
    Decode {
        profile: PathBuf,
        #[arg(allow_hyphen_values = true)]
        hex: String,
        /// Use RxPDO mappings instead of TxPDO mappings.
        #[arg(long)]
        rx: bool,
    },
    /// Run a bounded synthetic or approval-gated live capture. Writes JSON to stdout.
    Run {
        profile: PathBuf,
        #[arg(long, value_enum, default_value = "simulate")]
        backend: Backend,
        #[arg(long, default_value_t = 10)]
        seconds: u64,
        #[arg(long)]
        csv: Option<PathBuf>,
        /// New UTF-8 JSON report file. Existing paths are rejected before starting the run.
        #[arg(long)]
        report: Option<PathBuf>,
        #[arg(long, value_enum)]
        scheduler: Option<Schedule>,
        #[arg(long)]
        on_change: bool,
        /// Stop after continuous invalid input for this duration; 0 monitors until the run ends.
        #[arg(long)]
        input_loss_timeout_ms: Option<u64>,
        #[arg(long)]
        simulate_faults: bool,
        #[arg(long, required_if_eq("backend", "replay"))]
        replay: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "none")]
        virtual_fault: ethercat_workbench::virtual_esc::VirtualFault,
        #[arg(long, value_enum, default_value = "coe")]
        virtual_model: ethercat_workbench::virtual_esc::VirtualModel,
        #[arg(long, default_value_t = 1)]
        generation: u64,
        /// Confirm approval for ESC initialization, SAFEOP and return to INIT on one isolated device.
        #[arg(long)]
        approve_esc_writes: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Backend {
    Simulate,
    Safeop,
    Replay,
    Virtual,
}

#[derive(Clone, Copy, ValueEnum)]
enum Schedule {
    Deadline,
    Relative,
}

fn output(value: &impl Serialize) -> Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value)?;
    writeln!(out)?;
    Ok(())
}

fn pdo_arguments(
    values: &[String],
    default: Vec<ethercat_workbench::pdo_catalog::Assignment>,
) -> Result<Vec<ethercat_workbench::pdo_catalog::Assignment>> {
    use ethercat_workbench::pdo_catalog::Assignment;
    if values.is_empty() {
        return Ok(default);
    }
    if values.len() == 1 && values[0] == "none" {
        return Ok(Vec::new());
    }
    values
        .iter()
        .map(|value| {
            let (index, sm) = value
                .split_once('@')
                .context("PDO choice must be INDEX@SM, or none alone")?;
            Ok(Assignment {
                index: u16::try_from(esi::number(index)?)?,
                sm: u8::try_from(esi::number(sm)?)?,
            })
        })
        .collect()
}

#[derive(Deserialize)]
struct SavedSyncReport {
    synchronization: Option<ethercat_workbench::sync::Synchronization>,
    devices: Vec<SavedSyncDevice>,
}
#[derive(Deserialize)]
struct SavedSyncDevice {
    identity: Option<ethercat_workbench::model::Identity>,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Nics => output(&ethercat_workbench::live::nics()?),
        Command::Scan { nic } => output(&ethercat_workbench::live::scan(&nic)?),
        Command::ScanVirtual { model, case } => {
            let report = ethercat_workbench::live::scan_virtual(model, case);
            output(&report)?;
            if let Some(error) = report.error {
                bail!("{error}");
            }
            Ok(())
        }
        Command::DecodeEsc { file } => output(&ethercat_workbench::esc::load(&file)?),
        Command::CompareRuns { reports, csv } => {
            let result = if csv.is_empty() {
                ethercat_workbench::benchmark::compare_files(&reports)?
            } else {
                ethercat_workbench::benchmark::compare_with_captures(&reports, &csv)?
            };
            output(&result)
        }
        Command::VerifyCapture { report, csv } => {
            output(&ethercat_workbench::capture_audit::verify(&report, &csv)?)
        }
        Command::EsiList { file } => {
            let entries = esi::load(&file)?;
            let list: Vec<_> = entries.iter().enumerate().map(|(index, entry)| {
                serde_json::json!({"index": index, "source": entry.source, "tx_bytes": entry.tx_bytes,
                    "rx_bytes": entry.rx_bytes, "notes": entry.notes})
            }).collect();
            output(&list)
        }
        Command::EsiImport {
            file,
            device,
            out,
            dc_mode,
            sync_unit_cycle_ns,
            tx_pdo,
            rx_pdo,
        } => {
            let devices = esi::load(&file)?;
            let selected = devices
                .get(device)
                .context("ESI device index out of range")?;
            let mut profile = Profile::default();
            let mut selection =
                ethercat_workbench::pdo_catalog::defaults(&selected.source.pdo_catalog);
            selection.tx = pdo_arguments(&tx_pdo, selection.tx)?;
            selection.rx = pdo_arguments(&rx_pdo, selection.rx)?;
            selected.apply_selection(&mut profile, selection)?;
            profile.staged_esi_dc_mode = dc_mode;
            profile.sync_unit_cycle_ns = sync_unit_cycle_ns;
            profile.save(&out)?;
            output(&selected.notes)
        }
        Command::SelectPdos {
            profile,
            tx_pdo,
            rx_pdo,
            out,
        } => {
            let mut profile = Profile::load(&profile)?;
            let esi = profile.esi.as_ref().context("profile has no ESI catalog")?;
            let mut selection = profile
                .esi_pdo_selection
                .clone()
                .unwrap_or_else(|| ethercat_workbench::pdo_catalog::defaults(&esi.pdo_catalog));
            selection.tx = pdo_arguments(&tx_pdo, selection.tx)?;
            selection.rx = pdo_arguments(&rx_pdo, selection.rx)?;
            ethercat_workbench::pdo_catalog::apply(&mut profile, selection)?;
            profile.save(&out)?;
            output(&profile)
        }
        Command::ReviewPdos { profile } => {
            let profile = Profile::load(&profile)?;
            let esi = profile.esi.as_ref().context("profile has no ESI catalog")?;
            let selection = profile
                .esi_pdo_selection
                .as_ref()
                .context("profile has no attached ESI PDO selection")?;
            let built = ethercat_workbench::pdo_catalog::build(&esi.pdo_catalog, selection)?;
            output(
                &serde_json::json!({"applied":false,"esi_file_name":esi.file_name,"esi_sha256":esi.sha256,
                "identity":esi.identity,"selection":selection,"tx":built.tx_layout,"rx":built.rx_layout,
                "tx_bytes":built.tx_bytes,"rx_bytes":built.rx_bytes,"boundary":"Offline expectation only; no assignment writes were sent"}),
            )
        }
        Command::ReviewSync { profile, readback } => {
            let profile = Profile::load(&profile)?;
            let saved = readback
                .map(|path| -> Result<_> {
                    let file = std::fs::File::open(path)?;
                    ensure!(
                        file.metadata()?.len() <= 16 * 1024 * 1024,
                        "saved report exceeds 16 MiB"
                    );
                    let saved: SavedSyncReport = serde_json::from_reader(file)?;
                    ensure!(
                        saved.devices.len() == 1
                            && profile.expected_identity.is_some()
                            && saved.devices[0].identity == profile.expected_identity,
                        "saved synchronization report must identify one device matching the profile"
                    );
                    let mut sync = saved
                        .synchronization
                        .context("saved report has no synchronization readback")?;
                    sync.source = format!("Saved run report ({})", sync.source);
                    Ok(sync)
                })
                .transpose()?;
            let review = ethercat_workbench::sync_review::review(&profile, saved.as_ref())?
                .context("select an ESI DC mode for offline review first")?;
            output(&review)
        }
        Command::Validate { profile } => output(&Profile::load(&profile)?),
        Command::VerifyPdo { profile, readback } => {
            let profile = Profile::load(&profile)?;
            let readback: ethercat_workbench::pdo::Readback =
                serde_json::from_reader(std::fs::File::open(readback)?)?;
            let verification = readback.verify(&profile, "Saved PDO readback");
            output(&verification)?;
            ensure!(
                verification.compatible(),
                "saved PDO layout differs from profile"
            );
            Ok(())
        }
        Command::Decode { profile, hex, rx } => {
            let profile = Profile::load(&profile)?;
            let payload = payload_hex(&hex)?;
            let (len, fields) = if rx {
                (profile.rx_bytes, profile.rx)
            } else {
                (profile.tx_bytes, profile.tx)
            };
            ensure!(
                payload.len() == len,
                "expected {len} bytes, got {}",
                payload.len()
            );
            let values: Vec<_> = fields.iter().map(|f| serde_json::json!({
                "field": f.name, "bit": f.bit, "width": f.width, "source": f.source, "value": f.decode(&payload)
            })).collect();
            output(&values)
        }
        Command::Run {
            profile,
            backend,
            seconds,
            csv,
            report: report_path,
            scheduler,
            on_change,
            input_loss_timeout_ms,
            simulate_faults,
            replay,
            virtual_fault,
            virtual_model,
            generation,
            approve_esc_writes,
        } => {
            ensure!(
                replay.is_none() || matches!(backend, Backend::Replay),
                "--replay requires --backend replay"
            );
            ensure!(
                matches!(backend, Backend::Virtual)
                    || virtual_fault == ethercat_workbench::virtual_esc::VirtualFault::None,
                "--virtual-fault requires --backend virtual"
            );
            ensure!(
                matches!(backend, Backend::Virtual)
                    || virtual_model == ethercat_workbench::virtual_esc::VirtualModel::Coe,
                "--virtual-model requires --backend virtual"
            );
            ensure!(
                virtual_model.has_coe()
                    || !matches!(
                        virtual_fault,
                        ethercat_workbench::virtual_esc::VirtualFault::MailboxAbort
                            | ethercat_workbench::virtual_esc::VirtualFault::ReadbackUnavailable
                    ),
                "selected virtual fault requires the CoE model"
            );
            ensure!(
                virtual_model == ethercat_workbench::virtual_esc::VirtualModel::CoeDc
                    || !matches!(
                        virtual_fault,
                        ethercat_workbench::virtual_esc::VirtualFault::DcActive
                            | ethercat_workbench::virtual_esc::VirtualFault::DcReadbackUnavailable
                    ),
                "selected virtual fault requires the coe-dc model"
            );
            ensure!(
                virtual_model == ethercat_workbench::virtual_esc::VirtualModel::CoeSegmented
                    || !matches!(
                        virtual_fault,
                        ethercat_workbench::virtual_esc::VirtualFault::SegmentToggle
                            | ethercat_workbench::virtual_esc::VirtualFault::SegmentSize
                            | ethercat_workbench::virtual_esc::VirtualFault::SegmentTimeout
                            | ethercat_workbench::virtual_esc::VirtualFault::SegmentAbort
                            | ethercat_workbench::virtual_esc::VirtualFault::MailboxCounter
                            | ethercat_workbench::virtual_esc::VirtualFault::SegmentInitialData
                    ),
                "selected virtual fault requires the coe-segmented model"
            );
            let mode = match backend {
                Backend::Simulate => Mode::Simulate {
                    faults: simulate_faults,
                },
                Backend::Virtual => {
                    ensure!(
                        !simulate_faults,
                        "--simulate-faults is for the synthetic backend"
                    );
                    Mode::Virtual {
                        model: virtual_model,
                        fault: virtual_fault,
                    }
                }
                Backend::Replay => {
                    ensure!(
                        !simulate_faults,
                        "--simulate-faults is for the synthetic backend"
                    );
                    Mode::Replay {
                        fixture: replay.context("replay fixture path is required")?,
                    }
                }
                Backend::Safeop => {
                    ensure!(
                        !simulate_faults,
                        "--simulate-faults is for the synthetic backend"
                    );
                    Mode::SafeOp {
                        approved: BenchApproval::confirm(approve_esc_writes)?,
                    }
                }
            };
            let mut profile = Profile::load(&profile)?;
            if let Some(scheduler) = scheduler {
                profile.scheduler = match scheduler {
                    Schedule::Deadline => Scheduler::Deadline,
                    Schedule::Relative => Scheduler::Relative,
                };
            }
            if on_change {
                profile.mode = LogMode::Change;
            }
            if let Some(timeout) = input_loss_timeout_ms {
                profile.input_loss_timeout_ms = timeout;
            }
            let report_file = report_path
                .as_ref()
                .map(|path| {
                    ensure!(
                        path.extension()
                            .is_some_and(|ext| ext.eq_ignore_ascii_case("json")),
                        "report path must end in .json"
                    );
                    std::fs::File::create_new(path)
                        .with_context(|| format!("reserve new report {}", path.display()))
                })
                .transpose()?;
            let stop = Arc::new(AtomicBool::new(false));
            ctrlc::set_handler({
                let stop = stop.clone();
                move || stop.store(true, Relaxed)
            })
            .context("install Ctrl+C handler")?;
            let report = run::run(
                profile,
                RunOptions {
                    frontend: ethercat_workbench::benchmark::Frontend::Cli,
                    mode,
                    duration: Duration::from_secs(seconds),
                    csv,
                    generation,
                },
                &stop,
                &Mutex::new(Snapshot::default()),
            );
            if let Some(mut file) = report_file {
                use std::io::Write;
                serde_json::to_writer_pretty(&mut file, &report)?;
                writeln!(file)?;
                file.sync_all().context("flush saved run report")?;
            }
            output(&report)?;
            if let Some(error) = report.error {
                bail!("{error}");
            }
            Ok(())
        }
    }
}

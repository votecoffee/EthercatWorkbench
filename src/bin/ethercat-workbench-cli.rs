use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use ethercat_workbench::{
    esi,
    model::{LogMode, Profile, Scheduler, payload_hex},
    run::{self, BenchApproval, Mode, RunOptions, Snapshot},
};
use serde::Serialize;
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
    /// List products and revisions in an ESI XML.
    EsiList { file: PathBuf },
    /// Write a new profile from one zero-based ESI list selection.
    EsiImport {
        file: PathBuf,
        #[arg(long)]
        device: usize,
        #[arg(long)]
        out: PathBuf,
    },
    /// Parse and validate a saved profile.
    Validate { profile: PathBuf },
    /// Compare saved CoE PDO readback with an ESI or manual profile.
    VerifyPdo { profile: PathBuf, readback: PathBuf },
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
        #[arg(long, value_enum)]
        scheduler: Option<Schedule>,
        #[arg(long)]
        on_change: bool,
        #[arg(long)]
        simulate_faults: bool,
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

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Nics => output(&ethercat_workbench::live::nics()?),
        Command::Scan { nic } => output(&ethercat_workbench::live::scan(&nic)?),
        Command::EsiList { file } => {
            let entries = esi::load(&file)?;
            let list: Vec<_> = entries.iter().enumerate().map(|(index, entry)| {
                serde_json::json!({"index": index, "source": entry.source, "tx_bytes": entry.tx_bytes,
                    "rx_bytes": entry.rx_bytes, "notes": entry.notes})
            }).collect();
            output(&list)
        }
        Command::EsiImport { file, device, out } => {
            let devices = esi::load(&file)?;
            let selected = devices
                .get(device)
                .context("ESI device index out of range")?;
            let mut profile = Profile::default();
            selected.apply(&mut profile);
            profile.save(&out)?;
            output(&selected.notes)
        }
        Command::Validate { profile } => output(&Profile::load(&profile)?),
        Command::VerifyPdo { profile, readback } => {
            let profile = Profile::load(&profile)?;
            let readback: ethercat_workbench::pdo::Readback =
                serde_json::from_reader(std::fs::File::open(readback)?)?;
            let verification = readback.verify(&profile, "Saved CoE readback");
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
            scheduler,
            on_change,
            simulate_faults,
            generation,
            approve_esc_writes,
        } => {
            let mode = match backend {
                Backend::Simulate => Mode::Simulate {
                    faults: simulate_faults,
                },
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
            let stop = Arc::new(AtomicBool::new(false));
            ctrlc::set_handler({
                let stop = stop.clone();
                move || stop.store(true, Relaxed)
            })
            .context("install Ctrl+C handler")?;
            let report = run::run(
                profile,
                RunOptions {
                    mode,
                    duration: Duration::from_secs(seconds),
                    csv,
                    generation,
                },
                &stop,
                &Mutex::new(Snapshot::default()),
            );
            output(&report)?;
            if let Some(error) = report.error {
                bail!("{error}");
            }
            Ok(())
        }
    }
}

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use ethercat_workbench::{
    esi,
    model::{LogMode, Profile, Scheduler, payload_hex},
    run::{self, BenchApproval, Mode, RunOptions, Snapshot},
    trial_set::{TrialSet, comparison_task},
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

#[derive(Args)]
#[group(skip)]
struct ModularSelection {
    file: PathBuf,
    /// Zero-based device entry in esi-list.
    #[arg(long)]
    device: Option<usize>,
    /// Exact VENDOR/PRODUCT/REVISION, optionally guarding the device index.
    #[arg(long, value_parser = esi::identity_selector)]
    identity: Option<ethercat_workbench::model::Identity>,
    /// Supply one zero-based SLOT=MODULE_IDENT for each expanded position. Use 0 for an empty optional slot.
    #[arg(long, required_unless_present = "module_inventory", value_parser = esi::modular_preview::placement)]
    slot: Vec<esi::modular_preview::Placement>,
    /// Supply a zero-based DECLARATION=COUNT for each variable repeatable declaration.
    #[arg(long, value_parser = esi::modular_preview::slot_count)]
    slot_count: Vec<esi::modular_preview::SlotCount>,
    /// Use saved configured/detected CoE module IDs to review or fill the slot choices.
    #[arg(long)]
    module_inventory: Option<PathBuf>,
}

impl ModularSelection {
    fn preview(&self) -> Result<esi::modular_preview::Preview> {
        esi::modular_preview::preview_with_slot_counts(
            &self.file,
            self.device,
            self.identity.as_ref(),
            &self.slot,
            self.module_inventory.as_deref(),
            &self.slot_count,
        )
    }
}

#[derive(Subcommand)]
enum Command {
    /// Inspect Windows Npcap host files, service and policy without opening a NIC.
    CheckRuntime {
        /// Export the host observations to a new .json file.
        #[arg(long)]
        out: Option<PathBuf>,
    },
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
    /// Plan one grouped logical input read or decode its saved bytes offline.
    InspectInputGroup {
        manifest: PathBuf,
        /// Complete LRD payload as hex byte pairs, with optional spaces.
        #[arg(long, requires = "wkc")]
        hex: Option<String>,
        /// Actual LRD Working Counter supplied with the sample.
        #[arg(long, requires = "hex")]
        wkc: Option<u16>,
        /// Inspect a saved Workbench Ethernet reply with its ordered station addresses.
        #[arg(long, conflicts_with_all = ["hex", "wkc"])]
        frame: Option<PathBuf>,
        /// Check a saved FMMU register snapshot against the input plan.
        #[arg(long, conflicts_with_all = ["hex", "wkc"])]
        fmmu: Option<PathBuf>,
        /// Check saved SyncManager registers against the FMMU physical ranges.
        #[arg(long, requires = "fmmu")]
        sync_managers: Option<PathBuf>,
        /// Check saved TxPDO assignments, descriptor order and logical placement per station.
        #[arg(long, requires_all = ["fmmu", "sync_managers"])]
        pdo: Option<PathBuf>,
        /// Export inspection JSON to a new file.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Read and check the topology, FMMUs and SyncManagers of an authored virtual group.
    InspectVirtualGroupMapping {
        manifest: PathBuf,
        #[arg(long, value_enum, default_value = "clean")]
        scenario: ethercat_workbench::input_group::preflight::GroupMappingScenario,
        /// Read TxPDO descriptors from the modeled CoE mailboxes and SII EEPROM.
        #[arg(long)]
        read_pdos: bool,
        /// Save the mapping evidence and inspection to a new JSON file.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Rehearse clock distribution and qualify sampled inputs on two or three virtual DC stations.
    RehearseGroupDc {
        manifest: PathBuf,
        #[command(flatten)]
        clock: GroupDcArgs,
        /// Save the clock and input evidence to a new JSON file.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Save raw virtual DC group and input replies for verified CSV replay.
    GenerateGroupDcReplay {
        manifest: PathBuf,
        #[command(flatten)]
        clock: GroupDcArgs,
        /// Save the fixture to a new JSON file.
        #[arg(long)]
        out: PathBuf,
    },
    /// Generate deterministic replies from an authored virtual group.
    GenerateGroupReplay {
        manifest: PathBuf,
        #[arg(long, value_enum, default_value = "clean")]
        scenario: ethercat_workbench::input_group::replay::VirtualScenario,
        /// Record CoE and SII TxPDO exchanges during each virtual setup.
        #[arg(long)]
        read_pdos: bool,
        /// Save the fixture to a new JSON file.
        #[arg(long)]
        out: PathBuf,
    },
    /// Replay saved group replies into CSV using the recorded receive times.
    ReplayInputGroup {
        manifest: PathBuf,
        fixture: PathBuf,
        /// Create a new CSV, or a numbered series when rotation is enabled.
        #[arg(long)]
        csv: PathBuf,
        /// Write the first valid row per generation and subsequent selected-field changes.
        #[arg(long)]
        on_change: bool,
        /// Rows per CSV part. Zero disables rotation.
        #[arg(long, default_value_t = 0)]
        rotate_rows: u64,
        /// Optional saved FMMU evidence to verify before replay.
        #[arg(long)]
        fmmu: Option<PathBuf>,
        /// Optional SyncManager evidence to verify before replay.
        #[arg(long, requires = "fmmu")]
        sync_managers: Option<PathBuf>,
        /// TxPDO snapshot or virtual readback report. Can use the fixture's saved mapping replies.
        #[arg(long)]
        pdo: Option<PathBuf>,
        /// Save the replay receipt to a new JSON file.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify a saved group replay receipt and CSV against the original frames.
    VerifyGroupReplay {
        manifest: PathBuf,
        fixture: PathBuf,
        receipt: PathBuf,
        csv: PathBuf,
        /// Saved FMMU evidence used when creating the receipt.
        #[arg(long)]
        fmmu: Option<PathBuf>,
        /// Saved SyncManager evidence used when creating the receipt.
        #[arg(long, requires = "fmmu")]
        sync_managers: Option<PathBuf>,
        /// TxPDO snapshot or virtual readback report used when creating the receipt.
        #[arg(long)]
        pdo: Option<PathBuf>,
        /// Export the audit and CSV part hashes to a new JSON file.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Export verified group replay evidence to a new portable directory.
    BundleGroupReplay {
        manifest: PathBuf,
        fixture: PathBuf,
        receipt: PathBuf,
        csv: PathBuf,
        #[arg(long)]
        fmmu: Option<PathBuf>,
        #[arg(long, requires = "fmmu")]
        sync_managers: Option<PathBuf>,
        /// TxPDO snapshot or virtual readback report used when creating the receipt.
        #[arg(long)]
        pdo: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Reopen a portable group replay bundle and rerun the CSV audit.
    VerifyGroupBundle {
        directory: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Read one existing Windows shared-memory input snapshot. Never opens an EtherCAT NIC.
    ReadShared {
        name: String,
        /// Exact effective profile for verified typed decoding; raw inspection works without it.
        #[arg(long, conflicts_with = "run_report")]
        profile: Option<PathBuf>,
        /// Use the effective profile embedded in a saved run context.
        #[arg(long)]
        run_report: Option<PathBuf>,
        /// Save coherent ready raw bytes to a new .bin file.
        #[arg(long)]
        save_raw: Option<PathBuf>,
        /// Export this inspection to a new .json file.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Inspect saved shared-memory bytes as historical evidence; never reads IPC or a NIC.
    InspectShared {
        file: PathBuf,
        #[arg(long, conflicts_with = "run_report")]
        profile: Option<PathBuf>,
        #[arg(long)]
        run_report: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Inspect Ethernet PCAP or one PCAPNG interface offline; never opens a NIC or transmits frames.
    InspectPcap {
        profile: PathBuf,
        file: PathBuf,
        /// Expected station address (decimal or 0x hex), not discovered from the capture.
        #[arg(long, default_value = "0x1000", value_parser = esi::number)]
        station: u32,
        /// Number of returned-frame payload previews (0..64); all frames are counted.
        #[arg(long, default_value_t = 16)]
        preview: usize,
        /// PCAPNG interface ID (0..31); required when the file has multiple interfaces.
        #[arg(long, value_parser = clap::value_parser!(u32).range(0..32))]
        interface: Option<u32>,
        /// Save UTF-8 JSON to a new .json file after inspection; preserve existing paths.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// List products and revisions in an ESI XML.
    EsiList { file: PathBuf },
    /// Write a new profile from an exact ESI identity or zero-based list selection.
    #[command(group(clap::ArgGroup::new("esi_selector").required(true).multiple(true).args(["device", "identity"])))]
    EsiImport {
        file: PathBuf,
        /// Zero-based esi-list index. Combine with --identity to guard the chosen entry.
        #[arg(long)]
        device: Option<usize>,
        /// Exact VENDOR/PRODUCT/REVISION, in decimal, 0x hex or #x hex; rejects ambiguous matches.
        #[arg(long, value_parser = esi::identity_selector)]
        identity: Option<ethercat_workbench::model::Identity>,
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
    /// Read the configured and detected module lists on the fixed-slot virtual fixture.
    ReadVirtualModuleInventory {
        #[arg(long, value_enum, default_value = "matched")]
        scenario: ethercat_workbench::live::virtual_inventory::ModuleInventoryCase,
        /// Save the schema-1 inventory for use with --module-inventory.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Read PDOs in the same virtual PREOP session and save a new --run-report input.
        #[arg(long)]
        pdo_report: Option<PathBuf>,
    },
    /// Inspect ESI TxPDOs that describe ESC registers and optionally decode a saved ESC snapshot.
    #[command(group(clap::ArgGroup::new("register_pdo_device").required(true).multiple(true).args(["device", "identity"])))]
    PreviewRegisterPdos {
        file: PathBuf,
        /// Zero-based device entry in esi-list.
        #[arg(long)]
        device: Option<usize>,
        /// Exact VENDOR/PRODUCT/REVISION, optionally guarding the device index.
        #[arg(long, value_parser = esi::identity_selector)]
        identity: Option<ethercat_workbench::model::Identity>,
        /// Raw ESC diagnostics snapshot, using the same format as decode-esc.
        #[arg(long)]
        snapshot: Option<PathBuf>,
        /// Saved schema-1 FMMU register table.
        #[arg(long, requires = "station")]
        fmmu: Option<PathBuf>,
        /// Select the configured station address in the saved FMMU table.
        #[arg(long, requires = "fmmu", value_parser = esi::number)]
        station: Option<u32>,
        /// Export to a new JSON file.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Compose a device-level PDO layout offline from an ESI and explicit JSON assignments.
    #[command(group(clap::ArgGroup::new("layout_device").required(true).multiple(true).args(["device", "identity"])))]
    PreviewPdoLayout {
        file: PathBuf,
        #[arg(long)]
        device: Option<usize>,
        #[arg(long, value_parser = esi::identity_selector)]
        identity: Option<ethercat_workbench::model::Identity>,
        #[arg(long)]
        expect_layout: PathBuf,
        #[arg(long)]
        run_report: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Resolve module PDO candidate indexes for explicit or detected placements in fixed ESI slots.
    #[command(group(clap::ArgGroup::new("module_device").required(true).multiple(true).args(["device", "identity"])))]
    PreviewModularPdos {
        #[command(flatten)]
        selection: ModularSelection,
        /// Compose the expected offline image from an explicit JSON assignment list.
        #[arg(long)]
        expect_layout: Option<PathBuf>,
        /// Compare against PDO readback in a saved run report for the same identity.
        #[arg(long)]
        run_report: Option<PathBuf>,
        /// Decode a supplied TxPDO image using the matching saved descriptors.
        #[arg(long, requires = "run_report")]
        tx_hex: Option<String>,
        /// Decode a supplied RxPDO image using the matching saved descriptors.
        #[arg(long, requires = "run_report")]
        rx_hex: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Export an offline decoder profile from matched module PDOs and a saved run.
    #[command(group(clap::ArgGroup::new("module_device").required(true).multiple(true).args(["device", "identity"])))]
    ExportModularProfile {
        #[command(flatten)]
        selection: ModularSelection,
        #[arg(long)]
        run_report: PathBuf,
        #[arg(long)]
        out: PathBuf,
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
    /// Preview PDO choices from the selected ESI mode; optionally save a new offline profile.
    StageModePdos {
        profile: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Explicitly discard staged RxPDO bytes when their layout changes.
        #[arg(long)]
        clear_staged_rx: bool,
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
    /// Inspect the observed assignments and optional payloads from a saved one-device PDO run.
    InspectPdoReadback {
        profile: PathBuf,
        run_report: PathBuf,
        #[arg(long)]
        tx_hex: Option<String>,
        #[arg(long)]
        rx_hex: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Save an offline decoder with bit positions from a matching saved PDO run.
    ExportObservedPdoProfile {
        profile: PathBuf,
        run_report: PathBuf,
        /// Override a Tx entry type with BIT=KIND.
        #[arg(long, value_parser = ethercat_workbench::pdo::inspect::profile::choice)]
        tx_kind: Vec<ethercat_workbench::pdo::inspect::profile::Choice>,
        /// Override an Rx entry type with BIT=KIND.
        #[arg(long, value_parser = ethercat_workbench::pdo::inspect::profile::choice)]
        rx_kind: Vec<ethercat_workbench::pdo::inspect::profile::Choice>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Compare saved timing trials with matching settings except for their scheduler. No bus operations.
    CompareRuns {
        #[arg(required_unless_present_any = ["trial_set", "bundle"], num_args = 2..=32)]
        reports: Vec<PathBuf>,
        /// Audit one CSV base per report, repeated in report order.
        #[arg(long)]
        csv: Vec<PathBuf>,
        /// Use the ordered report paths and audit setting from a saved trial set.
        #[arg(long, value_name = "JSON", conflicts_with_all = ["reports", "csv"])]
        trial_set: Option<PathBuf>,
        /// Recompute from a portable bundle and match the evidence hashes.
        #[arg(long, value_name = "DIRECTORY", conflicts_with_all = ["reports", "csv", "trial_set"])]
        bundle: Option<PathBuf>,
        /// Save the comparison result to a new JSON file. JSON is also printed to stdout.
        #[arg(long, value_name = "JSON")]
        out: Option<PathBuf>,
    },
    /// Audit the CSV parts declared by a saved run report, without bus operations.
    VerifyCapture { report: PathBuf, csv: PathBuf },
    /// Check the report and CSV-part hashes recorded in a saved comparison.
    CheckComparison {
        file: PathBuf,
        /// Resolve relative references against this original working folder.
        #[arg(long, value_name = "DIRECTORY")]
        base: Option<PathBuf>,
        /// Save the file check to a new JSON file.
        #[arg(long, value_name = "JSON")]
        out: Option<PathBuf>,
    },
    /// Copy a comparison and its verified sources to a new portable directory.
    BundleComparison {
        file: PathBuf,
        /// Resolve relative references against this original working folder.
        #[arg(long, value_name = "DIRECTORY")]
        base: Option<PathBuf>,
        /// Create this new bundle directory.
        #[arg(long, value_name = "DIRECTORY")]
        out: PathBuf,
    },
    /// Verify a portable comparison bundle in its current folder.
    VerifyBundle { directory: PathBuf },
    /// Prepare typed RxPDO values offline; print a preview or save a new staged profile. No bus access.
    StageRx {
        profile: PathBuf,
        /// Repeat zero-based INDEX=VALUE. Edits affect saved offline bytes only.
        #[arg(long = "set", required = true)]
        assignments: Vec<String>,
        /// Initialize an empty staged image from zero; existing bytes are never reset.
        #[arg(long)]
        zero: bool,
        /// Save the resulting profile to a new file. Without this, print the preview only.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Propose a one-shot output trial for offline review.
    PlanOutput {
        profile: PathBuf,
        #[arg(long)]
        safe_hex: String,
        /// Documented or proposed process-data watchdog interval in microseconds.
        #[arg(long)]
        watchdog_us: u64,
        /// Proposed maximum time to stay in OP, in microseconds.
        #[arg(long)]
        max_op_us: u64,
        /// How the operator will independently observe the safe stop.
        #[arg(long)]
        stop_observation: String,
        /// Require this device serial when observing the device.
        #[arg(long)]
        serial: Option<u32>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify a saved output proposal against the reviewed SHA-256 and current profile.
    VerifyOutputPlan {
        profile: PathBuf,
        plan: PathBuf,
        #[arg(long)]
        sha256: String,
    },
    /// Rehearse reviewed DC setup, reference-clock traffic and teardown on one in-memory device.
    RehearseDc {
        profile: PathBuf,
        /// Explicit SYNC0 period in nanoseconds.
        #[arg(
            long,
            required_unless_present = "from_esi",
            conflicts_with = "from_esi"
        )]
        period_ns: Option<u32>,
        /// Enable SYNC1 and set its register delay in nanoseconds. Zero enables coincident SYNC1.
        #[arg(long, conflicts_with = "from_esi")]
        sync1_delay_ns: Option<u32>,
        /// Resolve timing from the profile's staged ESI mode.
        #[arg(long)]
        from_esi: bool,
        #[arg(long)]
        start_delay_ns: u32,
        #[arg(long, default_value_t = 3)]
        cycles: u64,
        #[arg(long, value_enum, default_value = "normal")]
        scenario: ethercat_workbench::live::virtual_dc::DcRehearsalCase,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Rehearse staged RxPDO output, OP and INIT using an in-memory device.
    RehearseOutput {
        profile: PathBuf,
        #[arg(long, value_enum, default_value = "normal")]
        scenario: ethercat_workbench::live::virtual_output::OutputRehearsalCase,
        /// Use the safe image and optional serial from this saved proposal.
        #[arg(long, requires = "plan_sha256")]
        plan: Option<PathBuf>,
        /// Review digest recorded independently of the proposal file.
        #[arg(long, requires = "plan")]
        plan_sha256: Option<String>,
        /// Save the review, including failed rehearsal outcomes, to a new JSON file.
        #[arg(long)]
        out: Option<PathBuf>,
    },
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
        /// Enable the read-only HTTP feed on 127.0.0.1 (0 chooses a free port). No device writes.
        #[arg(long)]
        http_port: Option<u16>,
        /// Enable publish-only MQTT on a local broker at 127.0.0.1:PORT.
        #[arg(long)]
        mqtt_port: Option<u16>,
        /// Enable a read-only Windows latest raw input snapshot under this name.
        #[arg(long)]
        shared_memory: Option<String>,
        /// Confirm approval for ESC initialization, SAFEOP and return to INIT on one isolated device.
        #[arg(long)]
        approve_esc_writes: bool,
    },
}

#[derive(Args)]
struct GroupDcArgs {
    /// Modeled SYNC0 period in nanoseconds.
    #[arg(long, default_value_t = 1_000_000)]
    period_ns: u32,
    /// Maximum absolute filtered follower time difference in nanoseconds.
    #[arg(long, default_value_t = 500)]
    difference_limit_ns: u32,
    /// Total modeled cycles. Topology-change defaults to eight and topology-reconnect to twelve.
    #[arg(
        long,
        default_value_t = 4,
        default_value_if("scenario", "topology-change", "8"),
        default_value_if("scenario", "topology-reconnect", "12")
    )]
    cycles: u32,
    #[arg(long, value_enum, default_value = "normal")]
    scenario: ethercat_workbench::input_group::clock_rehearsal::GroupClockCase,
}

impl From<GroupDcArgs> for ethercat_workbench::input_group::clock_rehearsal::Options {
    fn from(args: GroupDcArgs) -> Self {
        Self {
            period_ns: args.period_ns,
            difference_limit_ns: args.difference_limit_ns,
            cycles: args.cycles,
            scenario: args.scenario,
        }
    }
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

fn save_inspection(value: &impl Serialize, path: &std::path::Path) -> Result<()> {
    use std::io::Write;
    ensure!(
        path.extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("json")),
        "inspection output must end in .json"
    );
    let mut file = std::fs::File::create_new(path)
        .context("create new inspection output; existing paths are preserved")?;
    serde_json::to_writer_pretty(&mut file, value)?;
    writeln!(file)?;
    file.sync_all().context("flush inspection output")
}

fn inspection_export(value: &impl Serialize, path: Option<&std::path::Path>) -> Result<()> {
    if let Some(path) = path {
        save_inspection(value, path)?;
    }
    output(value)
}

fn shared_outputs(out: Option<&std::path::Path>, raw: Option<&std::path::Path>) -> Result<()> {
    for (path, extension) in [(out, "json"), (raw, "bin")] {
        if let Some(path) = path {
            ensure!(
                path.extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case(extension)),
                "output must end in .{extension}"
            );
            match std::fs::symlink_metadata(path) {
                Ok(_) => bail!("output path already exists: {}", path.display()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
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
        Command::CheckRuntime { out } => {
            shared_outputs(out.as_deref(), None)?;
            let report = ethercat_workbench::runtime_check::collect();
            inspection_export(&report, out.as_deref())
        }
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
        Command::InspectInputGroup {
            manifest,
            hex,
            wkc,
            frame,
            fmmu,
            sync_managers,
            pdo,
            out,
        } => {
            let group = ethercat_workbench::input_group::InputGroup::load(&manifest)?;
            let inspection = match (
                fmmu.as_deref(),
                sync_managers.as_deref(),
                pdo.as_deref(),
                frame.as_deref(),
            ) {
                (Some(fmmu), Some(sm), Some(pdo), frame) => {
                    group.inspect_pdo_file(fmmu, sm, pdo, frame)?
                }
                (Some(path), sm, None, frame) => group.inspect_mapping_files(path, sm, frame)?,
                (None, None, None, Some(path)) => group.inspect_frame_file(path)?,
                (None, None, None, None) => {
                    let payload = hex.as_deref().map(payload_hex).transpose()?;
                    group.inspect(payload.as_deref().zip(wkc))?
                }
                _ => bail!("TxPDO review requires FMMU and SyncManager evidence"),
            };
            inspection_export(&inspection, out.as_deref())
        }
        Command::InspectVirtualGroupMapping {
            manifest,
            scenario,
            read_pdos,
            out,
        } => {
            use ethercat_workbench::input_group::{InputGroup, preflight};
            shared_outputs(out.as_deref(), None)?;
            let group = InputGroup::load(&manifest)?;
            let report = preflight::inspect_virtual(&group, scenario, read_pdos)?;
            inspection_export(&report, out.as_deref())
        }
        Command::RehearseGroupDc {
            manifest,
            clock,
            out,
        } => {
            use ethercat_workbench::input_group::{InputGroup, clock_rehearsal};
            shared_outputs(out.as_deref(), None)?;
            let group = InputGroup::load(&manifest)?;
            let report = clock_rehearsal::run(&group, clock.into())?;
            inspection_export(&report, out.as_deref())
        }
        Command::GenerateGroupDcReplay {
            manifest,
            clock,
            out,
        } => {
            use ethercat_workbench::input_group::{InputGroup, clock_rehearsal};
            shared_outputs(Some(&out), None)?;
            let group = InputGroup::load(&manifest)?;
            let fixture = clock_rehearsal::generate_replay(&group, clock.into())?;
            inspection_export(&fixture, Some(&out))
        }
        Command::GenerateGroupReplay {
            manifest,
            scenario,
            read_pdos,
            out,
        } => {
            use ethercat_workbench::input_group::{InputGroup, replay};
            shared_outputs(Some(&out), None)?;
            let group = InputGroup::load(&manifest)?;
            let fixture = replay::generate_virtual(&group, scenario, read_pdos)?;
            inspection_export(&fixture, Some(&out))
        }
        Command::ReplayInputGroup {
            manifest,
            fixture,
            csv,
            on_change,
            rotate_rows,
            fmmu,
            sync_managers,
            pdo,
            out,
        } => {
            use ethercat_workbench::input_group::{InputGroup, replay};
            shared_outputs(out.as_deref(), None)?;
            let group = InputGroup::load(&manifest)?;
            let report = replay::run(
                &group,
                &fixture,
                replay::Options {
                    csv: &csv,
                    mode: if on_change {
                        LogMode::Change
                    } else {
                        LogMode::Every
                    },
                    rotate_rows,
                    fmmu: fmmu.as_deref(),
                    sync_managers: sync_managers.as_deref(),
                    pdo: pdo.as_deref(),
                },
            )?;
            inspection_export(&report, out.as_deref())?;
            if let Some(error) = report.error {
                bail!("{error}");
            }
            Ok(())
        }
        Command::VerifyGroupReplay {
            manifest,
            fixture,
            receipt,
            csv,
            fmmu,
            sync_managers,
            pdo,
            out,
        } => {
            use ethercat_workbench::input_group::{InputGroup, audit};
            let group = InputGroup::load(&manifest)?;
            let checked = audit::verify(
                &group,
                &fixture,
                &receipt,
                &csv,
                audit::Evidence {
                    fmmu: fmmu.as_deref(),
                    sync_managers: sync_managers.as_deref(),
                    pdo: pdo.as_deref(),
                },
            )?;
            inspection_export(&checked, out.as_deref())
        }
        Command::BundleGroupReplay {
            manifest,
            fixture,
            receipt,
            csv,
            fmmu,
            sync_managers,
            pdo,
            out,
        } => {
            use ethercat_workbench::input_group::{audit::Evidence, bundle};
            let sources = bundle::Sources {
                manifest: &manifest,
                fixture: &fixture,
                replay: &receipt,
                csv: &csv,
                evidence: Evidence {
                    fmmu: fmmu.as_deref(),
                    sync_managers: sync_managers.as_deref(),
                    pdo: pdo.as_deref(),
                },
            };
            output(&bundle::create(sources, &out)?)
        }
        Command::VerifyGroupBundle { directory, out } => {
            let result = ethercat_workbench::input_group::bundle::verify(&directory)?;
            inspection_export(&result, out.as_deref())
        }
        Command::ReadShared {
            name,
            profile,
            run_report,
            save_raw,
            out,
        } => {
            shared_outputs(out.as_deref(), save_raw.as_deref())?;
            let profile = ethercat_workbench::shared_memory::reader::load_decoding_profile(
                profile.as_deref(),
                run_report.as_deref(),
            )?;
            let capture =
                ethercat_workbench::shared_memory::reader::read_once(&name, profile.as_ref())?;
            if let Some(path) = save_raw {
                capture.save_raw(&path)?;
            }
            inspection_export(&capture.inspection, out.as_deref())
        }
        Command::InspectShared {
            file,
            profile,
            run_report,
            out,
        } => {
            shared_outputs(out.as_deref(), None)?;
            let profile = ethercat_workbench::shared_memory::reader::load_decoding_profile(
                profile.as_deref(),
                run_report.as_deref(),
            )?;
            let capture =
                ethercat_workbench::shared_memory::reader::inspect_file(&file, profile.as_ref())?;
            inspection_export(&capture.inspection, out.as_deref())
        }
        Command::InspectPcap {
            profile,
            file,
            station,
            preview,
            interface,
            out,
        } => {
            let report = ethercat_workbench::pcap_inspect::inspect_interface(
                &file,
                &Profile::load(&profile)?,
                u16::try_from(station).context("station address exceeds 16 bits")?,
                preview,
                interface,
            )?;
            if let Some(path) = out {
                use std::io::Write;
                ensure!(
                    path.extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("json")),
                    "inspection export path must end in .json"
                );
                let mut file = std::fs::File::create_new(&path)
                    .context("create new inspection export; existing paths are preserved")?;
                serde_json::to_writer_pretty(&mut file, &report)?;
                writeln!(file)?;
                file.sync_all().context("flush inspection export")?;
            }
            output(&report)
        }
        Command::CompareRuns {
            reports,
            csv,
            trial_set,
            bundle,
            out,
        } => {
            shared_outputs(out.as_deref(), None)?;
            if let Some(directory) = bundle {
                let result = ethercat_workbench::comparison_bundle::compare(
                    &directory,
                    None,
                    &AtomicBool::new(false),
                )?;
                return inspection_export(&result, out.as_deref());
            }
            if let Some(path) = trial_set {
                let set = TrialSet::load(&path)
                    .with_context(|| format!("load trial set {}", path.display()))?;
                let result = comparison_task(&set.trials, set.audit_csv)
                    .execute(&AtomicBool::new(false))
                    .with_context(|| format!("compare trial set {}", path.display()))?;
                return inspection_export(&result, out.as_deref());
            }
            let result = if csv.is_empty() {
                ethercat_workbench::benchmark::compare_files(&reports)?
            } else {
                ethercat_workbench::benchmark::compare_with_captures(&reports, &csv)?
            };
            inspection_export(&result, out.as_deref())
        }
        Command::VerifyCapture { report, csv } => {
            output(&ethercat_workbench::capture_audit::verify(&report, &csv)?)
        }
        Command::CheckComparison { file, base, out } => {
            shared_outputs(out.as_deref(), None)?;
            let checked = ethercat_workbench::comparison_files::check(
                &file,
                base.as_deref(),
                None,
                &AtomicBool::new(false),
            )?;
            inspection_export(&checked.report, out.as_deref())
        }
        Command::BundleComparison { file, base, out } => {
            output(&ethercat_workbench::comparison_bundle::create(
                &file,
                base.as_deref(),
                &out,
                &AtomicBool::new(false),
            )?)
        }
        Command::VerifyBundle { directory } => output(
            &ethercat_workbench::comparison_bundle::verify(&directory, &AtomicBool::new(false))?,
        ),
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
            identity,
            out,
            dc_mode,
            sync_unit_cycle_ns,
            tx_pdo,
            rx_pdo,
        } => {
            let devices = esi::load(&file)?;
            let selected = esi::select_device(&devices, device, identity.as_ref())?;
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
        Command::ReadVirtualModuleInventory {
            scenario,
            out,
            pdo_report,
        } => {
            shared_outputs(out.as_deref(), None)?;
            shared_outputs(pdo_report.as_deref(), None)?;
            if let (Some(inventory), Some(pdos)) = (&out, &pdo_report) {
                let absolute_destination = |path: &PathBuf| -> Result<PathBuf> {
                    let absolute = std::path::absolute(path)?;
                    let parent = absolute
                        .parent()
                        .context("output has no parent directory")?;
                    let name = absolute.file_name().context("output has no file name")?;
                    Ok(parent.canonicalize()?.join(name))
                };
                let inventory = absolute_destination(inventory)?;
                let pdos = absolute_destination(pdos)?;
                ensure!(
                    !inventory
                        .to_string_lossy()
                        .eq_ignore_ascii_case(&pdos.to_string_lossy()),
                    "inventory and PDO report require different output paths"
                );
            }
            let report =
                ethercat_workbench::live::virtual_inventory::read(scenario, pdo_report.is_some())?;
            if let Some(path) = out.as_deref() {
                save_inspection(&report.inventory, path)?;
            }
            if let (Some(path), Some(evidence)) = (pdo_report.as_deref(), &report.pdo_report) {
                save_inspection(evidence, path)?;
            }
            output(&report)
        }
        Command::PreviewRegisterPdos {
            file,
            device,
            identity,
            snapshot,
            fmmu,
            station,
            out,
        } => {
            let station = station
                .map(u16::try_from)
                .transpose()
                .context("FMMU station address exceeds 16 bits")?;
            let report = esi::register_pdos::preview(
                &file,
                device,
                identity.as_ref(),
                snapshot.as_deref(),
                fmmu.as_deref().zip(station),
            )?;
            inspection_export(&report, out.as_deref())
        }
        Command::PreviewPdoLayout {
            file,
            device,
            identity,
            expect_layout,
            run_report,
            out,
        } => {
            let report = esi::modular_preview::preview_device_layout(
                &file,
                device,
                identity.as_ref(),
                &expect_layout,
                run_report.as_deref(),
            )?;
            inspection_export(&report, out.as_deref())
        }
        Command::PreviewModularPdos {
            selection,
            expect_layout,
            run_report,
            tx_hex,
            rx_hex,
            out,
        } => {
            use ethercat_workbench::pdo_catalog::Direction;
            let mut report = selection.preview()?;
            if let Some(path) = &expect_layout {
                report.compose_expected_layout(path)?;
            }
            if let Some(path) = &run_report {
                report.compare_saved_run(path)?;
            }
            for (direction, hex) in [(Direction::Tx, tx_hex), (Direction::Rx, rx_hex)] {
                if let Some(hex) = hex {
                    report.decode_saved_payload(direction, &payload_hex(&hex)?)?;
                }
            }
            inspection_export(&report, out.as_deref())
        }
        Command::ExportModularProfile {
            selection,
            run_report,
            out,
        } => {
            let mut review = selection.preview()?;
            review.compare_saved_run(&run_report)?;
            let profile = review.offline_profile()?;
            profile.save(&out)?;
            output(&profile)
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
        Command::StageModePdos {
            profile,
            out,
            clear_staged_rx,
        } => {
            let mut profile = Profile::load(&profile)?;
            let plan = ethercat_workbench::mode_pdo_stage::prepare(&profile)?;
            if let Some(path) = out {
                plan.apply(&mut profile, clear_staged_rx)?;
                profile.save(&path)?;
            }
            output(plan.review())
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
        Command::InspectPdoReadback {
            profile,
            run_report,
            tx_hex,
            rx_hex,
            out,
        } => {
            let profile = Profile::load(&profile)?;
            let tx = tx_hex.as_deref().map(payload_hex).transpose()?;
            let rx = rx_hex.as_deref().map(payload_hex).transpose()?;
            let report = ethercat_workbench::pdo::inspect::inspect(
                &profile,
                &run_report,
                tx.as_deref(),
                rx.as_deref(),
            )?;
            inspection_export(&report, out.as_deref())
        }
        Command::ExportObservedPdoProfile {
            profile,
            run_report,
            tx_kind,
            rx_kind,
            out,
        } => {
            let baseline = Profile::load(&profile)?;
            let exported = ethercat_workbench::pdo::inspect::profile::build(
                &baseline,
                &run_report,
                &tx_kind,
                &rx_kind,
            )?;
            exported.save(&out)?;
            output(&exported)
        }
        Command::StageRx {
            profile,
            assignments,
            zero,
            out,
        } => {
            use ethercat_workbench::output_stage::{Assignment, prepare};
            let mut profile = Profile::load(&profile)?;
            let assignments = assignments
                .iter()
                .map(|value| Assignment::parse(value))
                .collect::<Result<Vec<_>>>()?;
            let plan = prepare(&profile, &assignments, zero)?;
            if let Some(path) = out {
                plan.apply(&mut profile)?;
                profile.save(&path)?;
            }
            output(plan.review())
        }
        Command::PlanOutput {
            profile,
            safe_hex,
            watchdog_us,
            max_op_us,
            stop_observation,
            serial,
            out,
        } => {
            use ethercat_workbench::output_plan::{StopPlan, prepare};
            shared_outputs(out.as_deref(), None)?;
            let profile = Profile::load(&profile)?;
            let review = prepare(
                &profile,
                StopPlan {
                    safe_rx_hex: safe_hex,
                    watchdog_us,
                    max_op_us,
                    stop_observation,
                    expected_serial: serial,
                },
            )?;
            inspection_export(&review, out.as_deref())
        }
        Command::VerifyOutputPlan {
            profile,
            plan,
            sha256,
        } => {
            let profile = Profile::load(&profile)?;
            output(&ethercat_workbench::output_plan::verify(
                &profile, &plan, &sha256,
            )?)
        }
        Command::RehearseDc {
            profile,
            period_ns,
            sync1_delay_ns,
            from_esi,
            start_delay_ns,
            cycles,
            scenario,
            out,
        } => {
            use ethercat_workbench::live::virtual_dc::{TimingRequest, run};
            shared_outputs(out.as_deref(), None)?;
            let profile = Profile::load(&profile)?;
            let timing = if from_esi {
                TimingRequest::StagedEsi
            } else {
                TimingRequest::Manual {
                    period_ns: period_ns.context("specify --period-ns or --from-esi")?,
                    sync1_delay_ns,
                }
            };
            let report = run(&profile, timing, start_delay_ns, cycles, scenario)?;
            inspection_export(&report, out.as_deref())?;
            if let Some(error) = report.error {
                bail!("{error}");
            }
            Ok(())
        }
        Command::RehearseOutput {
            profile,
            scenario,
            plan,
            plan_sha256,
            out,
        } => {
            shared_outputs(out.as_deref(), None)?;
            let profile = Profile::load(&profile)?;
            let review = plan
                .as_deref()
                .zip(plan_sha256.as_deref())
                .map(|(path, digest)| {
                    ethercat_workbench::output_plan::verify(&profile, path, digest)
                })
                .transpose()?;
            let report =
                ethercat_workbench::live::virtual_output::run(&profile, scenario, review.as_ref())?;
            inspection_export(&report, out.as_deref())?;
            if let Some(error) = report.error {
                bail!("{error}");
            }
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
            http_port,
            mqtt_port,
            shared_memory,
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
            let mut profile = Profile::load(&profile)?;
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
                    profile.require_native_scope()?;
                    ensure!(
                        !simulate_faults,
                        "--simulate-faults is for the synthetic backend"
                    );
                    Mode::SafeOp {
                        approved: BenchApproval::confirm(approve_esc_writes)?,
                    }
                }
            };
            if let Some(port) = http_port {
                profile.http.get_or_insert_with(Default::default).port = port;
            }
            if let Some(port) = mqtt_port {
                profile.mqtt.get_or_insert_with(Default::default).port = port;
            }
            if let Some(name) = shared_memory {
                profile
                    .shared_memory
                    .get_or_insert_with(Default::default)
                    .name = name;
            }
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

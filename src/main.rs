#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod gui_mode_pdo;
mod gui_review;
mod gui_stage;
mod gui_workspace;

use gui_workspace::{ConnectPage, MappingPage, Tab};

use clap::Parser;
use eframe::egui;
use ethercat_workbench::{
    esi::{self, Device},
    live::{self, Nic},
    model::{Field, Identity, Kind, LogMode, Profile, Scheduler, Source, payload_hex},
    pdo_catalog::{self, Assignment, Definition, Direction, Selection},
    run::{self, BenchApproval, DeviceInfo, Mode, Report, RunOptions, Snapshot},
};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering::Relaxed},
    },
    thread::JoinHandle,
    time::Duration,
};

#[derive(Parser)]
#[command(version, about = "EtherCAT MainDevice bench workbench")]
struct Args {
    #[arg(long)]
    profile: Option<PathBuf>,
    #[arg(long)]
    csv: Option<PathBuf>,
    /// Launch a bounded synthetic run from the GUI and close after flushing.
    #[arg(long, requires = "profile")]
    simulate_seconds: Option<u64>,
    #[arg(long, requires = "simulate_seconds")]
    report: Option<PathBuf>,
}

fn main() -> eframe::Result {
    let args = Args::parse();
    eframe::run_native(
        "EtherCAT Workbench",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1100.0, 840.0])
                .with_min_inner_size([820.0, 560.0]),
            ..Default::default()
        },
        Box::new(|_| Ok(Box::new(App::new(args)))),
    )
}

struct Session {
    stop: Arc<AtomicBool>,
    view: Arc<Mutex<Snapshot>>,
    worker: JoinHandle<Report>,
}

struct App {
    profile: Profile,
    profile_path: String,
    esi_path: String,
    esi: Vec<Device>,
    esi_selected: usize,
    esi_pdo_draft: Option<(usize, Selection)>,
    profile_pdo_draft: Option<Selection>,
    nics: Vec<Nic>,
    discovery: Vec<DeviceInfo>,
    scan: Option<JoinHandle<anyhow::Result<Vec<DeviceInfo>>>>,
    csv: String,
    offline_hex: String,
    replay_path: String,
    virtual_model: ethercat_workbench::virtual_esc::VirtualModel,
    seconds: u64,
    approved: bool,
    generation: u64,
    session: Option<Session>,
    last: Option<Snapshot>,
    message: String,
    auto_start: bool,
    auto_exit: bool,
    report_path: Option<PathBuf>,
    report_save: String,
    deferred_close: bool,
    review: gui_review::Panel,
    stage: gui_stage::Panel,
    mode_pdos: gui_mode_pdo::Panel,
    tab: Tab,
    mapping_page: MappingPage,
    connect_page: ConnectPage,
    profiles_open: bool,
    connect_open: bool,
    decoder_open: bool,
}

impl App {
    fn new(args: Args) -> Self {
        let mut app = Self {
            profile: Profile::default(),
            profile_path: String::new(),
            esi_path: String::new(),
            esi: Vec::new(),
            esi_selected: 0,
            esi_pdo_draft: None,
            profile_pdo_draft: None,
            nics: Vec::new(),
            discovery: Vec::new(),
            scan: None,
            csv: args
                .csv
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            offline_hex: String::new(),
            replay_path: String::new(),
            virtual_model: ethercat_workbench::virtual_esc::VirtualModel::Coe,
            seconds: args.simulate_seconds.unwrap_or(10),
            approved: false,
            generation: 0,
            session: None,
            last: None,
            message: String::new(),
            auto_start: args.simulate_seconds.is_some(),
            auto_exit: args.simulate_seconds.is_some(),
            report_path: args.report,
            report_save: String::new(),
            deferred_close: false,
            review: gui_review::Panel::default(),
            stage: gui_stage::Panel::default(),
            mode_pdos: gui_mode_pdo::Panel::default(),
            tab: Tab::default(),
            mapping_page: MappingPage::default(),
            connect_page: ConnectPage::default(),
            profiles_open: false,
            connect_open: false,
            decoder_open: false,
        };
        if let Some(path) = args.profile {
            app.profile_path = path.to_string_lossy().into_owned();
            app.load();
        }
        app
    }

    fn load(&mut self) {
        match Profile::load(Path::new(&self.profile_path)) {
            Ok(profile) => {
                self.profile = profile;
                self.profile_pdo_draft = None;
                self.stage = gui_stage::Panel::default();
                self.mode_pdos = gui_mode_pdo::Panel::default();
                self.approved = false;
                self.last = None;
                self.message = "Profile loaded".into();
            }
            Err(error) => self.message = format!("{error:#}"),
        }
    }

    fn start(&mut self, mode: Mode) {
        if self.busy() {
            self.message =
                "Wait for or stop the active session, discovery or saved-file review before starting".into();
            return;
        }
        self.approved = false;
        self.generation += 1;
        let stop = Arc::new(AtomicBool::new(false));
        let view = Arc::new(Mutex::new(Snapshot::default()));
        let csv = (!self.csv.trim().is_empty()).then(|| PathBuf::from(self.csv.trim()));
        let opts = RunOptions {
            frontend: ethercat_workbench::benchmark::Frontend::Gui,
            mode,
            csv,
            duration: Duration::from_secs(self.seconds),
            generation: self.generation,
        };
        match run::spawn(self.profile.clone(), opts, stop.clone(), view.clone()) {
            Ok(worker) => {
                self.last = None;
                self.message.clear();
                self.session = Some(Session { stop, view, worker });
                self.tab = Tab::Inputs;
                self.connect_open = false;
            }
            Err(error) => self.message = format!("{error:#}"),
        }
    }

    fn refresh(&mut self, ctx: &egui::Context) {
        self.review.refresh(ctx);
        if self
            .scan
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
        {
            match self.scan.take().expect("finished scan").join() {
                Ok(Ok(devices)) => {
                    self.discovery = devices;
                    self.message = "Discovery complete. ESC diagnostics are snapshots; device identity requires approved SII access.".into();
                }
                Ok(Err(error)) => self.message = format!("{error:#}"),
                Err(_) => self.message = "Read-only scan worker failed".into(),
            }
        }
        if let Some(session) = &self.session
            && let Ok(view) = session.view.try_lock()
        {
            self.last = Some(view.clone());
        }
        if self
            .session
            .as_ref()
            .is_some_and(|s| s.worker.is_finished())
        {
            let session = self.session.take().expect("finished session");
            match session.worker.join() {
                Ok(report) => {
                    self.last = session.view.lock().ok().map(|view| view.clone());
                    if let Some(path) = &self.report_path
                        && let Err(error) = write_report(path, &report)
                    {
                        self.message = format!("Write run report: {error:#}");
                        self.auto_exit = false;
                    }
                }
                Err(_) => self.message = "Cycle worker failed".into(),
            }
            if self.auto_exit || self.deferred_close {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
        if self.session.is_some() || self.scan.is_some() {
            ctx.request_repaint_after(Duration::from_millis(80));
        }
    }

    fn profile_file_controls(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label("Profile JSON");
            ui.add(egui::TextEdit::singleline(&mut self.profile_path).desired_width(410.0));
            if ui.button("Load").clicked() {
                self.load();
            }
            if ui.button("Save new").clicked() {
                self.message = match self.profile.save(Path::new(&self.profile_path)) {
                    Ok(()) => "Profile saved".into(),
                    Err(error) => format!("{error:#}"),
                };
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("Name");
            ui.text_edit_singleline(&mut self.profile.name);
        });
    }

    fn device_controls(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label("ESI XML");
            ui.add(egui::TextEdit::singleline(&mut self.esi_path).desired_width(430.0));
            if ui.button("Read devices").clicked() {
                match esi::load(Path::new(&self.esi_path)) {
                    Ok(devices) => {
                        self.esi = devices;
                        self.esi_selected = 0;
                        self.esi_pdo_draft = None;
                        self.message.clear();
                    }
                    Err(error) => {
                        self.esi.clear();
                        self.message = format!("{error:#}");
                    }
                }
            }
        });
        if let Some(selected) = self.esi.get(self.esi_selected) {
            let selected_label =
                format!("{} · {}", selected.source.device, selected.source.identity);
            ui.horizontal_wrapped(|ui| {
                egui::ComboBox::from_id_salt("esi_device")
                    .width(560.0)
                    .truncate()
                    .selected_text(selected_label)
                    .show_ui(ui, |ui| {
                        for (i, device) in self.esi.iter().enumerate() {
                            ui.selectable_value(
                                &mut self.esi_selected,
                                i,
                                format!("{} · {}", device.source.device, device.source.identity),
                            );
                        }
                    });
            });
            let device = &self.esi[self.esi_selected];
            let (index, draft) = self.esi_pdo_draft.get_or_insert_with(|| {
                (
                    self.esi_selected,
                    pdo_catalog::defaults(&device.source.pdo_catalog),
                )
            });
            if *index != self.esi_selected {
                *index = self.esi_selected;
                *draft = pdo_catalog::defaults(&device.source.pdo_catalog);
            }
            ui.push_id("loaded_pdos", |ui| {
                ui.collapsing("ESI PDO candidates and offline choices", |ui| {
                    pdo_choices(ui, &device.source.pdo_catalog, draft)
                });
            });
            if ui
                .button("Build profile from selected ESI PDO choices")
                .clicked()
            {
                match device.apply_selection(&mut self.profile, draft.clone()) {
                    Ok(()) => {
                        self.profile_pdo_draft = None;
                        self.approved = false;
                        self.last = None;
                        self.message.clear();
                    }
                    Err(error) => self.message = error.to_string(),
                }
            }
            for note in &self.esi[self.esi_selected].notes {
                ui.small(note);
            }
        }
        if let Some(source) = &self.profile.esi {
            ui.small(format!(
                "ESI baseline · {} · {} · SHA-256 {}",
                source.file_name, source.identity, source.sha256
            ));
        }
        if let Some(source) = &self.profile.esi {
            for note in &source.notes {
                ui.small(note);
            }
            if let (Some(tx), Some(rx)) = (source.default_tx_bytes, source.default_rx_bytes) {
                let provenance = if (tx, rx) == (self.profile.tx_bytes, self.profile.rx_bytes) {
                    "ESI"
                } else {
                    "Override"
                };
                ui.small(format!(
                    "Image lengths · {provenance} · ESI Tx {tx} / Rx {rx} bytes"
                ));
            }
        }
    }

    fn catalog_controls(&mut self, ui: &mut egui::Ui) {
        if self
            .profile
            .esi
            .as_ref()
            .is_some_and(|s| !s.pdo_catalog.is_empty())
        {
            ui.push_id("profile_pdos", |ui| {
                ui.collapsing("Saved profile PDO catalog and offline choices", |ui| {
                    let catalog = &self
                        .profile
                        .esi
                        .as_ref()
                        .expect("catalog present")
                        .pdo_catalog;
                    let draft = self.profile_pdo_draft.get_or_insert_with(|| {
                        self.profile
                            .esi_pdo_selection
                            .clone()
                            .unwrap_or_else(|| pdo_catalog::defaults(catalog))
                    });
                    pdo_choices(ui, catalog, draft);
                    if ui
                        .button("Rebuild offline fields from these choices")
                        .clicked()
                    {
                        match pdo_catalog::apply(&mut self.profile, draft.clone()) {
                            Ok(()) => {
                                self.approved = false;
                                self.last = None;
                                self.message.clear();
                            }
                            Err(error) => self.message = error.to_string(),
                        }
                    }
                    if ui
                        .button("Detach selection and keep editable fields")
                        .clicked()
                    {
                        self.profile.esi_pdo_selection = None;
                        self.message =
                            "ESI selection detached; editable field checks remain active".into();
                        for field in self.profile.tx.iter_mut().chain(&mut self.profile.rx) {
                            if field.source == Source::Esi {
                                field.source = Source::Override;
                            }
                        }
                    }
                });
            });
        }
    }

    fn sync_controls(&mut self, ui: &mut egui::Ui) {
        if let Some(esi) = &self.profile.esi
            && !esi.dc_modes.is_empty()
        {
            ui.label("ESI DC mode review (staged; runtime requests disabled SYNC)");
            let selected = self
                .profile
                .staged_esi_dc_mode
                .and_then(|i| esi.dc_modes.get(i))
                .map_or("None selected", |m| m.name.as_str());
            egui::ComboBox::from_id_salt("staged_dc_mode")
                .selected_text(selected)
                .show_ui(ui, |ui| {
                    if ui
                        .selectable_value(
                            &mut self.profile.staged_esi_dc_mode,
                            None,
                            "None selected",
                        )
                        .clicked()
                    {
                        self.profile.sync_unit_cycle_ns = None;
                    }
                    for (index, mode) in esi.dc_modes.iter().enumerate() {
                        ui.selectable_value(
                            &mut self.profile.staged_esi_dc_mode,
                            Some(index),
                            format!("{index}: {}", mode.name),
                        );
                    }
                });
            if self.profile.staged_esi_dc_mode.is_some() {
                ui.horizontal_wrapped(|ui| {
                    ui.label("Manual sync-unit assumption ns (0 = unspecified)");
                    let mut value = self.profile.sync_unit_cycle_ns.unwrap_or(0);
                    if ui.add(egui::DragValue::new(&mut value)).changed() {
                        self.profile.sync_unit_cycle_ns = (value != 0).then_some(value);
                    }
                });
                match ethercat_workbench::sync_review::review(&self.profile, None) {
                    Ok(Some(review)) => {
                        ui.collapsing("Staged ESI timing details", |ui| {
                            ui.monospace(serde_json::to_string_pretty(&review).unwrap_or_default());
                        });
                    }
                    Err(error) => {
                        ui.colored_label(egui::Color32::LIGHT_RED, error.to_string());
                    }
                    _ => {}
                }
            }
        }
        let blocked = self.session.is_some() || self.scan.is_some() || self.review.is_running();
        if self.mode_pdos.draw(ui, &mut self.profile, blocked) {
            self.profile_pdo_draft = None;
            self.stage = gui_stage::Panel::default();
            self.approved = false;
            self.last = None;
            self.message =
                "Mode PDO candidate applied offline. Save new to retain the profile.".into();
        }
    }

    fn identity_controls(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            if let Some(identity) = &mut self.profile.expected_identity {
                ui.label("Expected identity (vendor / product / revision)");
                for value in [
                    &mut identity.vendor,
                    &mut identity.product,
                    &mut identity.revision,
                ] {
                    ui.add(
                        egui::DragValue::new(value)
                            .hexadecimal(8, false, true)
                            .prefix("0x"),
                    );
                }
                let source = match &self.profile.esi {
                    Some(source) if &source.identity == identity => "ESI",
                    Some(_) => "Override",
                    None => "Manual",
                };
                ui.small(source);
                if ui.button("Clear").clicked() {
                    self.profile.expected_identity = None;
                }
            } else if ui.button("Set manual identity").clicked() {
                self.profile.expected_identity = Some(Identity::default());
            }
        });
    }

    fn integration_controls(&mut self, ui: &mut egui::Ui) {
        let mut memory_enabled = self.profile.shared_memory.is_some();
        if ui
            .checkbox(&mut memory_enabled, "Enable Windows shared-memory input")
            .changed()
        {
            self.profile.shared_memory = memory_enabled.then(Default::default);
        }
        if let Some(config) = &mut self.profile.shared_memory {
            ui.horizontal_wrapped(|ui| {
                ui.label("Local snapshot name");
                ui.text_edit_singleline(&mut config.name);
                ui.label("Publish ms");
                ui.add(egui::DragValue::new(&mut config.period_ms).range(1..=60000));
                ui.label("Freshness ms");
                ui.add(egui::DragValue::new(&mut config.freshness_ms).range(1..=60000));
                ui.label("Queue");
                ui.add(egui::DragValue::new(&mut config.queue_capacity).range(1..=8192));
            });
            ui.small("Latest raw input/status; a reader holding the mutex causes skipped publications, without waiting on cyclic I/O.");
        }
        let mut mqtt_enabled = self.profile.mqtt.is_some();
        if ui
            .checkbox(&mut mqtt_enabled, "Enable read-only MQTT input publisher")
            .changed()
        {
            self.profile.mqtt = mqtt_enabled.then(Default::default);
        }
        if let Some(config) = &mut self.profile.mqtt {
            ui.horizontal_wrapped(|ui| {
                ui.label("Local broker 127.0.0.1 port");
                ui.add(egui::DragValue::new(&mut config.port).range(1..=65535));
                ui.label("Topic");
                ui.text_edit_singleline(&mut config.topic);
            });
            ui.horizontal_wrapped(|ui| {
                ui.label("Publish ms");
                ui.add(egui::DragValue::new(&mut config.period_ms).range(1..=60000));
                ui.label("Freshness ms");
                ui.add(egui::DragValue::new(&mut config.freshness_ms).range(1..=60000));
                ui.label("MQTT queue");
                ui.add(egui::DragValue::new(&mut config.queue_capacity).range(1..=8192));
            });
            ui.small("Latest input/status to a trusted local broker. QoS 0, non-retained; TCP writes do not prove consumer delivery.");
        }
        let mut enabled = self.profile.http.is_some();
        if ui
            .checkbox(&mut enabled, "Enable read-only local HTTP input feed")
            .changed()
        {
            self.profile.http = enabled.then(Default::default);
        }
        if let Some(config) = &mut self.profile.http {
            ui.horizontal_wrapped(|ui| {
                ui.label("127.0.0.1 port (0 = automatic)");
                ui.add(egui::DragValue::new(&mut config.port).range(0..=65535));
                ui.label("Freshness ms");
                ui.add(egui::DragValue::new(&mut config.freshness_ms).range(1..=60000));
            });
            ui.horizontal_wrapped(|ui| {
                ui.label("Feed queue");
                ui.add(egui::DragValue::new(&mut config.queue_capacity).range(1..=8192));
                ui.label("HTTP history");
                ui.add(egui::DragValue::new(&mut config.history_capacity).range(1..=4096));
            });
            ui.small("Read-only input/status; any local process can connect. Network/JSON work is outside cyclic I/O.");
        }
    }

    fn nic_controls(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            if ui.button("Refresh NICs").clicked() {
                match live::nics() {
                    Ok(nics) => {
                        self.nics = nics;
                        self.message.clear();
                    }
                    Err(error) => {
                        self.nics.clear();
                        self.message = format!("{error:#}");
                    }
                }
            }
            egui::ComboBox::from_id_salt("nic")
                .width(420.0)
                .truncate()
                .selected_text(if self.profile.nic.is_empty() {
                    "Select isolated NIC"
                } else {
                    &self.profile.nic
                })
                .show_ui(ui, |ui| {
                    for nic in &self.nics {
                        let label = format!("{} · {}", nic.description, nic.id);
                        if ui
                            .selectable_value(&mut self.profile.nic, nic.id.clone(), label)
                            .changed()
                        {
                            self.discovery.clear();
                            self.approved = false;
                        }
                    }
                });
            if ui
                .add_enabled(
                    !self.profile.nic.is_empty() && self.scan.is_none(),
                    egui::Button::new("Read-only scan"),
                )
                .clicked()
            {
                let nic = self.profile.nic.clone();
                self.discovery.clear();
                self.scan = Some(std::thread::spawn(move || live::scan(&nic)));
            }
        });
        for device in &self.discovery {
            device_info(ui, device);
        }
    }

    fn timing_controls(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label("Cycle µs");
            ui.add(
                egui::DragValue::new(&mut self.profile.requested_cycle_us).range(250..=1_000_000),
            );
            ui.label("Input loss timeout ms (0 = monitor only)");
            ui.add(egui::DragValue::new(&mut self.profile.input_loss_timeout_ms).range(0..=60_000));
            ui.selectable_value(&mut self.profile.scheduler, Scheduler::Deadline, "Deadline");
            ui.selectable_value(
                &mut self.profile.scheduler,
                Scheduler::Relative,
                "Stock relative",
            );
        });
    }

    fn logging_controls(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label("Duration s");
            ui.add(egui::DragValue::new(&mut self.seconds).range(1..=86_400));
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("New CSV path");
            ui.add(
                egui::TextEdit::singleline(&mut self.csv)
                    .hint_text(".local/capture.csv")
                    .desired_width(420.0),
            );
            ui.selectable_value(
                &mut self.profile.mode,
                LogMode::Every,
                "Every valid exchange",
            );
            ui.selectable_value(&mut self.profile.mode, LogMode::Change, "On change");
        });
        ui.collapsing("Buffer sizing and rotation", |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label("Queue samples");
                ui.add(egui::DragValue::new(&mut self.profile.queue_capacity).range(1..=65_536));
                ui.label("Rotate rows (0 = one file)");
                ui.add(egui::DragValue::new(&mut self.profile.rotate_rows));
            });
        });
    }

    fn offline_connection_controls(&mut self, ui: &mut egui::Ui) {
        if ui.button("Start synthetic fixture").clicked() {
            self.start(Mode::Simulate { faults: false });
        }
        egui::ComboBox::from_id_salt("virtual_model")
            .selected_text(format!("{:?}", self.virtual_model))
            .show_ui(ui, |ui| {
                ui.selectable_value(
                    &mut self.virtual_model,
                    ethercat_workbench::virtual_esc::VirtualModel::Coe,
                    "CoE virtual device",
                );
                ui.selectable_value(
                    &mut self.virtual_model,
                    ethercat_workbench::virtual_esc::VirtualModel::Sii,
                    "SII virtual device",
                );
                ui.selectable_value(
                    &mut self.virtual_model,
                    ethercat_workbench::virtual_esc::VirtualModel::CoeDc,
                    "CoE / DC virtual device",
                );
                ui.selectable_value(
                    &mut self.virtual_model,
                    ethercat_workbench::virtual_esc::VirtualModel::CoeNormal,
                    "CoE normal readback",
                );
                ui.selectable_value(
                    &mut self.virtual_model,
                    ethercat_workbench::virtual_esc::VirtualModel::CoeSegmented,
                    "CoE segmented readback",
                );
            });
        if ui
            .add_enabled(
                self.scan.is_none(),
                egui::Button::new("Preview virtual discovery"),
            )
            .clicked()
        {
            let model = self.virtual_model;
            self.discovery.clear();
            self.scan = Some(std::thread::spawn(move || {
                let report =
                    live::scan_virtual(model, ethercat_workbench::virtual_esc::ScanCase::Normal);
                if let Some(error) = report.error {
                    anyhow::bail!("{error}");
                }
                Ok(report.devices)
            }));
        }
        if ui.button("Start virtual EtherCAT controller").clicked() {
            self.start(Mode::Virtual {
                model: self.virtual_model,
                fault: ethercat_workbench::virtual_esc::VirtualFault::None,
            });
        }
        ui.horizontal_wrapped(|ui| {
            ui.label("Offline frame fixture");
            ui.add(
                egui::TextEdit::singleline(&mut self.replay_path)
                    .hint_text("samples/synthetic-replay.json")
                    .desired_width(350.0),
            );
            if ui
                .add_enabled(
                    !self.replay_path.trim().is_empty(),
                    egui::Button::new("Replay frames"),
                )
                .clicked()
            {
                self.start(Mode::Replay {
                    fixture: PathBuf::from(self.replay_path.trim()),
                });
            }
        });
    }

    fn live_connection_controls(&mut self, ui: &mut egui::Ui) {
        ui.checkbox(
            &mut self.approved,
            "Approved: isolated one-device bench, ESC setup writes, SAFEOP and INIT on stop",
        );
        if ui
            .add_enabled(
                self.approved && !self.profile.nic.is_empty() && self.scan.is_none(),
                egui::Button::new("Start live SAFEOP inputs"),
            )
            .clicked()
        {
            match BenchApproval::confirm(self.approved) {
                Ok(approved) => self.start(Mode::SafeOp { approved }),
                Err(error) => self.message = format!("{error:#}"),
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.auto_start {
            self.auto_start = false;
            self.start(Mode::Simulate { faults: false });
        }
        if ctx.input(|input| input.viewport().close_requested()) {
            self.review.cancel();
        }
        if ctx.input(|input| input.viewport().close_requested())
            && let Some(session) = &self.session
        {
            session.stop.store(true, Relaxed);
            self.deferred_close = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
        self.refresh(ctx);
        self.show_workspace(ctx);
    }
}

fn pdo_choices(ui: &mut egui::Ui, catalog: &[Definition], selection: &mut Selection) {
    ui.label(
        "Offline expectation only. Rebuilding fields sends no PDO assignment or output writes.",
    );
    if ui.button("Reset choices to ESI defaults").clicked() {
        *selection = pdo_catalog::defaults(catalog);
    }
    egui::ScrollArea::vertical()
        .max_height(240.0)
        .show(ui, |ui| {
            for direction in [Direction::Tx, Direction::Rx] {
                ui.strong(format!("{direction:?}PDO choices"));
                for pdo in catalog.iter().filter(|p| p.direction == direction) {
                    let assignments = selection.assignments_mut(direction);
                    let mut selected = assignments.iter().any(|a| a.index == pdo.index);
                    ui.horizontal(|ui| {
                        let label = format!(
                            "{:#06x} {} | ESI SM {:?} | mandatory {} | fixed {}",
                            pdo.index, pdo.name, pdo.default_sm, pdo.mandatory, pdo.fixed
                        );
                        if ui.checkbox(&mut selected, label).changed() {
                            if selected {
                                assignments.push(Assignment {
                                    index: pdo.index,
                                    sm: pdo.default_sm.unwrap_or(if direction == Direction::Tx {
                                        3
                                    } else {
                                        2
                                    }),
                                });
                            } else {
                                assignments.retain(|a| a.index != pdo.index);
                            }
                        }
                        if let Some(position) =
                            assignments.iter().position(|a| a.index == pdo.index)
                        {
                            ui.label("Chosen SM");
                            ui.add(
                                egui::DragValue::new(&mut assignments[position].sm).range(0..=15),
                            );
                            let sm = assignments[position].sm;
                            if ui.small_button("Up").clicked()
                                && let Some(other) =
                                    (0..position).rev().find(|i| assignments[*i].sm == sm)
                            {
                                assignments.swap(position, other);
                            }
                            if ui.small_button("Down").clicked()
                                && let Some(other) = (position + 1..assignments.len())
                                    .find(|i| assignments[*i].sm == sm)
                            {
                                assignments.swap(position, other);
                            }
                        }
                    });
                    for note in &pdo.notes {
                        ui.small(note);
                    }
                }
                ui.small(format!(
                    "Chosen order within each SM: {}",
                    selection
                        .assignments(direction)
                        .iter()
                        .map(|a| format!("{:#06x}@{}", a.index, a.sm))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        });
    match pdo_catalog::build(catalog, selection) {
        Ok(built) => {
            ui.label(format!(
                "Offline image: Tx {} / Rx {} bytes; raw entries and padding preserved",
                built.tx_bytes, built.rx_bytes
            ));
        }
        Err(error) => {
            ui.colored_label(egui::Color32::LIGHT_RED, error.to_string());
        }
    }
}

fn fields(ui: &mut egui::Ui, title: &str, len: &mut usize, fields: &mut Vec<Field>) {
    ui.push_id(title, |ui| {
        ui.horizontal(|ui| {
            ui.strong(title);
            ui.label("Bytes");
            ui.add(egui::DragValue::new(len).range(0..=1024));
            if ui
                .add_enabled(fields.len() < 128, egui::Button::new("Add field"))
                .clicked()
            {
                fields.push(Field {
                    name: format!("Field {}", fields.len() + 1),
                    log: title == "TxPDO inputs",
                    ..Field::default()
                });
            }
        });
        let mut remove = None;
        egui::Grid::new("mappings").striped(true).show(ui, |ui| {
            for label in [
                "Field",
                "Bit",
                "Width",
                "Type",
                "BE",
                "Swap bytes",
                "Reverse words",
                "Log",
                "Source",
                "",
            ] {
                ui.strong(label);
            }
            ui.end_row();
            for (i, field) in fields.iter_mut().enumerate() {
                ui.push_id(i, |ui| {
                    let mut edited = ui
                        .add(egui::TextEdit::singleline(&mut field.name).desired_width(140.0))
                        .changed();
                    edited |= ui
                        .add(egui::DragValue::new(&mut field.bit).range(0..=8191))
                        .changed();
                    edited |= ui
                        .add(egui::DragValue::new(&mut field.width).range(1..=8192))
                        .changed();
                    let before = field.kind;
                    egui::ComboBox::from_id_salt("kind")
                        .selected_text(format!("{:?}", field.kind))
                        .show_ui(ui, |ui| {
                            for kind in [
                                Kind::Unsigned,
                                Kind::Signed,
                                Kind::Bool,
                                Kind::F32,
                                Kind::F64,
                                Kind::Raw,
                            ] {
                                ui.selectable_value(&mut field.kind, kind, format!("{kind:?}"));
                            }
                        });
                    edited |= before != field.kind;
                    edited |= ui.checkbox(&mut field.big_endian, "").changed();
                    edited |= ui.checkbox(&mut field.swap_bytes_in_words, "").changed();
                    edited |= ui.checkbox(&mut field.reverse_words, "").changed();
                    if title == "TxPDO inputs" {
                        ui.checkbox(&mut field.log, "");
                    } else {
                        ui.label("—");
                    }
                    if edited && field.source == Source::Esi {
                        field.source = Source::Override;
                    }
                    ui.label(format!("{:?}", field.source))
                        .on_hover_text(format!(
                            "PDO {:?}, object {:?}:{:?}",
                            field.pdo_index, field.object_index, field.subindex
                        ));
                    if ui.small_button("Remove").clicked() {
                        remove = Some(i);
                    }
                });
                ui.end_row();
            }
        });
        if let Some(i) = remove {
            fields.remove(i);
        }
    });
}

fn decode(ui: &mut egui::Ui, hex: &str, len: usize, fields: &[Field]) {
    if hex.trim().is_empty() {
        return;
    }
    match payload_hex(hex) {
        Ok(bytes) if bytes.len() == len => show_values(ui, &bytes, fields),
        Ok(bytes) => {
            ui.label(format!("Expected {len} bytes, got {}", bytes.len()));
        }
        Err(error) => {
            ui.label(format!("{error:#}"));
        }
    }
}

fn show_values(ui: &mut egui::Ui, bytes: &[u8], fields: &[Field]) {
    for field in fields {
        let value = field.decode(bytes).unwrap_or_else(|| "out of range".into());
        ui.monospace(format!("{}  {}", field.name, value));
    }
}

fn device_info(ui: &mut egui::Ui, device: &DeviceInfo) {
    let al = ethercat_workbench::esc::al_status(device.al_status, device.al_code);
    ui.label(format!("Bus position {} · station {:#06x} · alias {:#06x} · discovery links {:?} · {} / AL {:#06x} code {:#06x}",
        device.position, device.station_address, device.alias, device.link_ports, al.state, device.al_status, device.al_code));
    if al.error || al.code != 0 {
        ui.colored_label(
            egui::Color32::LIGHT_RED,
            format!("AL error flag {} · {}", al.error, al.description),
        );
    }
    if let Some(diagnostics) = &device.diagnostics {
        ui.push_id((device.position, &diagnostics.snapshot.started_utc), |ui| {
            ui.collapsing(
                "ESC discovery snapshot (not refreshed during cyclic input)",
                |ui| show_esc(ui, diagnostics),
            );
        });
    }
    if let Some(identity) = &device.identity {
        ui.label(format!(
            "Bus identity · {} · {} · serial {:?} · Tx/Rx bytes {:?}/{:?} · DC {:?}",
            device.name.as_deref().unwrap_or(""),
            identity,
            device.serial,
            device.tx_bytes,
            device.rx_bytes,
            device.dc_support
        ));
    }
    if let Some(name) = &device.coe_name {
        ui.label(format!(
            "CoE 0x1008 name · {}",
            name.value
                .as_deref()
                .unwrap_or_else(|| name.unavailable.as_deref().unwrap_or("unavailable"))
        ));
    }
}

fn show_esc(ui: &mut egui::Ui, diagnostics: &ethercat_workbench::esc::Diagnosis) {
    let raw = &diagnostics.snapshot;
    let dl = &diagnostics.data_link;
    ui.label(format!(
        "{:?} · started {} · sequential reads {} µs",
        raw.source, raw.started_utc, raw.elapsed_us
    ));
    ui.label(format!(
        "DL {:#06x} · PDI operational {} · watchdog OK {} · extended link flag {}",
        dl.raw, dl.pdi_operational, dl.watchdog_ok, dl.extended_link_detection
    ));
    ui.label(format!(
        "Snapshot AL {:#06x} · {} · error flag {} · code {:#06x}: {}",
        raw.al_status,
        diagnostics.al.state,
        diagnostics.al.error,
        raw.al_code,
        diagnostics.al.description
    ));
    for port in &dl.ports {
        ui.label(format!(
            "ESC port {} · link {} · loop {} · signal {}",
            port.number,
            port.physical_link,
            if port.loop_closed { "closed" } else { "open" },
            port.signal_detected
        ));
    }
    if let Some(info) = &diagnostics.information {
        ui.label(format!("ESC type {:#04x} · revision {} · build {:#06x} · FMMUs {} · SMs {} · RAM {} KiB · features {:#06x}",
            info.controller_type,info.revision,info.build,info.fmmus,info.sync_managers,info.ram_kib,info.feature_bits));
        ui.label(format!(
            "Port descriptors 0–3 · {}",
            info.port_types.join(", ")
        ));
    }
    if let Some(counters) = &diagnostics.counters {
        for port in &counters.ports {
            ui.label(format!(
                "Port {} counters · invalid {} · RX {} · forwarded {} · lost link {}",
                port.number,
                port.invalid_frames,
                port.rx_errors,
                port.forwarded_errors,
                port.lost_links
            ));
        }
        ui.label(format!(
            "Processing errors {} · PDI errors {} · controller-specific PDI code {:#06x}",
            counters.processing_errors, counters.pdi_errors, counters.pdi_error_code
        ));
        if !counters.at_byte_maximum.is_empty() {
            ui.label(format!(
                "Counters at 255 · {}",
                counters.at_byte_maximum.join(", ")
            ));
        }
    }
    for note in &diagnostics.notes {
        ui.label(note);
    }
}

fn write_report(path: &Path, report: &Report) -> anyhow::Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create_new(path)?;
    serde_json::to_writer_pretty(&mut file, report)?;
    writeln!(file)?;
    file.sync_all()?;
    Ok(())
}

fn show_snapshot(ui: &mut egui::Ui, snapshot: &Snapshot, fields: &[Field]) {
    let r = &snapshot.report;
    if let Some(memory) = &r.shared_memory {
        ui.label(format!("Shared memory {} · active {} · offered {} · queue drops {} · coalesced {} · unsent {} · writes {} · busy {} · abandoned {} · worker failed {}",memory.mapping,memory.active,memory.offered,memory.queue_drops,memory.coalesced,memory.unsent_events,memory.writes,memory.lock_misses,memory.abandoned_recoveries,memory.worker_failed));
        if let Some(error) = &memory.worker_error {
            ui.colored_label(egui::Color32::LIGHT_RED, format!("Shared memory: {error}"));
        }
    }
    if let Some(mqtt) = &r.mqtt {
        ui.label(format!("MQTT {} · topic {} · active {} · connected {} · offered {} · queue drops {} · coalesced {} · unsent {} · TCP writes {} · errors {} · worker failed {}",
            mqtt.address,mqtt.topic,mqtt.active,mqtt.connected,mqtt.offered,mqtt.queue_drops,mqtt.coalesced,mqtt.unsent_events,mqtt.write_completions,mqtt.errors,mqtt.worker_failed));
        if let Some(error) = mqtt.worker_error.as_ref().or(mqtt.last_error.as_ref()) {
            ui.colored_label(egui::Color32::LIGHT_RED, format!("MQTT: {error}"));
        }
    }
    if let Some(http) = &r.http {
        ui.label(format!("HTTP {} · active {} · offered {} · dispatched {} · queue drops {} · pending {} · history evictions {} · rejected requests {} · I/O errors {} · worker failed {}",
            http.address,http.active,http.offered,http.dispatched,http.queue_drops,http.pending,http.history_evictions,http.rejected_requests,http.io_errors,http.worker_failed));
        if let Some(error) = &http.worker_error {
            ui.colored_label(
                egui::Color32::LIGHT_RED,
                format!("HTTP feed worker: {error}"),
            );
        }
    }
    ui.strong(format!("{}  {}", snapshot.phase, r.backend));
    if let Some(context) = &r.context {
        ui.collapsing("Saved trial settings", |ui| {
            let elapsed = if r.cyclic_elapsed_us == 0 {
                "pending".into()
            } else {
                format!("{} µs", r.cyclic_elapsed_us)
            };
            ui.label(format!(
                "Workbench {} · {:?} · duration limit {} µs · final cyclic interval {}",
                context.app_version, context.frontend, context.duration_limit_us, elapsed
            ));
            ui.monospace(serde_json::to_string_pretty(context).unwrap_or_default());
        });
    }
    if let Some(error) = &r.error {
        ui.colored_label(egui::Color32::LIGHT_RED, error);
    }
    for device in &r.devices {
        device_info(ui, device);
    }
    if let Some(verification) = &r.pdo_verification {
        if verification.tx.unavailable.is_some() || verification.rx.unavailable.is_some() {
            ui.colored_label(
                egui::Color32::YELLOW,
                "Device PDO assignment order is unverified. See the layout details.",
            );
        }
        egui::CollapsingHeader::new(format!(
            "PDO layout · {} matched fields · {}",
            verification.matched_fields(),
            verification.source
        ))
        .show(ui, |ui| {
            for (direction, result) in [("TxPDO", &verification.tx), ("RxPDO", &verification.rx)] {
                if let Some(reason) = &result.unavailable {
                    ui.label(format!("{direction} mapping unavailable · {reason}"));
                }
                for error in &result.errors {
                    ui.colored_label(egui::Color32::LIGHT_RED, format!("{direction} · {error}"));
                }
                for field in &result.fields {
                    ui.label(format!(
                        "{direction} · {} · {:?} · {}",
                        field.name, field.state, field.detail
                    ));
                }
            }
        });
    }
    ui.label(format!(
        "Requested {} µs ({:?}) · generation {} · WKC {}/{}",
        r.requested_cycle_us,
        r.scheduler,
        r.connection_generation,
        r.actual_wkc.map_or("—".into(), |n| n.to_string()),
        r.expected_wkc
    ));
    ui.label(format!(
        "Device sync · {}  |  DC · {}",
        r.device_sync, r.dc_sync
    ));
    if let Some(review) = &r.sync_review {
        ui.collapsing(
            "Staged ESI DC mode versus run readback (not applied)",
            |ui| {
                ui.monospace(serde_json::to_string_pretty(review).unwrap_or_default());
            },
        );
    }
    if let Some(sync) = &r.synchronization {
        ui.collapsing("Synchronization register readback", |ui| {
            ui.label(&sync.source);
            ui.monospace(serde_json::to_string_pretty(sync).unwrap_or_default());
        });
    }
    ui.label(format!("Cycles {} · replies {} · valid {} · timeouts {} · missed slots {} · WKC mismatches {} · AL mismatches {} · ignored frames {}",
        r.cycles, r.replies, r.valid, r.timeouts, r.missed_deadlines, r.wkc_mismatches, r.state_mismatches, r.ignored_frames));
    if let Some(origin) = &r.replay_origin {
        ui.label(format!("Replay origin · {origin}"));
        ui.label("Spacing measures host playback. Cycle and receive timestamps are generated during playback.");
    }
    for (label, gap) in [
        ("Send", &r.send_spacing),
        ("All received", &r.receive_spacing),
    ]
    .into_iter()
    .chain(r.valid_receive_spacing.as_ref().map(|s| ("Valid input", s)))
    {
        if let (Some(p50), Some(p95), Some(p99), Some(longest)) =
            (gap.p50_us, gap.p95_us, gap.p99_us, gap.longest_gap_us)
        {
            ui.label(format!(
                "{label} spacing µs · {} intervals · p50 {p50} · p95 {p95} · p99 {p99} · longest {longest}", gap.count
            ));
        }
    }
    match &r.valid_receive_spacing {
        None => {
            ui.label("Valid input spacing · unavailable (not recorded)");
        }
        Some(s) if s.count == 0 => {
            ui.label("Valid input spacing µs · 0 intervals (fewer than two valid inputs)");
        }
        _ => {}
    }
    if let Some(esc) = &r.virtual_esc {
        ui.label(format!("Virtual ESC · SII reads {} · CoE uploads {} · SM writes {} · FMMU writes {} · state requests {:?}",
            esc.sii_reads, esc.coe_uploads, esc.sync_manager_writes, esc.fmmu_writes, esc.state_requests));
        ui.label(format!(
            "Virtual audit · CoE downloads {} · logical writes {} · physical output writes {} · OP requests {}",
            esc.coe_downloads, esc.logical_writes, esc.physical_output_writes, esc.op_requests
        ));
    }
    if let Some((status, code)) = r.setup_failure_al {
        ui.label(format!(
            "AL at setup failure · {status:#06x} code {code:#06x}"
        ));
    }
    if let Some((status, code)) = r.stopped_al {
        ui.label(format!(
            "INIT confirmed on stop · AL {status:#06x} code {code:#06x}"
        ));
    }
    if let Some(c) = &r.capture {
        ui.label(format!(
            "CSV · selected {} · flushed {} · overruns {} · started {}",
            c.selected, c.written, c.overruns, c.utc_start
        ));
    }
    let health = &r.input_health;
    let age = snapshot
        .last_valid_received_at
        .map(|at| format!("{} µs", at.elapsed().as_micros()))
        .unwrap_or_else(|| "none received".into());
    let quality = health.current_issue.map(|issue| issue.label()).unwrap_or(
        if health.last_valid_cycle.is_some() {
            "valid at last receive"
        } else {
            "awaiting input"
        },
    );
    ui.label(format!("Input quality · {quality} · last valid age {age} · consecutive invalid {} · recoveries {} · longest invalid {} µs · transport errors {} · loss timeout {} ms",
        health.consecutive_invalid, health.recoveries, health.longest_invalid_us,
        r.transport_errors, r.input_loss_timeout_ms));
    if snapshot.payload_len > 0 {
        let data = &snapshot.payload[..snapshot.payload_len];
        let bytes = data
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        ui.label(if snapshot.valid {
            "Last TxPDO (valid at receive)"
        } else {
            "Last payload (invalid or stopped)"
        });
        ui.monospace(bytes);
        if snapshot.valid {
            show_values(ui, data, fields);
        }
    }
}

#[cfg(test)]
mod timing_layout_tests {
    use super::*;

    #[test]
    fn headless_snapshot_keeps_unrecorded_empty_and_measured_valid_spacing_distinct() {
        for (spacing, expected) in [
            (None, "Valid input spacing · unavailable (not recorded)"),
            (
                Some(run::Spacing::default()),
                "0 intervals (fewer than two valid inputs)",
            ),
            (
                Some(run::Spacing {
                    count: 2,
                    p50_us: Some(1000),
                    p95_us: Some(4000),
                    p99_us: Some(4000),
                    longest_gap_us: Some(4000),
                }),
                "2 intervals · p50 1000",
            ),
        ] {
            let mut snapshot = Snapshot::default();
            snapshot.report.valid_receive_spacing = spacing;
            let ctx = egui::Context::default();
            ctx.memory_mut(|m| m.set_everything_is_visible(true));
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1400.0, 10000.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| show_snapshot(ui, &snapshot, &[]));
                },
            );
            fn collect(shape: &egui::epaint::Shape, text: &mut String) {
                match shape {
                    egui::epaint::Shape::Text(s) => {
                        text.push_str(&s.galley.job.text);
                        text.push('\n');
                    }
                    egui::epaint::Shape::Vec(shapes) => {
                        for shape in shapes {
                            collect(shape, text);
                        }
                    }
                    _ => {}
                }
            }
            let mut text = String::new();
            for shape in output.shapes {
                collect(&shape.shape, &mut text);
            }
            assert!(text.contains(expected), "missing {expected:?}: {text}");
        }
    }
}

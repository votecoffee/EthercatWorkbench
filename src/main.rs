#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

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
                self.approved = false;
                self.last = None;
                self.message = "Profile loaded".into();
            }
            Err(error) => self.message = format!("{error:#}"),
        }
    }

    fn start(&mut self, mode: Mode) {
        self.approved = false;
        self.generation += 1;
        let stop = Arc::new(AtomicBool::new(false));
        let view = Arc::new(Mutex::new(Snapshot::default()));
        let csv = (!self.csv.trim().is_empty()).then(|| PathBuf::from(self.csv.trim()));
        let opts = RunOptions {
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
            }
            Err(error) => self.message = format!("{error:#}"),
        }
    }

    fn refresh(&mut self, ctx: &egui::Context) {
        if self
            .scan
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
        {
            match self.scan.take().expect("finished scan").join() {
                Ok(Ok(devices)) => {
                    self.discovery = devices;
                    self.message =
                        "Read-only scan complete. Identity requires approved SII access.".into();
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

    fn profile_controls(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
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
        ui.horizontal(|ui| {
            ui.label("Name");
            ui.text_edit_singleline(&mut self.profile.name);
        });
        ui.horizontal(|ui| {
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
            ui.horizontal(|ui| {
                egui::ComboBox::from_id_salt("esi_device")
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
                ui.horizontal(|ui| {
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
        ui.horizontal(|ui| {
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

    fn bench_controls(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
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
        ui.horizontal(|ui| {
            ui.label("Cycle µs");
            ui.add(
                egui::DragValue::new(&mut self.profile.requested_cycle_us).range(250..=1_000_000),
            );
            ui.label("Input loss timeout ms (0 = monitor only)");
            ui.add(egui::DragValue::new(&mut self.profile.input_loss_timeout_ms).range(0..=60_000));
            ui.label("Duration s");
            ui.add(egui::DragValue::new(&mut self.seconds).range(1..=86_400));
            ui.selectable_value(&mut self.profile.scheduler, Scheduler::Deadline, "Deadline");
            ui.selectable_value(
                &mut self.profile.scheduler,
                Scheduler::Relative,
                "Stock relative",
            );
        });
        ui.horizontal(|ui| {
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
        ui.horizontal(|ui| {
            ui.label("Queue samples");
            ui.add(egui::DragValue::new(&mut self.profile.queue_capacity).range(1..=65_536));
            ui.label("Rotate rows (0 = one file)");
            ui.add(egui::DragValue::new(&mut self.profile.rotate_rows));
        });
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
        if ui.button("Start virtual EtherCAT controller").clicked() {
            self.start(Mode::Virtual {
                model: self.virtual_model,
                fault: ethercat_workbench::virtual_esc::VirtualFault::None,
            });
        }
        ui.horizontal(|ui| {
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
        if ctx.input(|input| input.viewport().close_requested())
            && let Some(session) = &self.session
        {
            session.stop.store(true, Relaxed);
            self.deferred_close = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
        self.refresh(ctx);
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("EtherCAT Workbench");
            if !self.message.is_empty() {
                ui.label(&self.message);
            }
            if let Some(session) = &self.session
                && ui.button("Stop and flush").clicked()
            {
                session.stop.store(true, Relaxed);
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                if let Some(snapshot) = &self.last {
                    ui.group(|ui| {
                        show_snapshot(ui, snapshot, &self.profile.tx);
                        if self.session.is_none() {
                            ui.horizontal(|ui| {
                                ui.label("New report JSON");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.report_save)
                                        .hint_text(".local/bench-report.json")
                                        .desired_width(360.0),
                                );
                                if ui
                                    .add_enabled(
                                        !self.report_save.trim().is_empty(),
                                        egui::Button::new("Save report"),
                                    )
                                    .clicked()
                                {
                                    self.message = match write_report(
                                        Path::new(self.report_save.trim()),
                                        &snapshot.report,
                                    ) {
                                        Ok(()) => "Run report saved".into(),
                                        Err(error) => format!("Write run report: {error:#}"),
                                    };
                                }
                            });
                        }
                    });
                }
                ui.add_enabled_ui(self.session.is_none(), |ui| {
                    egui::CollapsingHeader::new("1  Profile and ESI")
                        .default_open(true)
                        .show(ui, |ui| self.profile_controls(ui));
                    egui::CollapsingHeader::new("2  Bus and capture")
                        .default_open(true)
                        .show(ui, |ui| self.bench_controls(ui));
                    egui::CollapsingHeader::new("3  PDO maps and offline payloads")
                        .default_open(true)
                        .show(ui, |ui| {
                            fields(
                                ui,
                                "TxPDO inputs",
                                &mut self.profile.tx_bytes,
                                &mut self.profile.tx,
                            );
                            ui.horizontal(|ui| {
                                ui.label("Offline TxPDO hex");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.offline_hex)
                                        .desired_width(360.0),
                                );
                            });
                            decode(
                                ui,
                                &self.offline_hex,
                                self.profile.tx_bytes,
                                &self.profile.tx,
                            );
                            ui.separator();
                            fields(
                                ui,
                                "RxPDO outputs",
                                &mut self.profile.rx_bytes,
                                &mut self.profile.rx,
                            );
                            ui.horizontal(|ui| {
                                ui.label("Stage RxPDO hex offline");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.profile.staged_rx_hex)
                                        .desired_width(360.0),
                                );
                            });
                            decode(
                                ui,
                                &self.profile.staged_rx_hex,
                                self.profile.rx_bytes,
                                &self.profile.rx,
                            );
                            if let Err(error) = self.profile.validate() {
                                ui.colored_label(egui::Color32::LIGHT_RED, format!("{error:#}"));
                            }
                        });
                });
            });
        });
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
    let state = match device.al_status & 0xf {
        1 => "INIT",
        2 => "PREOP",
        3 => "BOOT",
        4 => "SAFEOP",
        8 => "OP",
        _ => "unknown",
    };
    ui.label(format!("Bus position {} · station {:#06x} · alias {:#06x} · links {:?} · {} / AL {:#06x} code {:#06x}",
        device.position, device.station_address, device.alias, device.link_ports, state, device.al_status, device.al_code));
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
    ui.strong(format!("{}  {}", snapshot.phase, r.backend));
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
    for (label, gap) in [("Send", &r.send_spacing), ("Receive", &r.receive_spacing)] {
        if let (Some(p50), Some(p95), Some(p99), Some(longest)) =
            (gap.p50_us, gap.p95_us, gap.p99_us, gap.longest_gap_us)
        {
            ui.label(format!(
                "{label} spacing µs · p50 {p50} · p95 {p95} · p99 {p99} · longest {longest}"
            ));
        }
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

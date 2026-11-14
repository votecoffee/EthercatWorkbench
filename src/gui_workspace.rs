//! Focused workflows shared in shape with EthernetIP Workbench; no acquisition work here.
use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(super) enum Tab {
    #[default]
    Device,
    Inputs,
    Outputs,
    Logging,
    Mappings,
    Integration,
    Diagnostics,
    Review,
}

impl Tab {
    const ALL: [Self; 8] = [
        Self::Device,
        Self::Inputs,
        Self::Outputs,
        Self::Logging,
        Self::Mappings,
        Self::Integration,
        Self::Diagnostics,
        Self::Review,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Device => "Device",
            Self::Inputs => "Inputs",
            Self::Outputs => "Outputs",
            Self::Logging => "Logging",
            Self::Mappings => "Mappings",
            Self::Integration => "Integration",
            Self::Diagnostics => "Diagnostics",
            Self::Review => "Review",
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum MappingPage {
    #[default]
    Inputs,
    Outputs,
    Catalog,
    Synchronization,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum ConnectPage {
    #[default]
    Offline,
    Bench,
}

impl App {
    pub(super) fn busy(&self) -> bool {
        self.session.is_some() || self.scan.is_some() || self.review.is_running()
    }

    fn open_connection(&mut self) {
        self.approved = false;
        self.connect_open = true;
        self.profiles_open = false;
        self.decoder_open = false;
    }

    fn stop_control(&mut self, ui: &mut egui::Ui) {
        if ui
            .add_enabled(self.session.is_some(), egui::Button::new("Stop and flush"))
            .clicked()
            && let Some(session) = &self.session
        {
            session.stop.store(true, Relaxed);
        }
        if self.review.is_running() && ui.button("Cancel file review").clicked() {
            self.review.cancel();
        }
    }

    pub(super) fn show_workspace(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("workspace_header").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading("EtherCAT Workbench");
                if ui
                    .add_enabled(!self.busy(), egui::Button::new("Connect…"))
                    .clicked()
                {
                    self.open_connection();
                }
                if ui
                    .add_enabled(!self.busy(), egui::Button::new("Profiles…"))
                    .clicked()
                {
                    self.profiles_open = true;
                }
                if ui.button("Record CSV…").clicked() {
                    self.tab = Tab::Logging;
                }
                self.stop_control(ui);
            });
            ui.horizontal_wrapped(|ui| {
                ui.strong(&self.profile.name);
                ui.label(if self.session.is_some() {
                    "Session active"
                } else if self.scan.is_some() {
                    "Discovering devices"
                } else if self.review.is_running() {
                    "Reviewing saved files"
                } else {
                    "Idle"
                });
                if let Some(snapshot) = &self.last {
                    ui.label(format!(
                        "{} · WKC {}/{} · valid {}",
                        snapshot.phase,
                        snapshot
                            .report
                            .actual_wkc
                            .map_or("—".into(), |n| n.to_string()),
                        snapshot.report.expected_wkc,
                        snapshot.report.valid
                    ));
                }
            });
            egui::ScrollArea::vertical()
                .id_salt("workspace_alerts")
                .max_height(74.0)
                .show(ui, |ui| {
                    if !self.message.is_empty() {
                        ui.label(&self.message);
                    }
                    if let Some(snapshot) = &self.last {
                        if let Some(error) = &snapshot.report.error {
                            ui.colored_label(egui::Color32::LIGHT_RED, error);
                        }
                        if let Some(issue) = snapshot.report.input_health.current_issue {
                            ui.colored_label(
                                egui::Color32::YELLOW,
                                format!("Input quality · {}", issue.label()),
                            );
                        }
                        if let Some(capture) = &snapshot.report.capture {
                            ui.label(format!(
                                "CSV · selected {} · flushed {} · overruns {}",
                                capture.selected, capture.written, capture.overruns
                            ));
                        }
                    }
                });
            ui.horizontal_wrapped(|ui| {
                for tab in Tab::ALL {
                    ui.selectable_value(&mut self.tab, tab, tab.label());
                }
            });
        });

        // A profile edit elsewhere must invalidate an earlier live review before its button runs.
        let previous_profile = self
            .approved
            .then(|| serde_json::to_vec(&self.profile).expect("serializable profile"));
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().id_salt(self.tab).show(ui, |ui| {
                if self.busy() && matches!(self.tab, Tab::Device | Tab::Outputs | Tab::Logging | Tab::Mappings | Tab::Integration) {
                    ui.label("Settings are locked until the active session, discovery or file review finishes. Navigation and Stop and flush remain available.");
                }
                match self.tab {
                    Tab::Device => {
                        ui.heading("Device setup");
                        ui.label("Load a profile or import an ESI, review mappings, then connect. Use the offline demo to explore without a NIC.");
                        ui.add_enabled_ui(!self.busy(), |ui| {
                            ui.horizontal_wrapped(|ui| {
                                if ui.button("Open profiles…").clicked() { self.profiles_open = true; }
                                if ui.button("Use offline demo").clicked() {
                                    self.profile = serde_json::from_str(include_str!("../samples/synthetic.json")).expect("authored demo profile");
                                    self.profile_path.clear();
                                    self.profile_pdo_draft = None;
                                    self.stage = gui_stage::Panel::default();
                                    self.mode_pdos = gui_mode_pdo::Panel::default();
                                    self.last = None;
                                    self.message = "Offline demo loaded. Connect… offers synthetic and virtual sessions.".into();
                                }
                                if ui.button("Review mappings").clicked() { self.tab = Tab::Mappings; }
                            });
                            ui.separator();
                            self.device_controls(ui);
                            ui.collapsing("Expected identity / manual override", |ui| self.identity_controls(ui));
                        });
                        if !self.discovery.is_empty() {
                            ui.collapsing("Discovered devices (last scan)", |ui| {
                                for device in &self.discovery { device_info(ui, device); }
                            });
                        }
                    }
                    Tab::Inputs => self.input_page(ui),
                    Tab::Outputs => {
                        ui.heading("Stage outputs offline");
                        ui.label("Review typed edits before applying them to the saved profile. These controls send no live outputs. OP and live output writes are unavailable.");
                        ui.add_enabled_ui(!self.busy(), |ui| {
                            self.stage.draw(ui, &mut self.profile);
                            ui.collapsing("Raw RxPDO payload", |ui| {
                                ui.label("Stage RxPDO hex offline");
                                ui.add(egui::TextEdit::multiline(&mut self.profile.staged_rx_hex).desired_rows(2).desired_width(f32::INFINITY));
                                decode(ui, &self.profile.staged_rx_hex, self.profile.rx_bytes, &self.profile.rx);
                            });
                            if ui.button("Edit output mappings").clicked() {
                                self.tab = Tab::Mappings;
                                self.mapping_page = MappingPage::Outputs;
                            }
                        });
                    }
                    Tab::Logging => {
                        ui.heading("CSV logging");
                        ui.label("Choose a new file and the fields in Mappings before connecting. A session records automatically when a CSV path is set; Stop and flush ends the session and drains its writer.");
                        ui.add_enabled_ui(!self.busy(), |ui| {
                            let selected = self.profile.tx.iter().filter(|f| f.log).map(|f| f.name.as_str()).collect::<Vec<_>>();
                            ui.label(format!("Selected CSV fields · {} · {}", selected.len(), selected.join(", ")));
                            if ui.button("Choose fields in Mappings").clicked() {
                                self.tab = Tab::Mappings;
                                self.mapping_page = MappingPage::Inputs;
                            }
                            self.logging_controls(ui);
                            ui.collapsing("Advanced cycle scheduling", |ui| self.timing_controls(ui));
                            if ui.button("Connect with these settings…").clicked() { self.open_connection(); }
                        });
                    }
                    Tab::Mappings => self.mapping_page(ui),
                    Tab::Integration => {
                        ui.heading("Software integration");
                        ui.label("Optional read-only input feeds. Configure before starting a session.");
                        ui.add_enabled_ui(!self.busy(), |ui| self.integration_controls(ui));
                    }
                    Tab::Diagnostics => {
                        ui.heading("Connection diagnostics");
                        if let Some(snapshot) = &self.last {
                            show_snapshot(ui, snapshot, &self.profile.tx);
                        } else { ui.label("Connect to an offline fixture or approved bench to collect timing and device diagnostics."); }
                        self.report_controls(ui);
                    }
                    Tab::Review => {
                        ui.heading("Saved capture review");
                        self.review.draw(ui, self.session.is_some() || self.scan.is_some(), &self.profile);
                    }
                }
                if matches!(self.tab, Tab::Device | Tab::Mappings | Tab::Outputs | Tab::Logging | Tab::Integration)
                    && let Err(error) = self.profile.validate()
                {
                    ui.colored_label(egui::Color32::LIGHT_RED, format!("Profile needs attention: {error:#}"));
                }
            });
        });
        if previous_profile.is_some_and(|previous| {
            previous != serde_json::to_vec(&self.profile).expect("serializable profile")
        }) {
            self.approved = false;
        }
        self.dialogs(ctx);
        // Navigation must never preserve a write-capable preview across active work.
        if self.busy() {
            self.mode_pdos.block();
        }
    }

    fn input_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Live inputs");
        ui.horizontal_wrapped(|ui| {
            if ui.button("Offline decoder…").clicked() {
                self.decoder_open = true;
            }
            if ui.button("Edit input mappings").clicked() {
                self.tab = Tab::Mappings;
                self.mapping_page = MappingPage::Inputs;
            }
        });
        let Some(snapshot) = &self.last else {
            ui.label("No input received. Use Connect… for an offline fixture or an approved SAFEOP bench session.");
            return;
        };
        let age = snapshot
            .last_valid_received_at
            .map_or("none received".into(), |t| {
                format!("{} µs", t.elapsed().as_micros())
            });
        ui.label(format!("Last valid input age · {age}"));
        if snapshot.valid {
            ui.strong("Valid at last receive");
            show_values(
                ui,
                &snapshot.payload[..snapshot.payload_len],
                &self.profile.tx,
            );
        } else {
            ui.colored_label(egui::Color32::YELLOW, "Current input unavailable. Retained payload is historical; typed live values are hidden.");
        }
        ui.collapsing("Raw TxPDO payload", |ui| {
            ui.label(if snapshot.valid {
                "Last valid payload"
            } else {
                "Last payload (invalid or stopped)"
            });
            ui.add(
                egui::Label::new(
                    egui::RichText::new(hex::encode_upper(
                        &snapshot.payload[..snapshot.payload_len],
                    ))
                    .monospace(),
                )
                .wrap(),
            );
        });
    }

    fn mapping_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("PDO mappings");
        ui.label("Offline expectations and decoder fields. Changing these settings does not download a device mapping.");
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.mapping_page, MappingPage::Inputs, "Input fields");
            ui.selectable_value(
                &mut self.mapping_page,
                MappingPage::Outputs,
                "Output fields",
            );
            ui.selectable_value(
                &mut self.mapping_page,
                MappingPage::Catalog,
                "ESI PDO choices",
            );
            ui.selectable_value(
                &mut self.mapping_page,
                MappingPage::Synchronization,
                "ESI synchronization",
            );
        });
        ui.separator();
        ui.add_enabled_ui(!self.busy(), |ui| match self.mapping_page {
            MappingPage::Inputs => {
                egui::ScrollArea::horizontal()
                    .id_salt("input_fields")
                    .show(ui, |ui| {
                        fields(
                            ui,
                            "TxPDO inputs",
                            &mut self.profile.tx_bytes,
                            &mut self.profile.tx,
                        )
                    });
            }
            MappingPage::Outputs => {
                egui::ScrollArea::horizontal()
                    .id_salt("output_fields")
                    .show(ui, |ui| {
                        fields(
                            ui,
                            "RxPDO outputs",
                            &mut self.profile.rx_bytes,
                            &mut self.profile.rx,
                        )
                    });
            }
            MappingPage::Catalog => {
                if self.profile.esi.is_none() {
                    ui.label("Import an ESI in Device setup to retain its PDO catalog.");
                }
                self.catalog_controls(ui);
            }
            MappingPage::Synchronization => {
                ui.label(
                    "ESI mode and timing hints are staged offline. Runtime SYNC remains disabled.",
                );
                self.sync_controls(ui);
            }
        });
    }

    fn report_controls(&mut self, ui: &mut egui::Ui) {
        if self.session.is_none() && self.last.is_some() {
            ui.separator();
            ui.horizontal_wrapped(|ui| {
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
                        &self.last.as_ref().expect("report present").report,
                    ) {
                        Ok(()) => "Run report saved".into(),
                        Err(error) => format!("Write run report: {error:#}"),
                    };
                }
            });
        }
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        if self.profiles_open {
            let mut open = true;
            egui::Window::new("Profiles")
                .open(&mut open)
                .default_width(640.0)
                .show(ctx, |ui| {
                    ui.label("Load settings or save to a new path. Existing files are preserved.");
                    ui.add_enabled_ui(!self.busy(), |ui| self.profile_file_controls(ui));
                });
            self.profiles_open = open;
        }
        if self.decoder_open {
            let mut open = true;
            egui::Window::new("Offline payload decoder")
                .open(&mut open)
                .default_width(560.0)
                .show(ctx, |ui| {
                    ui.label(format!(
                        "Current input mapping · {} bytes. Pasted bytes never reach the bus.",
                        self.profile.tx_bytes
                    ));
                    ui.add(
                        egui::TextEdit::multiline(&mut self.offline_hex)
                            .hint_text("Paste TxPDO hex bytes")
                            .desired_rows(3)
                            .desired_width(f32::INFINITY),
                    );
                    decode(
                        ui,
                        &self.offline_hex,
                        self.profile.tx_bytes,
                        &self.profile.tx,
                    );
                });
            self.decoder_open = open;
        }
        if self.connect_open {
            let response = egui::Modal::new(egui::Id::new("connect_review")).show(ctx, |ui| {
                ui.set_width(680.0_f32.min(ctx.screen_rect().width() - 60.0));
                ui.horizontal_wrapped(|ui| {
                    ui.heading("Connect / review session");
                    if ui.button("Close").clicked() { self.connect_open = false; self.approved = false; }
                    self.stop_control(ui);
                });
                ui.label(format!("{} · requested {} µs · {:?} · {} s · CSV {}", self.profile.name, self.profile.requested_cycle_us, self.profile.scheduler, self.seconds,
                    if self.csv.trim().is_empty() { "disabled" } else { self.csv.trim() }));
                let before = self.connect_page;
                ui.horizontal_wrapped(|ui| {
                    ui.selectable_value(&mut self.connect_page, ConnectPage::Offline, "Offline fixtures");
                    ui.selectable_value(&mut self.connect_page, ConnectPage::Bench, "Isolated bench / SAFEOP");
                });
                if before != self.connect_page { self.approved = false; }
                egui::ScrollArea::vertical().id_salt("connect_content").max_height((ctx.screen_rect().height() - 220.0).max(150.0)).show(ui, |ui| {
                    ui.add_enabled_ui(!self.busy(), |ui| match self.connect_page {
                        ConnectPage::Offline => {
                            ui.label("Synthetic, virtual and replay sessions use no physical NIC. Configure input fields in Mappings first, or use the offline demo in Device.");
                            self.offline_connection_controls(ui);
                        }
                        ConnectPage::Bench => {
                            ui.label("Select the identified isolated NIC. Discovery does not initialize SAFEOP. Starting live inputs performs ESC setup, SM/FMMU configuration from the current mapping, SAFEOP entry and INIT cleanup.");
                            ui.label("OP, PDO mapping downloads, enabled DC and live outputs are unavailable. Staged RxPDO bytes are not sent.");
                            self.nic_controls(ui);
                            self.live_connection_controls(ui);
                        }
                    });
                });
            });
            if response.should_close() {
                self.connect_open = false;
                self.approved = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        App::new(Args::parse_from(["ethercat-workbench"]))
    }

    // Pure egui frames and events; no native window, GPU, screenshot or desktop input.
    fn draw(
        app: &mut App,
        ctx: &egui::Context,
        size: egui::Vec2,
        events: Vec<egui::Event>,
    ) -> Vec<(String, egui::Rect)> {
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                events,
                ..Default::default()
            },
            |ctx| app.show_workspace(ctx),
        );
        fn collect(shape: egui::epaint::Shape, text: &mut Vec<(String, egui::Rect)>) {
            match shape {
                egui::epaint::Shape::Text(s) => text.push((
                    s.galley.job.text.clone(),
                    egui::Rect::from_min_size(s.pos, s.galley.size()),
                )),
                egui::epaint::Shape::Vec(v) => {
                    for s in v {
                        collect(s, text);
                    }
                }
                _ => {}
            }
        }
        let mut text = Vec::new();
        for s in output.shapes {
            collect(s.shape, &mut text);
        }
        text
    }

    fn click(app: &mut App, ctx: &egui::Context, label: &str) {
        let size = egui::vec2(1100.0, 840.0);
        draw(app, ctx, size, vec![]);
        let text = draw(app, ctx, size, vec![]);
        let pos = text
            .iter()
            .find(|(s, _)| s == label)
            .unwrap_or_else(|| panic!("missing {label}"))
            .1
            .center();
        draw(
            app,
            ctx,
            size,
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: Default::default(),
                },
            ],
        );
        draw(
            app,
            ctx,
            size,
            vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: Default::default(),
            }],
        );
    }

    #[test]
    fn tabs_isolate_content_keep_actions_in_bounds_and_do_not_start_work() {
        for size in [egui::vec2(820.0, 560.0), egui::vec2(1100.0, 840.0)] {
            let mut app = app();
            let ctx = egui::Context::default();
            app.message = "Authored long error for bounded header checks. ".repeat(100);
            let profile = serde_json::to_vec(&app.profile).unwrap();
            for tab in Tab::ALL {
                app.tab = tab;
                draw(&mut app, &ctx, size, vec![]);
                let text = draw(&mut app, &ctx, size, vec![]);
                for label in [
                    "Connect…",
                    "Profiles…",
                    "Record CSV…",
                    "Stop and flush",
                    "Device",
                    "Inputs",
                    "Outputs",
                    "Logging",
                    "Mappings",
                    "Integration",
                    "Diagnostics",
                    "Review",
                ] {
                    let bounds = text
                        .iter()
                        .find(|(s, _)| s == label)
                        .unwrap_or_else(|| panic!("{label} missing on {tab:?}"))
                        .1;
                    assert!(
                        bounds.min.x >= 0.0
                            && bounds.max.x <= size.x
                            && bounds.min.y >= 0.0
                            && bounds.max.y <= size.y,
                        "{label}: {bounds:?} at {size:?}"
                    );
                }
                for (page, heading) in [
                    (Tab::Device, "Device setup"),
                    (Tab::Inputs, "Live inputs"),
                    (Tab::Outputs, "Stage outputs offline"),
                    (Tab::Logging, "CSV logging"),
                    (Tab::Mappings, "PDO mappings"),
                    (Tab::Integration, "Software integration"),
                    (Tab::Diagnostics, "Connection diagnostics"),
                    (Tab::Review, "Saved capture review"),
                ] {
                    assert_eq!(
                        text.iter().any(|(s, _)| s == heading),
                        tab == page,
                        "{tab:?}: {heading}"
                    );
                }
                assert_eq!(serde_json::to_vec(&app.profile).unwrap(), profile);
                assert!(!app.busy());
            }
        }
    }

    #[test]
    fn navigation_and_secondary_windows_preserve_drafts_without_starting() {
        let ctx = egui::Context::default();
        let mut app = app();
        app.profile.staged_rx_hex = "AB CD".into();
        click(&mut app, &ctx, "Logging");
        assert_eq!(app.tab, Tab::Logging);
        click(&mut app, &ctx, "Inputs");
        click(&mut app, &ctx, "Offline decoder…");
        assert!(app.decoder_open);
        app.decoder_open = false;
        click(&mut app, &ctx, "Profiles…");
        assert!(app.profiles_open);
        app.profiles_open = false;
        click(&mut app, &ctx, "Connect…");
        assert!(app.connect_open && !app.approved);
        assert_eq!(app.profile.staged_rx_hex, "AB CD");
        assert!(!app.busy());
    }

    #[test]
    fn live_review_names_setup_effects_and_keeps_offline_outputs_explicit() {
        let mut app = app();
        app.connect_open = true;
        app.connect_page = ConnectPage::Bench;
        app.profile.nic = "\\Device\\NPF_{00000000-0000-0000-0000-000000000000}".repeat(2);
        let ctx = egui::Context::default();
        let size = egui::vec2(820.0, 560.0);
        draw(&mut app, &ctx, size, vec![]);
        let labels = draw(&mut app, &ctx, size, vec![]);
        for (label, bounds) in &labels {
            if ["Connect / review session", "Close", "Stop and flush"].contains(&label.as_str()) {
                assert!(
                    bounds.min.x >= 0.0
                        && bounds.max.x <= size.x
                        && bounds.min.y >= 0.0
                        && bounds.max.y <= size.y,
                    "{label}: {bounds:?}"
                );
            }
        }
        let text = labels
            .iter()
            .map(|(s, _)| s.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        for expected in [
            "SM/FMMU",
            "SAFEOP entry",
            "INIT cleanup",
            "Staged RxPDO bytes are not sent",
            "Approved: isolated one-device bench",
            "Start live SAFEOP inputs",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
        assert!(app.nics.is_empty() && app.discovery.is_empty() && !app.busy());
    }

    #[test]
    fn discovery_blocks_configuration_and_duplicate_start_across_tabs() {
        let mut app = app();
        let (tx, rx) = std::sync::mpsc::channel();
        app.scan = Some(std::thread::spawn(move || {
            rx.recv().unwrap();
            Ok(vec![])
        }));
        let ctx = egui::Context::default();
        for tab in [
            Tab::Device,
            Tab::Outputs,
            Tab::Logging,
            Tab::Mappings,
            Tab::Integration,
        ] {
            app.tab = tab;
            let text = draw(&mut app, &ctx, egui::vec2(1100.0, 840.0), vec![]);
            assert!(text.iter().any(|(s, _)| s.contains("Settings are locked")));
        }
        click(&mut app, &ctx, "Connect…");
        assert!(!app.connect_open);
        app.start(Mode::Simulate { faults: false });
        assert!(app.session.is_none() && app.generation == 0);
        tx.send(()).unwrap();
        app.scan.take().unwrap().join().unwrap().unwrap();
    }

    #[test]
    fn invalid_retained_input_never_appears_as_typed_live_data() {
        let mut app = app();
        app.profile = serde_json::from_str(include_str!("../samples/synthetic.json")).unwrap();
        app.tab = Tab::Inputs;
        app.last = Some(Snapshot {
            payload_len: app.profile.tx_bytes,
            valid: false,
            ..Default::default()
        });
        let ctx = egui::Context::default();
        let text = draw(&mut app, &ctx, egui::vec2(1100.0, 840.0), vec![]);
        assert!(
            text.iter()
                .any(|(s, _)| s.contains("typed live values are hidden"))
        );
        assert!(!text.iter().any(|(s, _)| s == "Valid at last receive"));
        assert!(!text.iter().any(|(s, _)| s.contains("spacing µs")));
    }

    #[test]
    fn synthetic_capture_stops_and_flushes_after_navigation() {
        let mut app = app();
        app.profile = serde_json::from_str(include_str!("../samples/synthetic.json")).unwrap();
        app.profile.rotate_rows = 0;
        let dir = PathBuf::from(".local").join(format!(
            "gui-workflow-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let csv = dir.join("capture.csv");
        app.csv = csv.to_string_lossy().into_owned();
        app.seconds = 60;
        app.start(Mode::Simulate { faults: false });
        assert_eq!(app.tab, Tab::Inputs);
        assert!(app.session.is_some());
        let ctx = egui::Context::default();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while app
            .last
            .as_ref()
            .is_none_or(|s| s.report.capture.as_ref().is_none_or(|c| c.selected == 0))
        {
            app.refresh(&ctx);
            assert!(
                std::time::Instant::now() < deadline,
                "fixture did not publish capture progress"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        click(&mut app, &ctx, "Outputs");
        assert_eq!(app.tab, Tab::Outputs);
        click(&mut app, &ctx, "Stop and flush");
        while app.session.is_some() {
            app.refresh(&ctx);
            assert!(
                std::time::Instant::now() < deadline,
                "stop/flush did not finish"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let report = &app.last.as_ref().unwrap().report;
        assert!(report.error.is_none(), "{:?}", report.error);
        let capture = report.capture.as_ref().unwrap();
        assert!(capture.written > 0);
        assert_eq!(capture.written, capture.selected);
        assert_eq!(capture.overruns, 0);
        assert_eq!(
            csv::Reader::from_path(&csv).unwrap().records().count() as u64,
            capture.written
        );
        std::fs::remove_file(csv).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}

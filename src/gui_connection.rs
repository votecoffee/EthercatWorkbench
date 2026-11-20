//! Expected session settings and explicitly scoped discovery; no capture operations.
use super::*;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub(super) enum DiscoveryOrigin {
    Physical { nic: String },
    Virtual { model: String },
}

impl DiscoveryOrigin {
    fn matches_nic(&self, nic: &str) -> bool {
        matches!(self, Self::Physical {nic: observed} if observed == nic)
    }
    pub(super) fn label(&self) -> String {
        match self {
            Self::Physical { nic } => format!("Physical NIC · {nic}"),
            Self::Virtual { model } => format!("Virtual fixture · {model}"),
        }
    }
}

pub(super) struct DiscoveryJob {
    pub origin: DiscoveryOrigin,
    pub worker: JoinHandle<anyhow::Result<Vec<DeviceInfo>>>,
}

impl App {
    pub(super) fn invalidate_bench_review(&mut self) {
        self.approved = false;
        self.approved_settings = None;
    }

    fn bench_settings(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            &self.profile,
            self.seconds,
            self.csv.trim(),
            &self.discovery_origin,
            &self.discovery,
        ))
        .expect("serializable session settings")
    }

    pub(super) fn reconcile_bench_review(&mut self) {
        if self.approved
            && self
                .approved_settings
                .as_ref()
                .is_none_or(|saved| *saved != self.bench_settings())
        {
            self.invalidate_bench_review();
            self.message = "Session settings or discovery changed. Review the current plan and acknowledge it again.".into();
        } else if !self.approved {
            self.approved_settings = None;
        }
    }

    fn bench_issues(&self) -> Vec<String> {
        let mut issues = Vec::new();
        if let Err(error) = self.profile.validate() {
            issues.push(format!("Profile needs attention: {error:#}"));
        }
        if self.profile.nic.trim().is_empty() {
            issues.push("Select the isolated bench NIC.".into());
        }
        if self.profile.expected_identity.is_none() {
            issues.push("Set the exact expected vendor, product and revision in Device.".into());
        }
        if self.seconds == 0 {
            issues.push("Choose a nonzero duration in Logging.".into());
        }
        if self
            .discovery_origin
            .as_ref()
            .is_some_and(|origin| origin.matches_nic(&self.profile.nic))
            && self.discovery.len() != 1
        {
            issues.push(format!("The last successful scan on this NIC found {} devices. One isolated SubDevice is required; rescan after correcting the bench.", self.discovery.len()));
        }
        issues
    }

    fn bench_ready(&self) -> bool {
        !self.busy()
            && self.approved
            && self
                .approved_settings
                .as_ref()
                .is_some_and(|saved| *saved == self.bench_settings())
            && self.bench_issues().is_empty()
    }

    pub(super) fn begin_discovery(
        &mut self,
        origin: DiscoveryOrigin,
        work: impl FnOnce() -> anyhow::Result<Vec<DeviceInfo>> + Send + 'static,
    ) -> bool {
        if self.busy() {
            self.message =
                "Wait for active acquisition, discovery, file review or host work before scanning."
                    .into();
            return false;
        }
        self.invalidate_bench_review();
        match std::thread::Builder::new()
            .name("workbench-discovery".into())
            .spawn(work)
        {
            Ok(worker) => {
                self.discovery.clear();
                self.discovery_origin = None;
                self.scan = Some(DiscoveryJob { origin, worker });
                self.message.clear();
                true
            }
            Err(error) => {
                self.message = format!("Start discovery worker: {error}");
                false
            }
        }
    }

    pub(super) fn discovery_controls(&self, ui: &mut egui::Ui) {
        let Some(origin) = &self.discovery_origin else {
            ui.small(
                "No successful discovery snapshot. Device identity and topology remain unverified.",
            );
            return;
        };
        ui.collapsing("Last discovery snapshot", |ui| {
            ui.label(origin.label());
            ui.label(format!("{} devices · historical snapshot, not continuously refreshed", self.discovery.len()));
            match origin {
                DiscoveryOrigin::Virtual { .. } => { ui.label("Authored virtual evidence; excluded from physical bench topology checks."); }
                DiscoveryOrigin::Physical { .. } if !origin.matches_nic(&self.profile.nic) => { ui.label("Different NIC from the current profile; excluded from this bench review."); }
                DiscoveryOrigin::Physical { .. } => { ui.label("Read-only physical scan on the selected NIC. Exact device identity requires the approved setup/readback."); }
            }
            for device in &self.discovery { device_info(ui, device); }
        });
    }

    pub(super) fn show_bench_plan(&self, ui: &mut egui::Ui) {
        ui.strong("Proposed SAFEOP session");
        let source = match (&self.profile.expected_identity, &self.profile.esi) {
            (Some(expected), Some(esi)) if *expected == esi.identity => "ESI",
            (_, Some(_)) => "Override",
            _ => "Manual",
        };
        ui.label(format!(
            "Expected identity · {source} · {}",
            self.profile
                .expected_identity
                .as_ref()
                .map_or("not configured".into(), |id| id.to_string())
        ));
        ui.label(format!(
            "Configured image · TxPDO {} input bytes · RxPDO {} output bytes",
            self.profile.tx_bytes, self.profile.rx_bytes
        ));
        ui.label(format!(
            "Requested host cycle · {} µs · {:?} · duration {} s",
            self.profile.requested_cycle_us, self.profile.scheduler, self.seconds
        ));
        ui.label("Device synchronization and timing readback await approved setup. Runtime DC/SYNC remains disabled; ESI timing hints stay offline.");
        let selected = self
            .profile
            .tx
            .iter()
            .filter(|field| field.log)
            .collect::<Vec<_>>();
        let log_mode = match self.profile.mode {
            LogMode::Every => "every valid exchange",
            LogMode::Change => "on change",
        };
        ui.label(if self.csv.trim().is_empty() {
            "CSV disabled (no path configured)".into()
        } else {
            format!(
                "CSV · {} · {} · {} selected fields",
                self.csv.trim(),
                log_mode,
                selected.len()
            )
        });
        ui.collapsing("Capture fields and buffer settings", |ui| {
            for field in selected {
                ui.label(&field.name);
            }
            ui.label(format!(
                "Queue {} samples · rotate {} rows (0 = one file)",
                self.profile.queue_capacity, self.profile.rotate_rows
            ));
        });
        ui.label("Staged RxPDO bytes are not sent. OP, live outputs, PDO downloads and enabling DC are unavailable.");
        self.discovery_controls(ui);
        for issue in self.bench_issues() {
            ui.colored_label(egui::Color32::YELLOW, issue);
        }
    }

    pub(super) fn live_connection_controls(&mut self, ui: &mut egui::Ui) {
        self.reconcile_bench_review();
        let issues = self.bench_issues();
        let previously_approved = self.approved;
        ui.add_enabled(
            !self.busy() && issues.is_empty(),
            egui::Checkbox::new(
                &mut self.approved,
                "Approved: isolated one-device bench, ESC setup writes, SAFEOP and INIT on stop",
            ),
        );
        if self.approved && !previously_approved {
            self.approved_settings = Some(self.bench_settings());
        }
        if !self.approved {
            self.approved_settings = None;
        }
        if ui
            .add_enabled(
                self.bench_ready(),
                egui::Button::new("Start live SAFEOP inputs"),
            )
            .clicked()
        {
            match BenchApproval::confirm(self.bench_ready()) {
                Ok(approved) => self.start(Mode::SafeOp { approved }),
                Err(error) => self.message = format!("{error:#}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        let mut app = App::new(Args::parse_from(["ethercat-workbench"]));
        app.profile = serde_json::from_str(include_str!("../samples/synthetic.json")).unwrap();
        app.profile.nic = "authored-nic-A".into();
        app.profile.expected_identity = Some(Identity {
            vendor: 0x1234,
            product: 0x5678,
            revision: 1,
        });
        app
    }
    fn acknowledge(app: &mut App) {
        assert!(app.bench_issues().is_empty(), "{:?}", app.bench_issues());
        app.approved = true;
        app.approved_settings = Some(app.bench_settings());
        assert!(app.bench_ready());
    }
    fn wait(app: &mut App) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let ctx = egui::Context::default();
        while app.scan.is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "authored discovery did not finish"
            );
            app.refresh(&ctx);
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn acknowledgement_binds_profile_capture_duration_and_discovery() {
        let changes: [fn(&mut App); 7] = [
            |a| a.profile.tx[0].name = "Changed decoder".into(),
            |a| a.profile.staged_rx_hex = "01 00".into(),
            |a| a.profile.nic = "authored-nic-B".into(),
            |a| a.profile.expected_identity.as_mut().unwrap().revision += 1,
            |a| a.seconds += 1,
            |a| a.csv = ".local/different.csv".into(),
            |a| {
                a.discovery = vec![DeviceInfo {
                    al_status: 4,
                    ..Default::default()
                }]
            },
        ];
        for change in changes {
            let mut app = app();
            acknowledge(&mut app);
            change(&mut app);
            assert!(!app.bench_ready(), "changed plan reused an acknowledgement");
            app.reconcile_bench_review();
            assert!(!app.approved && app.approved_settings.is_none());
            assert!(app.session.is_none() && app.generation == 0);
        }
        let mut app = app();
        app.approved = true; // A bare boolean is insufficient.
        assert!(!app.bench_ready());
        app.reconcile_bench_review();
        assert!(!app.approved);
    }

    #[test]
    fn unrelated_editor_paths_and_decoder_text_do_not_change_effective_plan() {
        let mut app = app();
        acknowledge(&mut app);
        app.profile_editor.load_path = "different-load-path.json".into();
        app.offline_hex = "AA BB".into();
        app.reconcile_bench_review();
        assert!(app.bench_ready());
        app.invalidate_bench_review();
        assert!(!app.approved && app.approved_settings.is_none());
    }

    #[test]
    fn only_successful_discovery_on_current_physical_nic_qualifies_topology_preflight() {
        let mut app = app();
        let chain = live::scan_virtual(
            ethercat_workbench::virtual_esc::VirtualModel::Coe,
            ethercat_workbench::virtual_esc::ScanCase::TwoDevices,
        );
        assert!(chain.error.is_none(), "{:?}", chain.error);
        assert_eq!(chain.devices.len(), 2);
        app.discovery_origin = Some(DiscoveryOrigin::Virtual {
            model: "two-device chain".into(),
        });
        app.discovery = chain.devices;
        assert!(app.bench_issues().is_empty());
        app.discovery_origin = Some(DiscoveryOrigin::Physical {
            nic: "different-nic".into(),
        });
        assert!(app.bench_issues().is_empty());
        app.discovery_origin = Some(DiscoveryOrigin::Physical {
            nic: app.profile.nic.clone(),
        });
        assert!(
            app.bench_issues()
                .iter()
                .any(|s| s.contains("found 2 devices"))
        );
        app.discovery.clear();
        assert!(
            app.bench_issues()
                .iter()
                .any(|s| s.contains("found 0 devices"))
        );
        app.discovery.push(DeviceInfo::default());
        assert!(app.bench_issues().is_empty());
        app.profile.expected_identity = None;
        assert!(
            app.bench_issues()
                .iter()
                .any(|s| s.contains("exact expected"))
        );
        app.profile.nic.clear();
        assert!(
            app.bench_issues()
                .iter()
                .any(|s| s.contains("isolated bench NIC"))
        );
    }

    #[test]
    fn scanning_invalidates_review_immediately_and_retains_its_original_scope() {
        let mut app = app();
        acknowledge(&mut app);
        let original = DiscoveryOrigin::Physical {
            nic: app.profile.nic.clone(),
        };
        let (send, receive) = std::sync::mpsc::channel();
        assert!(app.begin_discovery(original.clone(), move || {
            receive.recv().unwrap();
            Ok(vec![DeviceInfo::default()])
        }));
        assert!(!app.approved && app.approved_settings.is_none());
        assert!(app.discovery_origin.is_none() && app.discovery.is_empty());
        assert!(!app.begin_discovery(
            DiscoveryOrigin::Virtual {
                model: "blocked".into()
            },
            || panic!("overlapping scan ran")
        ));
        app.profile.nic = "authored-nic-B".into();
        send.send(()).unwrap();
        wait(&mut app);
        assert_eq!(app.discovery_origin, Some(original));
        assert_eq!(app.discovery.len(), 1);
        assert!(!app.approved && !app.bench_ready());
        assert!(app.session.is_none() && app.generation == 0);
    }

    #[test]
    fn failed_discovery_is_not_presented_as_successful_zero_device_snapshot() {
        let mut app = app();
        app.discovery_origin = Some(DiscoveryOrigin::Physical {
            nic: app.profile.nic.clone(),
        });
        app.discovery = vec![DeviceInfo::default()];
        acknowledge(&mut app);
        assert!(app.begin_discovery(
            DiscoveryOrigin::Physical {
                nic: app.profile.nic.clone()
            },
            || anyhow::bail!("authored scan failure")
        ));
        wait(&mut app);
        assert!(app.discovery_origin.is_none() && app.discovery.is_empty());
        assert!(app.message.contains("authored scan failure"));
        assert!(!app.approved);
    }

    #[test]
    fn plan_layout_separates_expected_settings_scoped_evidence_and_disabled_outputs() {
        let mut app = app();
        app.csv = ".local/proposed.csv".into();
        app.discovery_origin = Some(DiscoveryOrigin::Virtual {
            model: "authored model".into(),
        });
        let ctx = egui::Context::default();
        ctx.memory_mut(|m| m.set_everything_is_visible(true));
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1000.0, 6000.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| app.show_bench_plan(ui));
            },
        );
        fn collect(s: egui::epaint::Shape, out: &mut String) {
            match s {
                egui::epaint::Shape::Text(s) => {
                    out.push_str(&s.galley.job.text);
                    out.push('\n');
                }
                egui::epaint::Shape::Vec(v) => {
                    for s in v {
                        collect(s, out);
                    }
                }
                _ => {}
            }
        }
        let mut text = String::new();
        for s in output.shapes {
            collect(s.shape, &mut text);
        }
        for expected in [
            "Expected identity · Manual",
            "TxPDO 8 input bytes",
            "RxPDO 2 output bytes",
            "Requested host cycle",
            "readback await approved setup",
            "Runtime DC/SYNC remains disabled",
            ".local/proposed.csv",
            "Counter",
            "Staged RxPDO bytes are not sent",
            "Virtual fixture",
            "excluded from physical bench topology",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
        assert!(app.session.is_none() && app.scan.is_none());
    }

    #[test]
    fn pinned_acknowledgement_fits_small_window_and_resets_after_settings_change() {
        for size in [egui::vec2(820.0, 560.0), egui::vec2(1100.0, 840.0)] {
            let mut app = app();
            app.profile.name = "Long configured profile ".repeat(80);
            app.csv = format!(".local/{}capture.csv", "deep/".repeat(200));
            app.connect_open = true;
            app.connect_page = ConnectPage::Bench;
            let ctx = egui::Context::default();
            let mut draw = |events| {
                ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                        events,
                        ..Default::default()
                    },
                    |ctx| app.show_workspace(ctx),
                )
            };
            draw(vec![]);
            let output = draw(vec![]);
            fn collect(s: egui::epaint::Shape, out: &mut Vec<(String, egui::Rect)>) {
                match s {
                    egui::epaint::Shape::Text(s) => out.push((
                        s.galley.job.text.clone(),
                        egui::Rect::from_min_size(s.pos, s.galley.size()),
                    )),
                    egui::epaint::Shape::Vec(v) => {
                        for s in v {
                            collect(s, out);
                        }
                    }
                    _ => {}
                }
            }
            let mut labels = Vec::new();
            for s in output.shapes {
                collect(s.shape, &mut labels);
            }
            let (_, bounds) = labels
                .iter()
                .find(|(s, _)| s.starts_with("Approved: isolated one-device bench"))
                .expect("visible pinned acknowledgement");
            assert!(
                bounds.min.x >= 0.0
                    && bounds.max.x <= size.x
                    && bounds.min.y >= 0.0
                    && bounds.max.y <= size.y,
                "{bounds:?}"
            );
            let pos = bounds.center();
            draw(vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: Default::default(),
                },
            ]);
            draw(vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: Default::default(),
            }]);
            assert!(app.bench_ready());
            app.seconds += 1;
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    ..Default::default()
                },
                |ctx| app.show_workspace(ctx),
            );
            assert!(!app.approved && app.approved_settings.is_none());
            assert!(app.session.is_none());
        }
    }
}

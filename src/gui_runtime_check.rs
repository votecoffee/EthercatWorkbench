//! Explicit, asynchronous host metadata checks; never opens a capture adapter.
use anyhow::{Context, Result, ensure};
use eframe::egui;
use ethercat_workbench::runtime_check::{self, HostStatus, Observation, Report, State};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    thread::JoinHandle,
};

#[derive(Clone, Copy)]
enum Activity {
    Check,
    Export,
}

enum Completion {
    Checked(Arc<Report>),
    Saved(PathBuf),
}

#[derive(Default)]
pub(super) struct Panel {
    pub open: bool,
    job: Option<(Activity, JoinHandle<Result<Completion>>)>,
    report: Option<Arc<Report>>,
    export: String,
    message: String,
}

impl Panel {
    pub fn is_running(&self) -> bool {
        self.job.is_some()
    }

    pub fn refresh(&mut self, ctx: &egui::Context) {
        if self
            .job
            .as_ref()
            .is_some_and(|(_, worker)| worker.is_finished())
        {
            match self.job.take().expect("finished metadata job").1.join() {
                Ok(Ok(Completion::Checked(report))) => {
                    self.report = Some(report);
                    self.message =
                        "Host observations collected. Capture access remains unprobed.".into();
                }
                Ok(Ok(Completion::Saved(path))) => {
                    self.message = format!("Host observations saved · {}", path.display())
                }
                Ok(Err(error)) => self.message = format!("{error:#}"),
                Err(_) => {
                    self.message =
                        "Host metadata worker failed. Previous observations are retained.".into()
                }
            }
        }
        if self.is_running() {
            ctx.request_repaint_after(std::time::Duration::from_millis(80));
        }
    }

    pub(super) fn begin_check(
        &mut self,
        blocked: bool,
        collect: impl FnOnce() -> Report + Send + 'static,
    ) -> bool {
        if blocked || self.is_running() {
            self.message =
                "Wait for active acquisition, discovery, review or host work to finish.".into();
            return false;
        }
        self.message.clear();
        self.job = Some((
            Activity::Check,
            std::thread::spawn(move || Ok(Completion::Checked(Arc::new(collect())))),
        ));
        true
    }

    fn begin_export(&mut self, blocked: bool) -> bool {
        if blocked || self.is_running() {
            self.message =
                "Wait for active acquisition, discovery, review or host work to finish.".into();
            return false;
        }
        let Some(report) = self.report.clone() else {
            return false;
        };
        let path = PathBuf::from(self.export.trim());
        self.message.clear();
        self.job = Some((
            Activity::Export,
            std::thread::spawn(move || {
                save_new(&report, &path)?;
                Ok(Completion::Saved(path))
            }),
        ));
        true
    }

    pub fn show(&mut self, ctx: &egui::Context, blocked: bool) {
        if !self.open {
            return;
        }
        let mut open = true;
        egui::Window::new("Host prerequisites")
            .open(&mut open)
            .default_width(650.0)
            .max_width((ctx.screen_rect().width() - 40.0).max(200.0))
            .max_height((ctx.screen_rect().height() - 60.0).max(150.0))
            .vscroll(true)
            .show(ctx, |ui| self.body(ui, blocked));
        self.open = open;
    }

    fn body(&mut self, ui: &mut egui::Ui, blocked: bool) {
        ui.label("Read local Npcap file, service and policy metadata. This check does not enumerate NICs, open adapters, transmit, change services or edit the registry.");
        ui.strong("Capture access: unprobed");
        ui.label(
            "These observations do not approve SAFEOP setup or establish device compatibility.",
        );
        if blocked {
            ui.label("Host checks and exports are locked while acquisition, discovery or saved-file review is active.");
        }
        if let Some((activity, _)) = &self.job {
            ui.label(match activity {
                Activity::Check => "Checking host metadata…",
                Activity::Export => "Saving host observations…",
            });
        }
        if !self.message.is_empty() {
            ui.label(&self.message);
        }
        if ui
            .add_enabled(
                !blocked && !self.is_running(),
                egui::Button::new("Check host metadata"),
            )
            .clicked()
        {
            self.begin_check(blocked, runtime_check::collect);
        }
        let Some(report) = &self.report else {
            ui.label("No observations collected. Opening this window does not run the check.");
            return;
        };
        ui.separator();
        show_report(ui, report);
        ui.separator();
        ui.add_enabled_ui(!blocked && !self.is_running(), |ui| {
            ui.label("New host report JSON");
            ui.add(
                egui::TextEdit::singleline(&mut self.export)
                    .hint_text(".local/host-prerequisites.json")
                    .desired_width(f32::INFINITY),
            );
            if ui
                .add_enabled(
                    !self.export.trim().is_empty(),
                    egui::Button::new("Save new host JSON"),
                )
                .clicked()
            {
                self.begin_export(blocked);
            }
        });
    }
}

fn state_label(state: State) -> &'static str {
    match state {
        State::Available => "available",
        State::Missing => "missing",
        State::Unavailable => "unavailable",
        State::Invalid => "invalid",
        State::NotQueried => "not queried",
    }
}

fn observation<T>(
    ui: &mut egui::Ui,
    label: &str,
    value: &Observation<T>,
    format: impl FnOnce(&T) -> String,
) {
    let detail = value
        .value
        .as_ref()
        .map(format)
        .unwrap_or_else(|| "unknown".into());
    ui.label(format!("{label} · {} · {detail}", state_label(value.state)));
    if let Some(code) = value.os_error {
        ui.small(format!("{label} · OS error {code}"));
    }
}

fn show_report(ui: &mut egui::Ui, r: &Report) {
    ui.label(format!(
        "Observed at {} · {} / {} bit · historical host snapshot",
        r.captured_at_utc, r.application_architecture, r.pointer_bits
    ));
    ui.strong(match r.host_status {
        HostStatus::MissingPrerequisites => "Required Npcap files or service are missing",
        HostStatus::IncompatibleImage => "An inspected DLL header is incompatible",
        HostStatus::ObservationUnavailable => "Required observations are unavailable",
        HostStatus::ServiceNotRunning => "Npcap service was not running",
        HostStatus::PresentUnprobed => "Files and running service observed; access still unprobed",
    });
    for dll in &r.dlls {
        ui.strong(&dll.name);
        observation(ui, "Image header", &dll.image, |v| {
            format!("{} · PE32+ {} · DLL {}", v.architecture, v.pe32_plus, v.dll)
        });
        observation(ui, "Literal file version", &dll.file_version, Clone::clone);
    }
    observation(ui, "Npcap service", &r.service, |v| {
        format!("{} (code {})", v.state, v.state_code)
    });
    observation(ui, "Recorded AdminOnly option", &r.admin_only, |v| {
        v.to_string()
    });
    ui.small("A missing/unreadable policy is unknown. A recorded false value is not an effective capture-permission test.");
    ui.collapsing("Paths, errors and raw host JSON", |ui| {
        for dll in &r.dlls {
            if let Some(path) = &dll.path {
                ui.label(format!("{} · {}", dll.name, path.display()));
            }
        }
        for note in &r.notes {
            ui.label(note);
        }
        ui.label(
            egui::RichText::new(serde_json::to_string_pretty(r).unwrap_or_default()).monospace(),
        );
    });
}

fn save_new(report: &Report, path: &Path) -> Result<()> {
    use std::io::Write;
    ensure!(
        path.extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("json")),
        "host inspection output must end in .json"
    );
    let mut file = std::fs::File::create_new(path)
        .context("create new host inspection output; existing paths are preserved")?;
    serde_json::to_writer_pretty(&mut file, report)?;
    writeln!(file)?;
    file.sync_all().context("flush host inspection output")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethercat_workbench::runtime_check::{Dll, LoadedModules, PeImage, Service};
    use std::time::{Duration, Instant};

    fn observed<T>(value: T) -> Observation<T> {
        Observation {
            state: State::Available,
            value: Some(value),
            detail: None,
            os_error: None,
        }
    }

    fn fixture() -> Report {
        Report {
            schema: 1,
            app_version: env!("CARGO_PKG_VERSION").into(),
            captured_at_utc: "2026-11-19T00:00:00Z".into(),
            scope: "host_prerequisites_only".into(),
            application_architecture: "x86_64".into(),
            pointer_bits: 64,
            system_directory: observed(PathBuf::from("authored-system")),
            dlls: vec![Dll {
                name: "wpcap.dll".into(),
                path: Some("authored-system/Npcap/wpcap.dll".into()),
                image: observed(PeImage {
                    machine: 0x8664,
                    architecture: "AMD64".into(),
                    pe32_plus: true,
                    dll: true,
                    bytes: 1024,
                }),
                file_version: observed("1.2.3.4".into()),
            }],
            service_name: "npcap".into(),
            service: observed(Service {
                state_code: 4,
                state: "running".into(),
            }),
            admin_only_registry_path: "authored-policy".into(),
            admin_only: observed(false),
            host_status: HostStatus::PresentUnprobed,
            capture_access: "not_probed".into(),
            npcap_modules_before: LoadedModules {
                wpcap: false,
                packet: false,
            },
            npcap_modules_after: LoadedModules {
                wpcap: false,
                packet: false,
            },
            notes: vec!["Authored GUI fixture; no host queries.".into()],
        }
    }

    fn wait(panel: &mut Panel) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while panel.is_running() {
            assert!(
                Instant::now() < deadline,
                "metadata worker did not complete"
            );
            panel.refresh(&egui::Context::default());
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    // Pure egui layout; never creates a native window or executes a host query.
    fn text(draw: impl FnMut(&egui::Context)) -> String {
        let ctx = egui::Context::default();
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(820.0, 560.0),
                )),
                ..Default::default()
            },
            draw,
        );
        fn collect(shape: &egui::epaint::Shape, out: &mut String) {
            match shape {
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
        let mut out = String::new();
        for shape in output.shapes {
            collect(&shape.shape, &mut out);
        }
        out
    }

    fn body_text(panel: &mut Panel, blocked: bool) -> String {
        text(|ctx| {
            egui::CentralPanel::default().show(ctx, |ui| panel.body(ui, blocked));
        })
    }

    #[test]
    fn opening_window_never_collects_and_empty_state_explains_scope() {
        let mut panel = Panel {
            open: true,
            ..Default::default()
        };
        text(|ctx| panel.show(ctx, false));
        let labels = body_text(&mut panel, false);
        for expected in [
            "Capture access: unprobed",
            "does not enumerate NICs",
            "does not run the check",
            "Check host metadata",
        ] {
            assert!(labels.contains(expected), "{labels}");
        }
        assert!(panel.report.is_none() && !panel.is_running());
    }

    #[test]
    fn layout_keeps_false_zero_missing_and_unavailable_distinct() {
        for (state, value, label) in [
            (State::Available, Some(false), "available · false"),
            (State::Available, Some(true), "available · true"),
            (State::Missing, None, "missing · unknown"),
            (State::Unavailable, None, "unavailable · unknown"),
        ] {
            let mut report = fixture();
            report.admin_only = Observation {
                state,
                value,
                detail: Some("Authored policy".into()),
                os_error: Some(5),
            };
            report.service = observed(Service {
                state_code: 0,
                state: "unknown-state".into(),
            });
            report.host_status = HostStatus::ObservationUnavailable;
            let mut panel = Panel {
                report: Some(Arc::new(report)),
                ..Default::default()
            };
            let labels = body_text(&mut panel, false);
            for expected in [
                label,
                "code 0",
                "OS error 5",
                "historical host snapshot",
                "Capture access: unprobed",
            ] {
                assert!(labels.contains(expected), "missing {expected}: {labels}");
            }
            assert!(
                !labels.contains("authored-system"),
                "raw paths should start collapsed"
            );
        }
    }

    #[test]
    fn asynchronous_jobs_are_exclusive_and_survive_window_close() {
        let mut panel = Panel::default();
        assert!(!panel.begin_check(true, || panic!("blocked collector ran")));
        let (send, receive) = std::sync::mpsc::channel();
        assert!(panel.begin_check(false, move || {
            receive.recv().unwrap();
            fixture()
        }));
        assert!(!panel.begin_check(false, || panic!("overlapping collector ran")));
        assert!(!panel.begin_export(false));
        panel.open = false;
        assert!(body_text(&mut panel, false).contains("Checking host metadata"));
        send.send(()).unwrap();
        wait(&mut panel);
        assert_eq!(
            panel.report.as_ref().unwrap().captured_at_utc,
            "2026-11-19T00:00:00Z"
        );
        assert_eq!(panel.report.as_ref().unwrap().capture_access, "not_probed");
    }

    #[test]
    fn export_freezes_its_path_and_report_and_preserves_existing_files() {
        let dir = PathBuf::from(".local").join(format!(
            "host-gui-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let saved = dir.join("saved.json");
        let edited = dir.join("edited.json");
        let mut panel = Panel {
            report: Some(Arc::new(fixture())),
            export: saved.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let expected = serde_json::to_value(panel.report.as_ref().unwrap()).unwrap();
        assert!(!panel.begin_export(true));
        assert!(!saved.exists());
        assert!(panel.begin_export(false));
        panel.export = edited.to_string_lossy().into_owned();
        wait(&mut panel);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&saved).unwrap()).unwrap(),
            expected
        );
        assert!(!edited.exists());
        let bytes = std::fs::read(&saved).unwrap();
        panel.export = saved.to_string_lossy().into_owned();
        assert!(panel.begin_export(false));
        wait(&mut panel);
        assert!(panel.message.contains("existing paths are preserved"));
        assert_eq!(std::fs::read(&saved).unwrap(), bytes);
        panel.export = dir.join("invalid.bin").to_string_lossy().into_owned();
        assert!(panel.begin_export(false));
        wait(&mut panel);
        assert!(panel.message.contains("must end in .json"));
        assert!(!dir.join("invalid.bin").exists());
        std::fs::remove_file(saved).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn failed_worker_preserves_previous_observations() {
        let mut panel = Panel {
            report: Some(Arc::new(fixture())),
            ..Default::default()
        };
        assert!(panel.begin_check(false, || panic!("authored metadata worker failure")));
        wait(&mut panel);
        assert!(panel.message.contains("worker failed"));
        assert_eq!(
            panel.report.as_ref().unwrap().captured_at_utc,
            "2026-11-19T00:00:00Z"
        );
    }

    #[test]
    fn host_job_blocks_bus_starts_and_configuration_across_tabs() {
        use crate::{App, Args, Mode, Tab};
        use clap::Parser;
        let mut app = App::new(Args::parse_from(["ethercat-workbench"]));
        let (send, receive) = std::sync::mpsc::channel();
        app.host_check.begin_check(false, move || {
            receive.recv().unwrap();
            fixture()
        });
        app.start(Mode::Simulate { faults: false });
        assert!(app.session.is_none() && app.generation == 0);
        for tab in [
            Tab::Device,
            Tab::Outputs,
            Tab::Logging,
            Tab::Mappings,
            Tab::Integration,
        ] {
            app.tab = tab;
            let labels = text(|ctx| app.show_workspace(ctx));
            assert!(
                labels.contains("Settings are locked") && labels.contains("host check finishes")
            );
        }
        app.tab = Tab::Review;
        assert!(text(|ctx| app.show_workspace(ctx)).contains("wait for host metadata work"));
        send.send(()).unwrap();
        wait(&mut app.host_check);
        assert!(!app.busy());
    }

    #[test]
    fn close_defers_until_background_work_finishes() {
        use crate::{App, Args};
        use clap::Parser;
        let mut app = App::new(Args::parse_from(["ethercat-workbench"]));
        let (send, receive) = std::sync::mpsc::channel();
        app.host_check.begin_check(false, move || {
            receive.recv().unwrap();
            fixture()
        });
        let ctx = egui::Context::default();
        let output = ctx.run(Default::default(), |ctx| {
            app.prepare_close(ctx);
            app.refresh(ctx);
        });
        let commands = &output.viewport_output[&egui::ViewportId::ROOT].commands;
        assert!(
            commands
                .iter()
                .any(|c| matches!(c, egui::ViewportCommand::CancelClose))
        );
        assert!(
            !commands
                .iter()
                .any(|c| matches!(c, egui::ViewportCommand::Close))
        );
        send.send(()).unwrap();
        wait(&mut app.host_check);
        let output = ctx.run(Default::default(), |ctx| app.refresh(ctx));
        assert!(
            output.viewport_output[&egui::ViewportId::ROOT]
                .commands
                .iter()
                .any(|c| matches!(c, egui::ViewportCommand::Close))
        );
    }
}

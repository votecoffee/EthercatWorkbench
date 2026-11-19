//! The finished worker owns the report and the CSV base used by that run.
use super::*;
use ethercat_workbench::review::Input;

pub(super) struct CompletedRun {
    report: Report,
    csv_base: Option<PathBuf>,
    report_destination: String,
    saved_report: Option<PathBuf>,
}

impl CompletedRun {
    pub(super) fn new(report: Report, csv_base: Option<PathBuf>) -> Self {
        // An attempted capture may have failed before the writer started.
        let csv_base = csv_base.filter(|_| report.capture.is_some());
        let report_destination = csv_base.as_ref().map_or_else(String::new, |base| {
            base.with_extension("run.json")
                .to_string_lossy()
                .into_owned()
        });
        Self {
            report,
            csv_base,
            report_destination,
            saved_report: None,
        }
    }

    pub(super) fn save(&mut self, path: PathBuf) -> anyhow::Result<()> {
        write_report(&path, &self.report)?;
        self.saved_report = Some(path);
        Ok(())
    }

    fn audit_input(&self) -> Option<Input> {
        Some(Input {
            report: self.saved_report.clone()?,
            csv: Some(self.csv_base.clone()?),
        })
    }
}

impl App {
    pub(super) fn completed_run_controls(&mut self, ui: &mut egui::Ui) {
        if self.session.is_some() {
            return;
        }
        let blocked = self.busy();
        let Some(run) = &mut self.completed_run else {
            return;
        };
        let mut audit = None;
        ui.group(|ui| {
            ui.strong(format!(
                "Completed run · generation {} · {}",
                run.report.connection_generation, run.report.backend
            ));
            if let (Some(base), Some(capture)) = (&run.csv_base, &run.report.capture) {
                ui.label(format!(
                    "CSV base · {} · {} written · {} parts",
                    base.display(),
                    capture.written,
                    capture.parts
                ));
            } else {
                ui.label("No CSV capture recorded");
            }
            if let Some(path) = &run.saved_report {
                ui.label(format!("Saved report · {}", path.display()));
            }
            ui.label("New report JSON");
            ui.add_enabled_ui(!blocked, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut run.report_destination)
                            .hint_text(".local/bench-report.json")
                            .desired_width(360.0),
                    );
                    let can_save = !run.report_destination.trim().is_empty();
                    let save = ui
                        .add_enabled(can_save, egui::Button::new("Save report"))
                        .clicked();
                    let save_and_audit = run.saved_report.is_none()
                        && run.csv_base.is_some()
                        && ui
                            .add_enabled(can_save, egui::Button::new("Save report and audit"))
                            .clicked();
                    if save || save_and_audit {
                        let path = PathBuf::from(run.report_destination.trim());
                        let result = if path
                            .extension()
                            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
                        {
                            run.save(path)
                        } else {
                            Err(anyhow::anyhow!("Choose a report path ending in .json"))
                        };
                        match result {
                            Ok(()) => {
                                run.report_destination.clear();
                                self.message = "Run report saved".into();
                                if save_and_audit {
                                    audit = run.audit_input();
                                }
                            }
                            Err(error) => self.message = format!("Write new run report: {error:#}"),
                        }
                    }
                });
                if let Some(input) = run.audit_input()
                    && ui.button("Audit saved capture").clicked()
                {
                    audit = Some(input);
                }
            });
        });
        if let Some(input) = audit {
            self.review.start_capture_audit(input);
            self.tab = Tab::Review;
        }
    }
}

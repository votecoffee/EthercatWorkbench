use eframe::egui;
use ethercat_workbench::{
    benchmark::Comparison,
    capture_audit::Audit,
    review::{Controller, Input, Outcome, State, Task},
};
use std::path::{Path, PathBuf};

#[derive(Default)]
struct Row {
    report: String,
    csv: String,
}
impl Row {
    fn input(&self) -> Input {
        Input {
            report: PathBuf::from(self.report.trim()),
            csv: (!self.csv.trim().is_empty()).then(|| PathBuf::from(self.csv.trim())),
        }
    }
}

pub struct Panel {
    rows: Vec<Row>,
    audit_csv: bool,
    controller: Controller,
    export: String,
    message: String,
}
impl Default for Panel {
    fn default() -> Self {
        Self {
            rows: vec![Row::default(), Row::default()],
            audit_csv: true,
            controller: Controller::default(),
            export: String::new(),
            message: String::new(),
        }
    }
}

impl Panel {
    pub fn is_running(&self) -> bool {
        self.controller.is_running()
    }
    pub fn cancel(&mut self) {
        self.controller.cancel();
    }
    pub fn refresh(&mut self, ctx: &egui::Context) {
        self.controller.poll();
        if self.is_running() {
            ctx.request_repaint_after(std::time::Duration::from_millis(80));
        }
    }
    fn start(&mut self, task: Task) {
        self.message = match self.controller.start(task) {
            Ok(()) => String::new(),
            Err(error) => format!("{error:#}"),
        };
    }

    pub fn draw(&mut self, ui: &mut egui::Ui, bus_busy: bool) {
        ui.label(
            "Review completed run reports and CSV files. These actions do not access the bus.",
        );
        if bus_busy {
            ui.label("Stop the active bus or discovery job before starting a file review.");
        }
        ui.label(self.controller.state().label());
        if let Some(error) = self.controller.error() {
            ui.colored_label(egui::Color32::LIGHT_RED, error);
        }
        if !self.message.is_empty() {
            ui.label(&self.message);
        }
        if self.is_running()
            && ui
                .add_enabled(
                    self.controller.state() == State::Running,
                    egui::Button::new("Cancel file review"),
                )
                .clicked()
        {
            self.cancel();
        }
        let mut audit = None;
        let mut move_row = None;
        let mut remove = None;
        let len = self.rows.len();
        ui.add_enabled_ui(!self.is_running() && !bus_busy, |ui| {
            for (index,row) in self.rows.iter_mut().enumerate() {
                ui.push_id(index, |ui| {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(format!("Trial {} · saved report",index+1));
                            ui.add(egui::TextEdit::singleline(&mut row.report).hint_text(".local/trial.json").desired_width(410.0));
                            if ui.add_enabled(index>0,egui::Button::new("Up")).clicked() { move_row=Some((index,index-1)); }
                            if ui.add_enabled(index+1<len,egui::Button::new("Down")).clicked() { move_row=Some((index,index+1)); }
                            if ui.add_enabled(len>1,egui::Button::new("Remove")).clicked() { remove=Some(index); }
                        });
                        ui.horizontal(|ui| {
                            ui.label("CSV base");
                            ui.add(egui::TextEdit::singleline(&mut row.csv).hint_text(".local/trial.csv").desired_width(410.0));
                            if ui.add_enabled(!row.report.trim().is_empty() && !row.csv.trim().is_empty(),
                                egui::Button::new("Audit this capture")).clicked() { audit=Some(row.input()); }
                        });
                    });
                });
            }
            if ui.add_enabled(len<32,egui::Button::new("Add trial")).clicked() { self.rows.push(Row::default()); }
            ui.checkbox(&mut self.audit_csv,"Audit CSV files during comparison");
            ui.label("Put trials in capture-start order. Both Deadline and Stock relative are required; three runs each are recommended.");
            if ui.add_enabled(self.rows.len()>=2 && self.rows.iter().all(|row| !row.report.trim().is_empty()
                && (!self.audit_csv || !row.csv.trim().is_empty())),egui::Button::new("Compare saved trials")).clicked() {
                self.start(Task::Compare { inputs:self.rows.iter().map(Row::input).collect(),audit_csv:self.audit_csv });
            }
        });
        if let Some((a, b)) = move_row {
            self.rows.swap(a, b);
        }
        if let Some(index) = remove {
            self.rows.remove(index);
        }
        if let Some(input) = audit {
            self.start(Task::Audit(input));
        }

        if let Some(completed) = self.controller.completed() {
            ui.separator();
            ui.strong("Result from the completed job");
            ui.label("Editing the path fields above does not change this result's saved inputs.");
            let inputs = match &completed.task {
                Task::Audit(input) => std::slice::from_ref(input),
                Task::Compare { inputs, .. } => inputs.as_slice(),
            };
            ui.collapsing("Inputs used", |ui| {
                let used_csv = matches!(
                    completed.task,
                    Task::Audit(_)
                        | Task::Compare {
                            audit_csv: true,
                            ..
                        }
                );
                for input in inputs {
                    ui.label(input.report.display().to_string());
                    if let Some(csv) = &input.csv
                        && used_csv
                    {
                        ui.label(format!("CSV base · {}", csv.display()));
                    }
                }
            });
            match &completed.outcome {
                Outcome::Audit(result) => show_audit(ui, result),
                Outcome::Comparison(result) => show_comparison(ui, result),
            }
            ui.add_enabled_ui(!self.is_running() && !bus_busy, |ui| {
                ui.horizontal(|ui| {
                    ui.label("New review JSON");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.export)
                            .hint_text(".local/review-result.json")
                            .desired_width(360.0),
                    );
                    if ui
                        .add_enabled(
                            !self.export.trim().is_empty(),
                            egui::Button::new("Save new result"),
                        )
                        .clicked()
                    {
                        self.message = match self.controller.save_new(Path::new(self.export.trim()))
                        {
                            Ok(()) => "Review result saved; source files preserved".into(),
                            Err(error) => format!("{error:#}"),
                        };
                    }
                });
            });
        }
    }
}

fn warnings(ui: &mut egui::Ui, warnings: &[String]) {
    egui::CollapsingHeader::new("Evidence limits and warnings")
        .default_open(true)
        .show(ui, |ui| {
            for warning in warnings {
                ui.label(warning);
            }
        });
}

fn show_audit(ui: &mut egui::Ui, audit: &Audit) {
    ui.strong(format!(
        "CSV structure passed · {} rows · {} parts",
        audit.rows,
        audit.parts.len()
    ));
    ui.label(format!(
        "Recorded app {} · auditor {} · {:?} logging · generation {}",
        audit.app_version, audit.auditor_version, audit.mode, audit.connection_generation
    ));
    ui.label(format!("Valid exchanges {} · invalid {} · reply timeouts {} · WKC mismatches {} · AL mismatches {} · transport errors {}",
        audit.valid_exchanges,audit.invalid_exchanges,audit.reply_timeouts,audit.wkc_mismatches,audit.state_mismatches,audit.transport_errors));
    ui.label(format!(
        "Logger overruns {} · index gaps: leading {}, interior {}, trailing {}",
        audit.logger_overruns,
        audit.leading_index_gap,
        audit.interior_index_gaps,
        audit.trailing_index_gap
    ));
    ui.label(format!(
        "Non-finite values {} · ambiguous NaN repeats {}",
        audit.non_finite_values, audit.ambiguous_nan_repeats
    ));
    if audit.run_cancelled {
        ui.colored_label(egui::Color32::YELLOW, "The captured run was cancelled.");
    }
    if let Some(error) = &audit.run_error {
        ui.colored_label(
            egui::Color32::LIGHT_RED,
            format!("Captured run failed · {error}"),
        );
    }
    ui.collapsing("Capture fields and file hashes", |ui| {
        ui.label(audit.report.display().to_string());
        ui.monospace(&audit.report_sha256);
        ui.label(format!("Selected fields · {}", audit.fields.join(", ")));
        for part in audit.parts.iter().take(32) {
            ui.label(format!(
                "{} · {} rows · {} bytes · {}",
                part.file.display(),
                part.rows,
                part.bytes,
                part.eol
            ));
            ui.monospace(&part.sha256);
        }
        if audit.parts.len() > 32 {
            ui.label("The first 32 parts are shown. Export JSON for all hashes.");
        }
    });
    warnings(ui, &audit.warnings);
}

fn show_comparison(ui: &mut egui::Ui, result: &Comparison) {
    ui.strong(format!(
        "{} compatible saved trials · {} · {:?}",
        result.trials.len(),
        result.app_version,
        result.frontend
    ));
    ui.label(format!(
        "Requested {} µs · duration limit {} µs · CSV audit {}",
        result.common_profile_settings["requested_cycle_us"],
        result.duration_limit_us,
        if result.csv_audits.is_some() {
            "included"
        } else {
            "not requested"
        }
    ));
    for group in &result.schedules {
        ui.label(format!(
            "{:?} · {} trials · per-run receive p99 min {} / median {:.1} / max {} µs",
            group.scheduler,
            group.trials,
            group.receive_p99_us.min,
            group.receive_p99_us.median,
            group.receive_p99_us.max
        ));
    }
    ui.label("Per-trial host spacing in microseconds; percentile summaries are not pooled.");
    egui::ScrollArea::horizontal()
        .id_salt("review-timing")
        .show(ui, |ui| {
            egui::Grid::new("review-timing-grid")
                .striped(true)
                .show(ui, |ui| {
                    for text in ["Trial", "Direction", "p50", "p95", "p99", "Longest gap"] {
                        ui.strong(text);
                    }
                    ui.end_row();
                    for (index, trial) in result.trials.iter().enumerate() {
                        for (direction, spacing) in [
                            ("Send", &trial.send_spacing),
                            ("Receive", &trial.receive_spacing),
                        ] {
                            ui.label(format!("{} {:?}", index + 1, trial.scheduler));
                            ui.label(direction);
                            for value in [
                                spacing.p50_us,
                                spacing.p95_us,
                                spacing.p99_us,
                                spacing.longest_gap_us,
                            ] {
                                ui.label(value.map_or("unavailable".into(), |v| v.to_string()));
                            }
                            ui.end_row();
                        }
                    }
                });
        });
    egui::ScrollArea::horizontal()
        .id_salt("review-losses")
        .show(ui, |ui| {
            egui::Grid::new("review-loss-grid")
                .striped(true)
                .show(ui, |ui| {
                    for text in [
                        "Trial",
                        "Valid",
                        "Timeouts",
                        "WKC",
                        "AL",
                        "Missed",
                        "CSV written",
                        "Overruns",
                    ] {
                        ui.strong(text);
                    }
                    ui.end_row();
                    for (index, trial) in result.trials.iter().enumerate() {
                        ui.label((index + 1).to_string());
                        for value in [
                            trial.valid,
                            trial.timeouts,
                            trial.wkc_mismatches,
                            trial.state_mismatches,
                            trial.missed_deadlines,
                            trial.capture.written,
                            trial.capture.overruns,
                        ] {
                            ui.label(value.to_string());
                        }
                        ui.end_row();
                    }
                });
        });
    ui.collapsing("Trial files and hashes", |ui| {
        for (index, trial) in result.trials.iter().enumerate() {
            ui.label(format!(
                "Trial {} · {} · {}",
                index + 1,
                trial.file.display(),
                trial.utc_start
            ));
            ui.monospace(&trial.sha256);
        }
    });
    warnings(ui, &result.warnings);
}

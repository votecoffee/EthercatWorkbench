use eframe::egui;
use ethercat_workbench::{
    benchmark::Comparison,
    capture_audit::Audit,
    model::Profile,
    pcap_inspect,
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
    pcap_path: String,
    station: String,
    preview_limit: usize,
}
impl Default for Panel {
    fn default() -> Self {
        Self {
            rows: vec![Row::default(), Row::default()],
            audit_csv: true,
            controller: Controller::default(),
            export: String::new(),
            message: String::new(),
            pcap_path: String::new(),
            station: "0x1000".into(),
            preview_limit: 16,
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

    pub fn draw(&mut self, ui: &mut egui::Ui, bus_busy: bool, profile: &Profile) {
        ui.label(
            "Review saved run reports, CSV files or Ethernet PCAP. These actions do not access the bus.",
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
        ui.collapsing("Inspect a saved Ethernet PCAP", |ui| {
            ui.label("Uses a frozen copy of the current commissioning profile. Identity, station and field meanings are offline expectations.");
            ui.label(format!("Current profile · {} · {} input bytes · {} fields", profile.name, profile.tx_bytes, profile.tx.len()));
            ui.add_enabled_ui(!self.is_running() && !bus_busy, |ui| {
                ui.horizontal(|ui| {
                    ui.label("PCAP / PCAPNG");
                    ui.add(egui::TextEdit::singleline(&mut self.pcap_path)
                        .hint_text(".local/bench.pcap").desired_width(410.0));
                });
                ui.horizontal(|ui| {
                    ui.label("Expected station");
                    ui.add(egui::TextEdit::singleline(&mut self.station).desired_width(90.0));
                    ui.label("Payload previews (0–64)");
                    ui.add(egui::DragValue::new(&mut self.preview_limit).range(0..=64));
                });
                let station = ethercat_workbench::esi::number(self.station.trim())
                    .ok().and_then(|v| u16::try_from(v).ok()).filter(|v| (1..=0xfffe).contains(v));
                if station.is_none() { ui.label("Station must be 1–65534, in decimal or 0x hex."); }
                if ui.add_enabled(!self.pcap_path.trim().is_empty() && station.is_some(),
                    egui::Button::new("Inspect PCAP with current profile")).clicked() {
                    self.start(Task::InspectPcap {
                        file: PathBuf::from(self.pcap_path.trim()), profile: Box::new(profile.clone()),
                        station: station.expect("validated station"), preview_limit: self.preview_limit,
                    });
                }
            });
            ui.label("Up to 64 MiB. PCAPNG requires one Ethernet interface and microsecond/nanosecond timestamps. VLAN decoding is unsupported. Capture timestamps remain separate from application cycle timing.");
        });
        ui.separator();
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
                Task::InspectPcap { .. } => &[],
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
                if let Task::InspectPcap { file, profile, station, preview_limit } = &completed.task {
                    ui.label(format!("PCAP · {}", file.display()));
                    ui.label(format!("Frozen commissioning profile · {} · {} input bytes · station {station:#06x} · preview limit {preview_limit}",
                        profile.name, profile.tx_bytes));
                    if let Some(identity) = &profile.expected_identity {
                        ui.label(format!("Expected identity · {identity}"));
                    }
                    ui.label("Export JSON for the complete frozen profile, including ESI provenance and field transformations.");
                }
            });
            match &completed.outcome {
                Outcome::Audit(result) => show_audit(ui, result),
                Outcome::Comparison(result) => show_comparison(ui, result),
                Outcome::Pcap(result) => show_pcap(ui, result),
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

fn show_pcap(ui: &mut egui::Ui, report: &pcap_inspect::Report) {
    let counts = &report.counts;
    ui.label(format!(
        "Capture container · {} · inspection schema {}",
        report.capture_format, report.schema
    ));
    if let Some(metadata) = &report.pcapng {
        ui.label(format!("Interface 0 · Ethernet · snaplen {} · 10^-{} s ticks · signed offset {} s · blocks {} · skipped blocks/options {}/{}",
            metadata.snaplen, metadata.timestamp_resolution_exponent, metadata.timestamp_offset_seconds,
            metadata.blocks, metadata.skipped_blocks, metadata.skipped_options));
    }
    ui.strong(format!(
        "{} saved packets · {} recognized returned frames · {} valid SAFEOP frames",
        counts.packets, counts.replies, counts.valid_safeop_replies
    ));
    ui.label("Frame counts are independent; duplicates are retained. This result does not establish fresh exchanges or device identity.");
    ui.label(format!(
        "Capture timestamp precision · {} · first UTC {}",
        report.timestamp_resolution,
        report.capture_first_utc.as_deref().unwrap_or("unavailable")
    ));
    ui.label(format!(
        "Expected station {:#06x} · input WKC {} · profile requested period {} µs",
        report.station_address, report.expected_input_wkc, report.profile.requested_cycle_us
    ));
    egui::Grid::new("pcap-counts").striped(true).show(ui, |ui| {
        for (label, value) in [
            ("Recognized requests", counts.requests),
            ("Recognized returned frames", counts.replies),
            ("Valid SAFEOP returned frames", counts.valid_safeop_replies),
            ("Input WKC mismatches", counts.wkc_mismatches),
            ("AL status/WKC mismatches", counts.al_mismatches),
            ("Unmatched EtherCAT", counts.unmatched_ethercat),
            ("Other packets", counts.other_packets),
            ("Snapshot-truncated packets", counts.snapshot_truncated),
            ("VLAN packets (not decoded)", counts.vlan_packets),
            (
                "Capture timestamp regressions",
                counts.timestamp_regressions,
            ),
        ] {
            ui.label(label);
            ui.label(value.to_string());
            ui.end_row();
        }
    });
    ui.label("Recorded capture spacing in nanoseconds; capture precision does not establish timing accuracy.");
    if counts.timestamp_regressions != 0 {
        ui.colored_label(
            egui::Color32::YELLOW,
            "Capture timestamps regress; all spacing summaries are unavailable.",
        );
    }
    egui::ScrollArea::horizontal()
        .id_salt("pcap-spacing")
        .show(ui, |ui| {
            egui::Grid::new("pcap-spacing-grid")
                .striped(true)
                .show(ui, |ui| {
                    for text in ["Frames", "Gaps", "p50 ns", "p95 ns", "p99 ns", "Longest ns"] {
                        ui.strong(text);
                    }
                    ui.end_row();
                    for (name, spacing) in [
                        ("Requests", &report.request_spacing),
                        ("Returned", &report.reply_spacing),
                        ("Valid SAFEOP returned", &report.valid_reply_spacing),
                    ] {
                        ui.label(name);
                        ui.label(
                            spacing
                                .as_ref()
                                .map_or("unavailable".into(), |s| s.count.to_string()),
                        );
                        for value in [
                            spacing.as_ref().and_then(|s| s.p50_ns),
                            spacing.as_ref().and_then(|s| s.p95_ns),
                            spacing.as_ref().and_then(|s| s.p99_ns),
                            spacing.as_ref().and_then(|s| s.longest_gap_ns),
                        ] {
                            ui.label(value.map_or("unavailable".into(), |v| v.to_string()));
                        }
                        ui.end_row();
                    }
                });
        });
    ui.collapsing("Capture and profile hashes", |ui| {
        ui.label(format!(
            "{} · {} bytes · app {}",
            report.file, report.file_bytes, report.app_version
        ));
        ui.monospace(&report.file_sha256);
        ui.label(format!("Frozen profile · {}", report.profile.name));
        ui.monospace(&report.profile_sha256);
        if let Some(esi) = &report.profile.esi {
            ui.label(format!("ESI · {} · {}", esi.file_name, esi.device));
            ui.monospace(&esi.sha256);
        }
    });
    warnings(ui, &report.notes);
    ui.collapsing(
        format!(
            "{} returned-frame payload previews (limit {})",
            report.preview.len(),
            report.preview_limit
        ),
        |ui| {
            for packet in &report.preview {
                ui.collapsing(
                    format!(
                        "Packet {} · sequence {} · {}",
                        packet.packet_index,
                        packet.sequence,
                        if packet.valid_safeop {
                            "valid SAFEOP"
                        } else {
                            "invalid input quality"
                        }
                    ),
                    |ui| {
                        if !packet.valid_safeop {
                            ui.colored_label(
                                egui::Color32::YELLOW,
                                "Decoded bytes below are from a frame with invalid input quality.",
                            );
                        }
                        ui.label(format!(
                            "Capture timestamp {} ns since Unix epoch · input WKC {} · AL WKC {}",
                            packet.timestamp_unix_ns, packet.input_wkc, packet.al_wkc
                        ));
                        let al =
                            ethercat_workbench::esc::al_status(packet.al_status, packet.al_code);
                        ui.label(format!(
                            "AL {:#06x} · {} · code {:#06x}: {}",
                            packet.al_status, al.state, packet.al_code, al.description
                        ));
                        ui.monospace(&packet.payload_hex);
                        egui::Grid::new("pcap-values").striped(true).show(ui, |ui| {
                            for text in ["Field", "Profile source", "Decoded value"] {
                                ui.strong(text);
                            }
                            ui.end_row();
                            for value in &packet.values {
                                ui.label(&value.field);
                                ui.label(format!("{:?}", value.source));
                                ui.label(value.value.as_deref().unwrap_or("unavailable"));
                                ui.end_row();
                            }
                        });
                    },
                );
            }
        },
    );
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
    for (index, trial) in result.trials.iter().enumerate() {
        if let Some(http) = &trial.http {
            ui.label(format!("Trial {} HTTP · offered {} · dispatched {} · queue drops {} · pending {} · history evictions {} · I/O errors {} · worker failed {}",
                index+1,http.offered,http.dispatched,http.queue_drops,http.pending,http.history_evictions,http.io_errors,http.worker_failed));
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    // Pure egui layout: no native window, desktop input, screenshot or GPU.
    fn text_from_layout(mut draw: impl FnMut(&mut egui::Ui)) -> String {
        let ctx = egui::Context::default();
        ctx.memory_mut(|memory| memory.set_everything_is_visible(true));
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1100.0, 5000.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| draw(ui));
            },
        );
        fn collect(shape: &egui::epaint::Shape, text: &mut String) {
            match shape {
                egui::epaint::Shape::Text(shape) => {
                    text.push_str(&shape.galley.job.text);
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
        text
    }

    #[test]
    fn pcap_layout_labels_invalid_payloads_and_unavailable_capture_spacing() {
        let report = pcap_inspect::Report {
            schema: 2,
            app_version: env!("CARGO_PKG_VERSION").into(),
            file: "Authored UI fixture".into(),
            file_bytes: 100,
            file_sha256: "0".repeat(64),
            profile: Profile {
                name: "Frozen profile".into(),
                tx_bytes: 1,
                ..Default::default()
            },
            profile_sha256: "1".repeat(64),
            station_address: 0x1000,
            expected_input_wkc: 1,
            timestamp_resolution: "nanoseconds".into(),
            capture_format: "pcapng".into(),
            pcapng: Some(pcap_inspect::PcapngMetadata {
                minor_version: 0,
                declared_section_bytes: None,
                interface_id: 0,
                link_type: 1,
                snaplen: 65535,
                timestamp_resolution_exponent: 9,
                timestamp_offset_seconds: -2,
                blocks: 4,
                skipped_blocks: 0,
                skipped_options: 1,
            }),
            capture_first_utc: None,
            first_timestamp_unix_ns: Some(100),
            last_timestamp_unix_ns: Some(90),
            counts: pcap_inspect::Counts {
                packets: 2,
                replies: 2,
                timestamp_regressions: 1,
                al_mismatches: 2,
                ..Default::default()
            },
            request_spacing: None,
            reply_spacing: None,
            valid_reply_spacing: None,
            preview_limit: 1,
            preview: vec![pcap_inspect::Preview {
                packet_index: 1,
                timestamp_unix_ns: 100,
                sequence: 8,
                input_wkc: 1,
                al_wkc: 1,
                al_status: 0x14,
                al_code: 0x1d,
                valid_safeop: false,
                payload_hex: "2A".into(),
                values: vec![pcap_inspect::Value {
                    field: "Authored value".into(),
                    source: ethercat_workbench::model::Source::Manual,
                    value: Some("42".into()),
                }],
            }],
            notes: vec!["Authored file evidence; hardware validity is unknown.".into()],
        };
        let text = text_from_layout(|ui| show_pcap(ui, &report));
        for expected in [
            "2 saved packets",
            "0 valid SAFEOP",
            "all spacing summaries are unavailable",
            "invalid input quality",
            "Decoded bytes below",
            "Authored value",
            "42",
            "2A",
            "Frozen profile",
            "Recorded capture spacing in nanoseconds",
            "hardware validity is unknown",
            "Capture container · pcapng",
            "signed offset -2 s",
        ] {
            assert!(
                text.contains(expected),
                "missing {expected:?} from layout: {text}"
            );
        }
    }

    #[test]
    fn pcap_editor_layout_retains_bus_exclusion_and_invalid_station_guidance() {
        let mut panel = Panel {
            station: "0x10000".into(),
            ..Default::default()
        };
        let profile = Profile::default();
        let text = text_from_layout(|ui| panel.draw(ui, true, &profile));
        assert!(!panel.is_running());
        for expected in [
            "Stop the active bus",
            "frozen copy",
            "Station must be 1–65534",
            "PCAPNG requires one Ethernet interface",
            "Inspect PCAP with current profile",
        ] {
            assert!(
                text.contains(expected),
                "missing {expected:?} from layout: {text}"
            );
        }
    }
}

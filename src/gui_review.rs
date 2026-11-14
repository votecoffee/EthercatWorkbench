use eframe::egui;
use ethercat_workbench::{
    benchmark::Comparison,
    capture_audit::Audit,
    model::Profile,
    pcap_inspect,
    review::{Controller, Input, Outcome, SharedDecoding, State, Task},
    shared_memory::reader,
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
    pcap_interface: String,
    shared_path: String,
    shared_mapping: SharedMapping,
    shared_report: String,
}
#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum SharedMapping {
    #[default]
    Raw,
    CurrentProfile,
    RunReport,
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
            pcap_interface: String::new(),
            shared_path: String::new(),
            shared_mapping: SharedMapping::Raw,
            shared_report: String::new(),
        }
    }
}

impl Panel {
    fn selected_interface(&self) -> anyhow::Result<Option<u32>> {
        let text = self.pcap_interface.trim();
        if text.is_empty() {
            return Ok(None);
        }
        let id = ethercat_workbench::esi::number(text)?;
        anyhow::ensure!(id < 32, "PCAPNG interface ID must be 0..31");
        Ok(Some(id))
    }
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

    fn shared_task(&self, profile: &Profile) -> anyhow::Result<Task> {
        let decoding = match self.shared_mapping {
            SharedMapping::Raw => SharedDecoding::Raw,
            SharedMapping::CurrentProfile => SharedDecoding::Profile(Box::new(profile.clone())),
            SharedMapping::RunReport => {
                SharedDecoding::RunReport(PathBuf::from(self.shared_report.trim()))
            }
        };
        let task = Task::InspectShared {
            file: PathBuf::from(self.shared_path.trim()),
            decoding,
        };
        task.validate()?;
        Ok(task)
    }

    pub fn draw(&mut self, ui: &mut egui::Ui, bus_busy: bool, profile: &Profile) {
        ui.label(
            "Review saved run reports, CSV, Ethernet PCAP or shared-input snapshots. These actions do not access the bus.",
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
                ui.horizontal(|ui|{ui.label("PCAPNG interface");ui.add(egui::TextEdit::singleline(&mut self.pcap_interface).hint_text("auto if sole").desired_width(100.0));});
                let interface = self.selected_interface();
                if interface.is_err(){ui.label("Interface must be 0–31, or blank for a sole interface.");}
                ui.label("Multiple interfaces require an explicit ID. Counts and timing use only that interface; original packet indexes are retained.");
                if ui.add_enabled(!self.pcap_path.trim().is_empty() && station.is_some() && interface.is_ok(),
                    egui::Button::new("Inspect PCAP with current profile")).clicked() {
                    self.start(Task::InspectPcap {
                        file: PathBuf::from(self.pcap_path.trim()), profile: Box::new(profile.clone()),
                        station: station.expect("validated station"), preview_limit: self.preview_limit,
                        interface: interface.expect("validated interface"),
                    });
                }
            });
            ui.label("Up to 64 MiB. PCAPNG supports one section, up to 32 interfaces and microsecond/nanosecond timestamps. Select an Ethernet interface. VLAN decoding is unsupported. Capture timestamps remain separate from application cycle timing.");
        });
        ui.collapsing("Inspect a saved shared-input snapshot",|ui|{
            ui.label("Historical file only. No IPC, process-liveness query, NIC or current-input check.");
            ui.add_enabled_ui(!self.is_running() && !bus_busy,|ui|{
                ui.horizontal(|ui|{ui.label("Snapshot (.bin)");ui.add(egui::TextEdit::singleline(&mut self.shared_path).hint_text(".local/input.bin").desired_width(410.0));});
                ui.horizontal(|ui|{ui.radio_value(&mut self.shared_mapping,SharedMapping::Raw,"Raw/status only");ui.radio_value(&mut self.shared_mapping,SharedMapping::CurrentProfile,"Current profile (frozen)");ui.radio_value(&mut self.shared_mapping,SharedMapping::RunReport,"Saved run's effective profile");});
                match self.shared_mapping {
                    SharedMapping::Raw=>{ui.label("Typed values are omitted. Raw bytes and recorded quality remain available.");},
                    SharedMapping::CurrentProfile=>{ui.label(format!("Freeze current profile · {} · {} input bytes · {} fields",profile.name,profile.tx_bytes,profile.tx.len()));},
                    SharedMapping::RunReport=>{ui.horizontal(|ui|{ui.label("Mapping run report");ui.add(egui::TextEdit::singleline(&mut self.shared_report).hint_text(".local/run.json").desired_width(410.0));});},
                }
                ui.label("Typed decoding requires the exact full profile hash. A mismatch fails; choose raw/status explicitly to inspect without a mapping.");
                let ready=!self.shared_path.trim().is_empty() && (self.shared_mapping!=SharedMapping::RunReport || !self.shared_report.trim().is_empty());
                if ui.add_enabled(ready,egui::Button::new("Inspect saved snapshot")).clicked(){match self.shared_task(profile){Ok(task)=>self.start(task),Err(error)=>self.message=format!("{error:#}")}}
            });
            ui.label("Exactly 2560 bytes, binary schema 1. Saved active/fresh flags never establish current usable input.");
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
                Task::InspectPcap { .. } | Task::InspectShared { .. } => &[],
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
                if let Task::InspectPcap { file, profile, station, preview_limit, interface } = &completed.task {
                    ui.label(format!("PCAP · {}", file.display()));
                    ui.label(format!("Frozen commissioning profile · {} · {} input bytes · station {station:#06x} · preview limit {preview_limit}",
                        profile.name, profile.tx_bytes));
                    if let Some(identity) = &profile.expected_identity {
                        ui.label(format!("Expected identity · {identity}"));
                    }
                    ui.label("Export JSON for the complete frozen profile, including ESI provenance and field transformations.");
                    ui.label(format!("PCAPNG interface choice · {}",interface.map_or("auto if sole".into(),|id|id.to_string())));
                }
                if let Task::InspectShared{file,decoding}=&completed.task{
                    ui.label(format!("Saved snapshot · {}",file.display()));
                    match decoding {
                        SharedDecoding::Raw=>{ui.label("Mapping choice · raw/status only");},
                        SharedDecoding::Profile(profile)=>{ui.label(format!("Frozen profile · {} · {} input bytes",profile.name,profile.tx_bytes));},
                        SharedDecoding::RunReport(path)=>{ui.label(format!("Mapping extracted from saved run · {}",path.display()));ui.label("Mapping extraction does not qualify that run or prove this snapshot came from it.");},
                    }
                }
            });
            match &completed.outcome {
                Outcome::Audit(result) => show_audit(ui, result),
                Outcome::Comparison(result) => show_comparison(ui, result),
                Outcome::Pcap(result) => show_pcap(ui, result),
                Outcome::Shared(result) => show_shared(ui, result),
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

fn shared_preview(text: &str) -> String {
    let mut chars = text.chars();
    let mut preview: String = chars.by_ref().take(512).collect();
    if chars.next().is_some() {
        preview.push_str(" … [preview truncated]");
    }
    preview
}
fn shared_payload(
    ui: &mut egui::Ui,
    title: &str,
    data: &reader::Payload,
    decoding: Option<&reader::Decoding>,
) {
    ui.collapsing(title,|ui|{
        ui.label("Raw TxPDO hex (complete captured payload)");ui.monospace(&data.payload_hex);
        if let Some(values)=&data.values {
            ui.label("Verified-profile typed input values. Long text previews stop at 512 characters; export JSON for complete values and definitions.");
            egui::ScrollArea::both().id_salt(title).max_height(260.0).show(ui,|ui|{
                egui::Grid::new((title,"values")).striped(true).show(ui,|ui|{
                    for label in ["Input field","Definition source","Bit:width","Recorded value"]{ui.strong(label);}ui.end_row();
                    for (name,value) in values {
                        let field=decoding.and_then(|d|d.tx_fields.iter().find(|f|f.name==*name));
                        ui.label(shared_preview(name));ui.label(field.map_or("unavailable".into(),|f|format!("{:?}",f.source)));
                        ui.label(field.map_or("unavailable".into(),|f|format!("{}:{}",f.bit,f.width)));ui.monospace(shared_preview(value));ui.end_row();
                    }
                });
            });
        }else{ui.label("Raw/status only · no verified typed mapping selected.");}
    });
}
fn show_shared(ui: &mut egui::Ui, report: &reader::Inspection) {
    ui.strong("Historical shared-input snapshot");
    if !matches!(&report.source, reader::Source::SavedFile { .. })
        || report.current_usable
        || report.observation.is_some()
    {
        ui.colored_label(egui::Color32::LIGHT_RED,"Unexpected live evidence in saved-file review; this result cannot be shown as historical input.");
        return;
    }
    ui.label(
        "Saved-file evidence only · current usable input: no · current age/liveness: unavailable.",
    );
    ui.label(format!(
        "Inspection schema {} · status {:?} · inspector {}",
        report.schema, report.status, report.app_version
    ));
    if let reader::Source::SavedFile { path } = &report.source {
        ui.label(format!("Snapshot file · {}", path.display()));
    }
    if let Some(hash) = &report.raw_sha256 {
        ui.label("Exact saved-byte SHA-256");
        ui.monospace(hash);
    }
    let Some(s) = &report.snapshot else {
        ui.label("Reserved/not-ready image · no input payload or verified mapping was captured.");
        return;
    };
    ui.label(format!(
        "Recorded backend · {} · stream {} · generation {}",
        s.backend, s.stream_id, s.generation
    ));
    ui.label(format!("Recorded producer flags · active {} · fresh at publication {}. These flags do not establish current input.",s.active,s.fresh_at_publication));
    ui.label(format!(
        "Recorded PID {} · process creation FILETIME {} (not queried)",
        s.publisher_pid, s.publisher_created_filetime
    ));
    ui.label(format!(
        "UTC anchor {} Unix µs · publication elapsed {} µs · publication attempt {}",
        s.utc_start_us, s.publication_elapsed_us, s.publication_index
    ));
    ui.label(format!(
        "Recorded publication QPC {} · frequency {}. No current clock comparison is performed.",
        s.publication_qpc, s.qpc_frequency
    ));
    ui.label(format!("Requested host cycle {} µs · publication period {} ms · freshness threshold {} ms · input bytes {}",s.requested_cycle_us,s.period_ms,s.freshness_ms,s.tx_bytes));
    ui.label("Device/DC synchronization, mapping verification and physical PDO meaning require the original run/profile evidence.");
    ui.collapsing("Recorded identity and mapping", |ui| {
        ui.label(format!(
            "Expected profile identity · {}",
            s.expected_identity
                .as_ref()
                .map_or("unavailable".into(), ToString::to_string)
        ));
        ui.label(format!(
            "Setup-observed identity · {}",
            s.observed_identity
                .as_ref()
                .map_or("unavailable".into(), ToString::to_string)
        ));
        ui.label(format!(
            "Setup station {:#06x} · bus position {}",
            s.station, s.position
        ));
        ui.label("Snapshot profile SHA-256");
        ui.monospace(s.profile_sha256.as_deref().unwrap_or("unavailable"));
        if let Some(decoding) = &report.decoding {
            ui.label(format!(
                "Verified full-profile hash · {} input definitions",
                decoding.tx_fields.len()
            ));
            ui.monospace(&decoding.profile_sha256);
        } else {
            ui.label("No typed mapping was verified; this is raw/status review.");
        }
    });
    if let Some(latest) = &s.latest {
        ui.strong(format!(
            "Latest recorded attempt · event {} · cycle {} · {}",
            latest.event_index,
            latest.cycle_index,
            if latest.valid_at_exchange {
                "valid at exchange"
            } else {
                "invalid input quality"
            }
        ));
        ui.label(format!("Receive/failed-attempt elapsed {} µs · age at publication {} µs · reply received {} · issue {}",latest.elapsed_us,latest.age_us_at_publication,latest.received,latest.issue));
        ui.label(format!(
            "Recorded WKC · expected {} · actual {}",
            latest.expected_wkc,
            latest
                .actual_wkc
                .map_or("unavailable".into(), |v| v.to_string())
        ));
        if let Some((status, code)) = latest.al_status.zip(latest.al_code) {
            let al = ethercat_workbench::esc::al_status(status, code);
            ui.label(format!(
                "Recorded AL {status:#06x} · {} · code {code:#06x}: {}",
                al.state, al.description
            ));
        } else {
            ui.label("Recorded AL status/code · unavailable");
        }
        if let Some(data) = &latest.data {
            shared_payload(
                ui,
                "Latest recorded payload",
                data,
                report.decoding.as_ref(),
            );
        } else {
            ui.colored_label(
                egui::Color32::YELLOW,
                "Invalid input · no current payload or typed values were exported.",
            );
        }
    } else {
        ui.label("No cyclic attempt was recorded in this initialized image.");
    }
    if let Some(last) = &s.last_valid {
        ui.strong(format!(
            "Historical last-valid input · event {} · cycle {}",
            last.event_index, last.cycle_index
        ));
        ui.label(format!(
            "Elapsed {} µs · age at publication {} µs · current age unavailable",
            last.elapsed_us, last.age_us_at_publication
        ));
        ui.label(
            "Historical payload only; its earlier WKC/AL readback is not stored in this format.",
        );
        shared_payload(
            ui,
            "Historical last-valid payload",
            &last.data,
            report.decoding.as_ref(),
        );
    } else {
        ui.label("No historical last-valid input is present.");
    }
    ui.collapsing("Recorded acquisition and consumer counters",|ui|{
        ui.label(format!("Bus · cycles {} · valid {} · timeouts {} · WKC mismatches {} · AL mismatches {} · transport errors {} · missed deadlines {}",s.cycles,s.valid_exchanges,s.timeouts,s.wkc_mismatches,s.al_mismatches,s.transport_errors,s.missed_deadlines));
        ui.label(format!("Shared input · offered {} · drained {} · queue drops {} · queue pending {} · coalesced {} · written events {} · copies {} · mutex misses {} · abandoned recoveries {}",s.offered,s.drained,s.queue_drops,s.queue_pending,s.coalesced,s.written_events,s.writes,s.lock_misses,s.abandoned_recoveries));
        if let Some(csv)=s.csv{ui.label(format!("CSV · selected {} · written {} · overruns {}",csv.selected,csv.written,csv.overruns));}else{ui.label("CSV counters · unavailable");}
        ui.label("Counters were separate live atomic observations, not a final drain proof. Use final reports and CSV audits for run acceptance.");
    });
}

fn show_pcap(ui: &mut egui::Ui, report: &pcap_inspect::Report) {
    let counts = &report.counts;
    ui.label(format!(
        "Capture container · {} · inspection schema {}",
        report.capture_format, report.schema
    ));
    if let Some(metadata) = &report.pcapng {
        ui.label(format!("Selected interface {} · Ethernet · snaplen {} · 10^-{} s ticks · signed offset {} s · blocks {} · skipped blocks/options {}/{}",
            metadata.interface_id, metadata.snaplen, metadata.timestamp_resolution_exponent, metadata.timestamp_offset_seconds,
            metadata.blocks, metadata.skipped_blocks, metadata.skipped_options));
        ui.label(format!("{} file packets · {} excluded on other interfaces. Counts and spacing below use the selected interface only; preview packet indexes refer to the whole file.", metadata.total_packets, metadata.skipped_packets));
        ui.collapsing("Capture interface inventory",|ui|{
            for i in &metadata.interfaces {
                ui.label(format!("Interface {} · link {} · {} packets · snaplen {} · 10^-{} s ticks · offset {} s{}",i.interface_id,i.link_type,i.packets,i.snaplen,i.timestamp_resolution_exponent,i.timestamp_offset_seconds,if i.interface_id==metadata.interface_id{" · SELECTED"}else{" · excluded"}));
            }
            ui.label("Interface IDs and clocks are recorded capture metadata, not confirmed physical NIC identities or synchronized clocks.");
        });
        show_capture_statistics(ui, metadata);
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

fn show_capture_statistics(ui: &mut egui::Ui, metadata: &pcap_inspect::PcapngMetadata) {
    let selected = metadata
        .statistics
        .iter()
        .filter(|s| s.interface_id == metadata.interface_id)
        .count();
    if selected == 0 {
        ui.label("Capture tool statistics · unavailable for selected interface. Missing counters do not mean zero loss.");
    } else {
        ui.label(format!(
            "Capture tool statistics · {selected} declared snapshots on selected interface {}",
            metadata.interface_id
        ));
    }
    let reported_losses = metadata
        .statistics
        .iter()
        .filter(|s| {
            s.interface_id == metadata.interface_id
                && (s.interface_dropped.is_some_and(|v| v > 0)
                    || s.os_dropped.is_some_and(|v| v > 0))
        })
        .count();
    if reported_losses > 0 {
        ui.colored_label(egui::Color32::YELLOW,format!("Declared capture drops in {reported_losses} selected-interface snapshots; inspect each record. Counters are not summed."));
    }
    ui.label("Capture-tool declarations only. Snapshots are separate; counters are not summed or reconciled with EtherCAT, CSV or consumer losses. Declared zero does not prove complete capture.");
    ui.collapsing("Declared capture statistics (all interfaces)", |ui| {
        egui::ScrollArea::vertical()
            .id_salt("pcap-statistics")
            .max_height(320.0)
            .show(ui, |ui| {
                for s in &metadata.statistics {
                    let selected = s.interface_id == metadata.interface_id;
                    ui.strong(format!(
                        "Block {} · interface {} · {}",
                        s.block_index,
                        s.interface_id,
                        if selected {
                            "SELECTED"
                        } else {
                            "excluded from frame analysis"
                        }
                    ));
                    ui.label(format!(
                        "Statistics timestamp · {} Unix ns · declared start {} · declared end {}",
                        s.timestamp_unix_ns,
                        s.start_timestamp_unix_ns
                            .map_or("unavailable".into(), |v| v.to_string()),
                        s.end_timestamp_unix_ns
                            .map_or("unavailable".into(), |v| v.to_string())
                    ));
                    for (label, value) in [
                        ("Received", s.received),
                        ("Interface dropped", s.interface_dropped),
                        ("Filter accepted", s.filter_accepted),
                        ("OS dropped", s.os_dropped),
                        ("User delivered", s.user_delivered),
                    ] {
                        ui.label(format!(
                            "{label} · {}",
                            value.map_or("unavailable".into(), |v| v.to_string())
                        ));
                    }
                    if s.interface_dropped.is_some_and(|v| v > 0)
                        || s.os_dropped.is_some_and(|v| v > 0)
                    {
                        ui.colored_label(
                            egui::Color32::YELLOW,
                            if selected {
                                "Reported capture drops present on selected interface"
                            } else {
                                "Reported capture drops on excluded interface"
                            },
                        );
                    }
                    warnings(ui, &s.notes);
                    ui.separator();
                }
            });
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
    for (index, trial) in result.trials.iter().enumerate() {
        if let Some(memory) = &trial.shared_memory {
            ui.label(format!("Trial {} shared memory · queue drops {} · coalesced {} · unsent {} · writes {} · busy {} · abandoned {} · worker failed {}",index+1,memory.queue_drops,memory.coalesced,memory.unsent_events,memory.writes,memory.lock_misses,memory.abandoned_recoveries,memory.worker_failed));
        }
        if let Some(mqtt) = &trial.mqtt {
            ui.label(format!("Trial {} MQTT · queue drops {} · coalesced {} · unsent {} · TCP writes {} · errors {} · worker failed {}",
                index+1,mqtt.queue_drops,mqtt.coalesced,mqtt.unsent_events,mqtt.write_completions,mqtt.errors,mqtt.worker_failed));
        }
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
    for group in &result.schedules {
        if let Some(range) = &group.valid_receive_p99_us {
            ui.label(format!("{:?} · valid-input p99 min {} / median {:.1} / max {} µs · {}/{} trials with intervals",
                group.scheduler, range.min, range.median, range.max, group.valid_receive_trials, group.trials));
        } else {
            ui.label(format!(
                "{:?} · complete-group valid-input p99 unavailable · {}/{} trials with intervals",
                group.scheduler, group.valid_receive_trials, group.trials
            ));
        }
    }
    ui.label("Per-trial host spacing in microseconds; percentile summaries are not pooled.");
    egui::ScrollArea::horizontal()
        .id_salt("review-timing")
        .show(ui, |ui| {
            egui::Grid::new("review-timing-grid")
                .striped(true)
                .show(ui, |ui| {
                    for text in [
                        "Trial",
                        "Direction",
                        "Intervals",
                        "p50",
                        "p95",
                        "p99",
                        "Longest gap",
                    ] {
                        ui.strong(text);
                    }
                    ui.end_row();
                    for (index, trial) in result.trials.iter().enumerate() {
                        for (direction, spacing) in [
                            ("Send", Some(&trial.send_spacing)),
                            ("All received", Some(&trial.receive_spacing)),
                            ("Valid input", trial.valid_receive_spacing.as_ref()),
                        ] {
                            ui.label(format!("{} {:?}", index + 1, trial.scheduler));
                            ui.label(direction);
                            ui.label(spacing.map_or("unavailable".into(), |s| s.count.to_string()));
                            for value in [
                                spacing.and_then(|s| s.p50_us),
                                spacing.and_then(|s| s.p95_us),
                                spacing.and_then(|s| s.p99_us),
                                spacing.and_then(|s| s.longest_gap_us),
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
            schema: 4,
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
                interface_id: 1,
                link_type: 1,
                snaplen: 65535,
                timestamp_resolution_exponent: 9,
                timestamp_offset_seconds: -2,
                blocks: 4,
                skipped_blocks: 0,
                skipped_options: 1,
                statistics: Vec::new(),
                selection_explicit: true,
                total_packets: 5,
                skipped_packets: 4,
                interfaces: vec![
                    pcap_inspect::InterfaceMetadata {
                        interface_id: 0,
                        link_type: 101,
                        snaplen: 1024,
                        timestamp_resolution_exponent: 6,
                        timestamp_offset_seconds: 0,
                        packets: 4,
                    },
                    pcap_inspect::InterfaceMetadata {
                        interface_id: 1,
                        link_type: 1,
                        snaplen: 65535,
                        timestamp_resolution_exponent: 9,
                        timestamp_offset_seconds: -2,
                        packets: 1,
                    },
                ],
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
            "Selected interface 1",
            "4 excluded on other interfaces",
            "Capture interface inventory",
            "Interface 0 · link 101",
            "whole file",
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
            "up to 32 interfaces",
            "Inspect PCAP with current profile",
        ] {
            assert!(
                text.contains(expected),
                "missing {expected:?} from layout: {text}"
            );
        }
    }

    #[test]
    fn pcap_interface_editor_requires_a_bounded_explicit_choice_and_retains_bus_exclusion() {
        let mut panel = Panel::default();
        assert_eq!(panel.selected_interface().unwrap(), None);
        panel.pcap_interface = "0x1f".into();
        assert_eq!(panel.selected_interface().unwrap(), Some(31));
        for invalid in ["32", "-1", "bad"] {
            panel.pcap_interface = invalid.into();
            assert!(panel.selected_interface().is_err());
        }
        let text = text_from_layout(|ui| panel.draw(ui, true, &Profile::default()));
        for label in [
            "PCAPNG interface",
            "Interface must be 0–31",
            "Multiple interfaces require an explicit ID",
            "original packet indexes",
            "Stop the active bus",
        ] {
            assert!(text.contains(label), "missing {label}: {text}");
        }
        assert!(!panel.is_running());
    }

    #[test]
    fn capture_statistics_layout_keeps_declared_unknown_zero_and_excluded_losses_distinct() {
        let mut metadata = pcap_inspect::PcapngMetadata {
            minor_version: 0,
            declared_section_bytes: None,
            interface_id: 1,
            link_type: 1,
            snaplen: 65535,
            timestamp_resolution_exponent: 9,
            timestamp_offset_seconds: 0,
            blocks: 4,
            skipped_blocks: 0,
            skipped_options: 0,
            selection_explicit: true,
            total_packets: 0,
            skipped_packets: 0,
            interfaces: Vec::new(),
            statistics: vec![pcap_inspect::InterfaceStatistics {
                block_index: 4,
                interface_id: 1,
                timestamp_unix_ns: 42,
                received: Some(u64::MAX),
                interface_dropped: Some(7),
                os_dropped: None,
                notes: vec!["Declared end precedes declared start".into()],
                ..Default::default()
            }],
        };
        let text = text_from_layout(|ui| show_capture_statistics(ui, &metadata));
        for label in [
            "1 declared snapshots on selected interface 1",
            "18446744073709551615",
            "Interface dropped · 7",
            "OS dropped · unavailable",
            "Reported capture drops present on selected interface",
            "Declared capture drops in 1 selected-interface snapshots",
            "not summed",
            "Declared zero does not prove complete capture",
            "Declared end precedes declared start",
        ] {
            assert!(text.contains(label), "missing {label}: {text}");
        }
        metadata.statistics[0].interface_dropped = Some(0);
        metadata.statistics[0].os_dropped = Some(0);
        let text = text_from_layout(|ui| show_capture_statistics(ui, &metadata));
        assert!(text.contains("Interface dropped · 0") && text.contains("OS dropped · 0"));
        assert!(!text.contains("Reported capture drops present"));
        metadata.statistics[0].interface_id = 0;
        metadata.statistics[0].interface_dropped = Some(7);
        let text = text_from_layout(|ui| show_capture_statistics(ui, &metadata));
        for label in [
            "unavailable for selected interface",
            "Missing counters do not mean zero loss",
            "excluded from frame analysis",
            "Reported capture drops on excluded interface",
        ] {
            assert!(text.contains(label), "missing {label}: {text}");
        }
    }

    #[test]
    fn shared_editor_freezes_mapping_choices_and_retains_bus_exclusion() {
        let mut profile = Profile {
            name: "Frozen input profile".into(),
            tx_bytes: 1,
            tx: vec![ethercat_workbench::model::Field {
                name: "Input".into(),
                width: 8,
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut panel = Panel {
            shared_path: ".local/input.bin".into(),
            shared_mapping: SharedMapping::CurrentProfile,
            ..Default::default()
        };
        let task = panel.shared_task(&profile).unwrap();
        profile.name = "Edited after capture request".into();
        profile.tx[0].name = "Changed".into();
        panel.shared_path = "changed.bin".into();
        let Task::InspectShared {
            file,
            decoding: SharedDecoding::Profile(frozen),
        } = task
        else {
            unreachable!()
        };
        assert_eq!(file, PathBuf::from(".local/input.bin"));
        assert_eq!(frozen.name, "Frozen input profile");
        assert_eq!(frozen.tx[0].name, "Input");
        panel.shared_mapping = SharedMapping::RunReport;
        assert!(panel.shared_task(&profile).is_err());
        panel.shared_report = ".local/run.json".into();
        assert!(matches!(
            panel.shared_task(&profile).unwrap(),
            Task::InspectShared {
                decoding: SharedDecoding::RunReport(_),
                ..
            }
        ));
        let text = text_from_layout(|ui| panel.draw(ui, true, &profile));
        assert!(!panel.is_running());
        for expected in [
            "Stop the active bus",
            "Historical file only",
            "Raw/status only",
            "Current profile (frozen)",
            "Saved run's effective profile",
            "exact full profile hash",
            "never establish current usable input",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
    }

    fn authored_shared_inspection() -> reader::Inspection {
        use sha2::{Digest, Sha256};
        use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let profile = Profile {
            tx_bytes: 1,
            tx: vec![ethercat_workbench::model::Field {
                name: "Saved counter".into(),
                width: 8,
                source: ethercat_workbench::model::Source::Override,
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut bytes = [0; 2560];
        bytes[..8].copy_from_slice(b"ECWBIN01");
        for (o, v) in [
            (8, 1u32),
            (12, 2560),
            (16, 512),
            (20, 1024),
            (264, 123),
            (268, 1 | 2 | 8 | 512),
            (280, 1),
            (284, 1),
            (292, 1),
            (320, 1000),
            (324, 100),
            (328, 10),
        ] {
            bytes[o..o + 4].copy_from_slice(&v.to_le_bytes());
        }
        for (o, v) in [
            (24, 3u64),
            (32, 1700000000000000),
            (40, 7),
            (48, 200),
            (56, 2),
            (64, 2),
            (72, 2),
            (80, 150),
            (88, 1),
            (96, 1),
            (104, 100),
            (248, 1000),
            (256, 1000000),
            (336, 456),
        ] {
            bytes[o..o + 8].copy_from_slice(&v.to_le_bytes());
        }
        bytes[272..274].copy_from_slice(&1u16.to_le_bytes());
        bytes[344..354].copy_from_slice(b"gui-shared");
        bytes[440..447].copy_from_slice(b"Fixture");
        bytes[1536] = 42;
        bytes[408..440].copy_from_slice(&Sha256::digest(serde_json::to_vec(&profile).unwrap()));
        let parent = std::env::current_dir().unwrap().join(".local");
        std::fs::create_dir_all(&parent).unwrap();
        let file = parent.join(format!(
            "shared-layout-{}-{}.bin",
            std::process::id(),
            NEXT.fetch_add(1, Relaxed)
        ));
        use std::io::Write;
        let mut out = std::fs::File::create_new(&file).unwrap();
        out.write_all(&bytes).unwrap();
        drop(out);
        let inspection = reader::inspect_file(&file, Some(&profile))
            .unwrap()
            .inspection;
        std::fs::remove_file(file).unwrap();
        inspection
    }
    #[test]
    fn shared_layout_separates_invalid_latest_historical_values_and_unavailable_current_time() {
        let mut report = authored_shared_inspection();
        let text = text_from_layout(|ui| show_shared(ui, &report));
        for expected in [
            "Historical shared-input snapshot",
            "current usable input: no",
            "current age/liveness: unavailable",
            "invalid input quality",
            "no current payload or typed values",
            "Recorded AL status/code · unavailable",
            "Historical last-valid input",
            "earlier WKC/AL readback is not stored",
            "Saved counter",
            "Override",
            "42",
            "2A",
            "Verified full-profile hash",
            "No current clock comparison",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
        assert!(!report.current_usable && report.observation.is_none());
        report.source = reader::Source::LiveSharedMemory {
            name: "not-opened".into(),
        };
        let text = text_from_layout(|ui| show_shared(ui, &report));
        assert!(text.contains("Unexpected live evidence"));
        assert!(!text.contains("Saved counter"));
    }
}

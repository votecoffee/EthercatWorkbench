use clap::ValueEnum;
use eframe::egui;
use ethercat_workbench::{
    input_group::{bundle::Review, replay::Cycle},
    model::LogMode,
    review::Task,
    run::Spacing,
};
use std::path::PathBuf;

const CYCLES_PER_PAGE: usize = 12;

pub(super) struct Panel {
    pub(super) path: String,
    only_issues: bool,
    page: usize,
}

impl Default for Panel {
    fn default() -> Self {
        Self {
            path: String::new(),
            only_issues: true,
            page: 0,
        }
    }
}

impl Panel {
    pub(super) fn task(&self) -> Task {
        Task::ReviewGroupBundle {
            directory: PathBuf::from(self.path.trim()),
        }
    }

    pub(super) fn controls(&mut self, ui: &mut egui::Ui, enabled: bool) -> Option<Task> {
        ui.label("Open a folder created with bundle-group-replay.");
        let clicked = ui
            .add_enabled_ui(enabled, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label("Bundle folder");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.path)
                            .hint_text(".local/group-bundle")
                            .desired_width(320.0),
                    );
                    ui.add_enabled(
                        !self.path.trim().is_empty(),
                        egui::Button::new("Verify grouped capture"),
                    )
                    .clicked()
                })
                .inner
            })
            .inner;
        clicked.then(|| {
            self.page = 0;
            self.task()
        })
    }

    pub(super) fn show(&mut self, ui: &mut egui::Ui, result: &Review) {
        let replay = &result.replay;
        let audit = &result.verified.audit;
        ui.separator();
        let completion = if audit.complete {
            "Complete"
        } else {
            "Verified prefix"
        };
        ui.strong(format!(
            "{completion} · {} of {} selected CSV rows verified",
            audit.verified_rows, audit.expected_rows
        ));
        ui.label(format!(
            "{} CSV parts · {} · Capture start {}",
            audit.parts.len(),
            match audit.mode {
                LogMode::Every => "Every valid input",
                LogMode::Change => "On change",
            },
            replay.utc_start
        ));
        if let Some(error) = &audit.capture_error {
            ui.label(format!("Recorded writer error · {error}"));
        }
        if let Some(dc) = &replay.virtual_dc {
            ui.label(format!(
                "Virtual DC · {} · Modeled SYNC0 {} ns · Difference limit {} ns",
                scenario_name(dc.scenario),
                dc.period_ns,
                dc.difference_limit_ns
            ));
        } else if let Some(scenario) = replay.virtual_scenario {
            ui.label(format!("Virtual group · {}", scenario_name(scenario)));
        }

        let counts = &replay.counts;
        ui.label(format!(
            "{} of {} cycles had valid inputs · {} matched input replies",
            counts.valid, counts.cycles, counts.matched_replies
        ));
        ui.horizontal_wrapped(|ui| {
            if let Some(rejections) = counts.clock_rejections {
                ui.label(format!("Clock rejections {rejections}"));
            }
            if let Some(rejections) = counts.topology_rejections {
                ui.label(format!("Topology rejections {rejections}"));
            }
            if let Some(holds) = counts.topology_hold_rejections {
                ui.label(format!("Held for fresh setup {holds}"));
            }
            ui.label(format!("Unanswered inputs {}", counts.unmatched_cycles));
            ui.label(format!("WKC mismatches {}", counts.wkc_mismatches));
            ui.label(format!("AL faults {}", counts.invalid_al));
        });
        ui.collapsing("Saved receive timing", |ui| {
            show_spacing(ui, "Matched replies", &replay.receive_spacing);
            show_spacing(ui, "Valid inputs", &replay.valid_receive_spacing);
        });
        egui::CollapsingHeader::new("Cycle details")
            .default_open(true)
            .show(ui, |ui| {
                self.show_cycles(ui, &replay.cycles, replay.expected_wkc)
            });
        ui.collapsing("Verified source", |ui| {
            ui.label(result.verified.directory.display().to_string());
            ui.label(format!(
                "Bundle SHA-256 · {}",
                result.verified.receipt_sha256
            ));
            let stations = replay
                .stations
                .iter()
                .map(|s| format!("{s:#06x}"))
                .collect::<Vec<_>>();
            ui.label(format!("Station order · {}", stations.join(", ")));
            if let Some(generations) = audit.verified_topology_generations {
                ui.label(format!(
                    "Saved setup topology verified · {generations} {}",
                    if generations == 1 {
                        "generation"
                    } else {
                        "generations"
                    }
                ));
            } else {
                ui.label("Saved setup topology unavailable");
            }
            if let Some(generations) = audit.verified_mapping_generations {
                ui.label(format!(
                    "Saved FMMU/SyncManager mapping verified · {generations} {}",
                    if generations == 1 {
                        "generation"
                    } else {
                        "generations"
                    }
                ));
            } else {
                ui.label("Raw setup mapping evidence unavailable");
            }
            ui.label(format!(
                "Ignored Ethernet candidates {}",
                counts.ignored_frames
            ));
        });
    }

    fn show_cycles(&mut self, ui: &mut egui::Ui, cycles: &[Cycle], expected_wkc: u16) {
        if ui
            .checkbox(&mut self.only_issues, "Only problem cycles")
            .changed()
        {
            self.page = 0;
        }
        let visible = cycles
            .iter()
            .filter(|cycle| !self.only_issues || !cycle.valid)
            .collect::<Vec<_>>();
        if visible.is_empty() {
            ui.label("No problem cycles");
            return;
        }
        let pages = visible.len().div_ceil(CYCLES_PER_PAGE);
        self.page = self.page.min(pages - 1);
        if pages > 1 {
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(self.page > 0, egui::Button::new("Previous"))
                    .clicked()
                {
                    self.page -= 1;
                }
                ui.label(format!("Page {} of {pages}", self.page + 1));
                if ui
                    .add_enabled(self.page + 1 < pages, egui::Button::new("Next"))
                    .clicked()
                {
                    self.page += 1;
                }
            });
        }
        for cycle in visible
            .into_iter()
            .skip(self.page * CYCLES_PER_PAGE)
            .take(CYCLES_PER_PAGE)
        {
            show_cycle(ui, cycle, expected_wkc);
        }
    }
}

fn scenario_name(scenario: impl ValueEnum) -> String {
    scenario
        .to_possible_value()
        .map_or_else(String::new, |value| value.get_name().into())
}

fn show_spacing(ui: &mut egui::Ui, label: &str, spacing: &Spacing) {
    let value = |us: Option<u64>| us.map_or_else(|| "—".into(), |us| format!("{us} µs"));
    ui.label(format!(
        "{label} · {} intervals · p50 {} · p95 {} · p99 {} · Longest {}",
        spacing.count,
        value(spacing.p50_us),
        value(spacing.p95_us),
        value(spacing.p99_us),
        value(spacing.longest_gap_us)
    ));
}

fn show_cycle(ui: &mut egui::Ui, cycle: &Cycle, expected_wkc: u16) {
    let status = if cycle.clock.as_ref().is_some_and(|clock| !clock.valid) {
        "Clock rejected".into()
    } else if let Some(wkc) = cycle.actual_wkc {
        let elapsed = cycle
            .elapsed_us
            .expect("matched replay cycle has a receive time");
        let status = if let Some(topology) = &cycle.cyclic_topology
            && !topology.matches_setup
        {
            "Topology rejected"
        } else if cycle
            .cyclic_topology
            .as_ref()
            .is_some_and(|topology| topology.held_for_setup)
        {
            "Held for fresh setup"
        } else if cycle.valid {
            "Valid input"
        } else {
            "Input rejected"
        };
        format!("{status} · LRD WKC {wkc}/{expected_wkc} · {elapsed} µs")
    } else {
        "No matching input reply".into()
    };
    ui.label(format!(
        "Generation {} · Cycle {} · {status}",
        cycle.connection_generation, cycle.cycle_index
    ));
    if let Some(clock) = &cycle.clock
        && !clock.valid
    {
        ui.label(format!(
            "FRMW WKC {}/{} · Follower difference {}",
            clock.actual_distribution_wkc,
            clock.expected_distribution_wkc,
            clock
                .difference
                .received_minus_local_ns
                .map_or_else(|| "unavailable".into(), |ns| format!("{ns} ns"))
        ));
        for issue in &clock.issues {
            ui.label(clock_issue(issue));
        }
        for follower in &clock.additional_followers {
            let difference = follower
                .difference
                .received_minus_local_ns
                .map_or_else(|| "unavailable".into(), |ns| format!("{ns} ns"));
            ui.label(format!(
                "Follower {:#06x} · Difference {difference}",
                follower.station()
            ));
            for issue in &follower.issues {
                ui.label(clock_issue(issue));
            }
        }
    }
    if let Some(topology) = &cycle.cyclic_topology
        && !topology.matches_setup
    {
        let stations = topology
            .stations()
            .map(|address| {
                address.map_or_else(|| "unavailable".into(), |address| format!("{address:#06x}"))
            })
            .collect::<Vec<_>>();
        ui.label(format!("Observed station order · {}", stations.join(", ")));
        ui.label(format!("Broadcast WKC {}", topology.count_wkc()));
    }
    for al in cycle.al.iter().filter(|al| !al.clean_safeop) {
        let description = al.status.as_ref().map_or_else(
            || format!("AL unavailable · WKC {}/1", al.actual_wkc),
            |status| {
                format!(
                    "{} · AL code {:#06x} · {}",
                    status.state, status.code, status.description
                )
            },
        );
        ui.label(format!(
            "Station {:#06x} · {description}",
            al.station_address
        ));
    }
}

fn clock_issue(issue: &str) -> &str {
    match issue {
        "distribution_wkc" => "Clock distribution Working Counter mismatch",
        "reference_time_wkc" => "Reference clock read Working Counter mismatch",
        "follower_time_wkc" => "Follower clock read Working Counter mismatch",
        "difference_wkc" => "Time difference read Working Counter mismatch",
        "reference_payload_mismatch" => "Reference time differs from distribution payload",
        "reference_time_not_new" => "Reference clock did not advance",
        "follower_time_not_new" => "Follower clock did not advance",
        "difference_outside_limit" => "Follower time difference exceeds the limit",
        "additional_follower_rejected" => "An additional follower failed clock verification",
        other => other,
    }
}

use eframe::egui;
use ethercat_workbench::{
    mode_pdo_stage::{self, Image, Plan},
    model::{Field, Profile},
    pdo_catalog::Assignment,
};

const BLOCKED_MESSAGE: &str =
    "Stop acquisition/discovery and finish or cancel saved-file review before staging mode PDOs.";

#[derive(Default)]
pub struct Panel {
    pending: Option<Plan>,
    clear_staged_rx: bool,
    message: String,
}

impl Panel {
    pub(super) fn block(&mut self) {
        self.pending = None;
        self.clear_staged_rx = false;
        self.message = BLOCKED_MESSAGE.into();
    }

    fn reconcile(&mut self, profile: &Profile, blocked: bool) {
        if blocked {
            self.block();
        } else if self
            .pending
            .as_ref()
            .is_some_and(|plan| !plan.matches_profile(profile).unwrap_or(false))
        {
            self.pending = None;
            self.clear_staged_rx = false;
            self.message =
                "Profile changed since preview. Preview mode PDO choices again before applying."
                    .into();
        } else if self.message == BLOCKED_MESSAGE {
            self.message.clear();
        }
    }

    fn preview(&mut self, profile: &Profile, blocked: bool) {
        self.reconcile(profile, blocked);
        if blocked {
            return;
        }
        self.clear_staged_rx = false;
        match mode_pdo_stage::prepare(profile) {
            Ok(plan) => {
                self.pending = Some(plan);
                self.message.clear();
            }
            Err(error) => {
                self.pending = None;
                self.message = format!("{error:#}");
            }
        }
    }

    fn apply(&mut self, profile: &mut Profile, blocked: bool) -> bool {
        self.reconcile(profile, blocked);
        if let Some(plan) = &self.pending {
            if plan.review().staged_rx_will_clear && !self.clear_staged_rx {
                self.message =
                    "Select Discard staged Rx bytes for this changed layout before applying."
                        .into();
                return false;
            }
            match plan.apply(profile, self.clear_staged_rx) {
                Ok(()) => {
                    self.pending = None;
                    self.clear_staged_rx = false;
                    self.message = "Mode PDO candidate applied to the offline profile in memory. Save new to retain it. No bus writes were sent.".into();
                    return true;
                }
                Err(error) => self.message = format!("{error:#}"),
            }
        }
        false
    }

    /// Returns true only when a reviewed candidate replaced the offline profile.
    pub fn draw(&mut self, ui: &mut egui::Ui, profile: &mut Profile, blocked: bool) -> bool {
        self.reconcile(profile, blocked);
        let mut applied = false;
        ui.collapsing("Stage PDO choices from the selected ESI mode", |ui| {
            ui.label("Preview and apply to the offline profile only. No device mapping, outputs, SyncType or DC settings are written.");
            ui.label("Selecting a mode alone changes no PDO choices. Changed directions rebuild decoder fields; unchanged directions keep edits and staged Rx bytes.");
            let ready = profile.staged_esi_dc_mode.is_some()
                && profile.esi_pdo_selection.is_some()
                && profile.esi.is_some();
            if !ready {
                ui.label("Select an ESI mode and attach an ESI PDO selection before previewing.");
            }
            ui.add_enabled_ui(!blocked, |ui| {
                if ui.add_enabled(ready, egui::Button::new("Preview mode PDO choices")).clicked() {
                    self.preview(profile, false);
                }
                if let Some(plan) = &self.pending {
                    let review = plan.review();
                    ui.separator();
                    ui.strong(format!("Frozen mode PDO preview · {} · {}: {}", review.profile_name, review.mode_index, review.mode_name));
                    ui.label(format!("Tx layout: {} · Rx layout: {}", change_label(review.tx_layout_changed), change_label(review.rx_layout_changed)));
                    image(ui, "Before", &review.before);
                    image(ui, "After", &review.after);
                    ui.label("Staged Rx before");
                    ui.monospace(if review.staged_rx_before_hex.is_empty() { "(empty)" } else { &review.staged_rx_before_hex });
                    ui.label("Staged Rx after");
                    ui.monospace(if review.staged_rx_after_hex.is_empty() { "(empty)" } else { &review.staged_rx_after_hex });
                    ui.collapsing("Profile and ESI provenance", |ui| {
                        ui.label(format!("ESI · {} · SHA-256 {}", review.esi_file_name, review.esi_sha256));
                        ui.label(format!("Source profile SHA-256 {}", review.profile_sha256));
                        ui.label(format!("Candidate profile SHA-256 {}", review.candidate_profile_sha256));
                    });
                    ui.label("Offline hints matching this candidate do not prove the actual device mapping. Setup verification still applies.");
                    if review.staged_rx_will_clear {
                        ui.colored_label(egui::Color32::YELLOW, "Rx layout changes: the existing staged output bytes will be cleared.");
                        ui.checkbox(&mut self.clear_staged_rx, "Discard staged Rx bytes for this changed layout");
                    }
                    let allowed = !review.staged_rx_will_clear || self.clear_staged_rx;
                    if ui.add_enabled(allowed, egui::Button::new("Apply mode PDO preview offline")).clicked() {
                        applied = self.apply(profile, false);
                    }
                    if ui.button("Discard mode PDO preview").clicked() {
                        self.pending = None;
                        self.clear_staged_rx = false;
                        self.message = "Mode PDO preview discarded. The profile was not changed.".into();
                    }
                }
            });
            if !self.message.is_empty() {
                ui.label(&self.message);
            }
        });
        applied
    }
}

fn change_label(changed: bool) -> &'static str {
    if changed { "changed" } else { "unchanged" }
}

fn assignments(ui: &mut egui::Ui, label: &str, choices: &[Assignment]) {
    let choices = choices
        .iter()
        .map(|a| format!("0x{:04X}@SM{}", a.index, a.sm))
        .collect::<Vec<_>>()
        .join(", ");
    ui.label(format!(
        "{label} · {}",
        if choices.is_empty() {
            "(empty)"
        } else {
            &choices
        }
    ));
}

fn image(ui: &mut egui::Ui, label: &str, image: &Image) {
    ui.push_id(label, |ui| {
        ui.strong(format!(
            "{label} · Tx {} bytes / Rx {} bytes",
            image.tx_bytes, image.rx_bytes
        ));
        assignments(ui, "TxPDO choices", &image.selection.tx);
        assignments(ui, "RxPDO choices", &image.selection.rx);
        for (direction, fields) in [("Tx", &image.tx_fields), ("Rx", &image.rx_fields)] {
            ui.collapsing(format!("{label} {direction} decoder fields"), |ui| {
                egui::ScrollArea::horizontal().show(ui, |ui| {
                    egui::Grid::new(direction).striped(true).show(ui, |ui| {
                        for label in [
                            "Field",
                            "Bits",
                            "Type",
                            "Mapping source",
                            "Log",
                            "Transforms",
                            "Object",
                        ] {
                            ui.strong(label);
                        }
                        ui.end_row();
                        for field in fields {
                            field_row(ui, field);
                        }
                    });
                });
            });
        }
    });
}

fn field_row(ui: &mut egui::Ui, field: &Field) {
    ui.label(&field.name);
    ui.label(format!("{} + {}", field.bit, field.width));
    ui.label(format!("{:?}", field.kind));
    ui.label(format!("{:?}", field.source));
    ui.label(field.log.to_string());
    ui.label(format!(
        "Big endian {} / byte swap {} / reverse words {}",
        field.big_endian, field.swap_bytes_in_words, field.reverse_words
    ));
    ui.label(
        match (field.pdo_index, field.object_index, field.subindex) {
            (Some(pdo), Some(object), Some(sub)) => format!("{pdo:04X}/{object:04X}:{sub:02X}"),
            _ => "manual / incomplete reference".into(),
        },
    );
    ui.end_row();
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethercat_workbench::{esi, model::Source};

    fn profile(mode: usize) -> Profile {
        let device = esi::parse(
            "mode-pdo-staging.esi.xml",
            include_bytes!("../samples/mode-pdo-staging.esi.xml"),
        )
        .unwrap()
        .remove(0);
        let mut profile = Profile::default();
        device.apply(&mut profile).unwrap();
        profile.staged_esi_dc_mode = Some(mode);
        profile.staged_rx_hex = "FEFF".into();
        profile.rx[0].name = "Custom output".into();
        profile.rx[0].source = Source::Override;
        profile.tx[0].log = false;
        profile.tx[0].big_endian = true;
        profile.validate().unwrap();
        profile
    }

    #[test]
    fn tx_preview_is_offline_and_apply_preserves_outputs() {
        let mut profile = profile(1);
        let original = profile.clone();
        let mut panel = Panel::default();
        panel.preview(&profile, false);
        assert_eq!(profile, original);
        assert!(panel.pending.as_ref().unwrap().review().tx_layout_changed);
        assert!(panel.apply(&mut profile, false));
        assert_eq!(profile.rx, original.rx);
        assert_eq!(profile.staged_rx_hex, "FEFF");
        assert_eq!(
            profile.esi_pdo_selection.as_ref().unwrap().tx[0].index,
            0x1a01
        );
        assert!(panel.pending.is_none() && !panel.clear_staged_rx);
        assert!(panel.message.contains("No bus writes"));
    }

    #[test]
    fn rx_clear_requires_a_fresh_explicit_choice() {
        let mut profile = profile(2);
        let original = profile.clone();
        let mut panel = Panel::default();
        panel.preview(&profile, false);
        assert!(!panel.apply(&mut profile, false));
        assert_eq!(profile, original);
        assert!(panel.message.contains("Select Discard staged Rx bytes"));
        panel.clear_staged_rx = true;
        panel.preview(&profile, false);
        assert!(!panel.clear_staged_rx);
        panel.clear_staged_rx = true;
        assert!(panel.apply(&mut profile, false));
        assert!(profile.staged_rx_hex.is_empty());
        assert_eq!(profile.rx_bytes, 4);
        assert_eq!(profile.tx, original.tx);
    }

    #[test]
    fn stale_blocked_and_unsupported_previews_cannot_apply() {
        let mut panel = Panel::default();
        let mut profile = profile(2);
        panel.preview(&profile, false);
        panel.clear_staged_rx = true;
        profile.staged_esi_dc_mode = Some(1);
        let changed = profile.clone();
        assert!(!panel.apply(&mut profile, false));
        assert_eq!(profile, changed);
        assert!(panel.pending.is_none() && !panel.clear_staged_rx);
        assert!(panel.message.contains("Profile changed since preview"));
        panel.preview(&profile, true);
        assert!(panel.pending.is_none());
        panel.preview(&profile, false);
        assert!(!panel.apply(&mut profile, true));
        assert_eq!(profile, changed);
        assert!(panel.pending.is_none() && panel.message.contains("Stop acquisition/discovery"));
        profile.staged_esi_dc_mode = Some(3);
        panel.preview(&profile, false);
        assert!(panel.pending.is_none() && panel.message.contains("unsupported annotations"));
        assert!(!panel.apply(&mut profile, false));
    }

    #[test]
    fn activity_invalidates_preview_even_when_panel_is_not_drawn() {
        let mut panel = Panel::default();
        let mut profile = profile(2);
        let original = profile.clone();
        panel.preview(&profile, false);
        panel.clear_staged_rx = true;
        // The app calls this after dispatching work, independently of collapsed headers.
        panel.block();
        assert!(panel.pending.is_none() && !panel.clear_staged_rx);
        assert!(!panel.apply(&mut profile, false));
        assert_eq!(profile, original);
        panel.preview(&profile, false);
        assert!(panel.pending.is_some() && !panel.clear_staged_rx);
    }

    #[test]
    fn headless_layout_shows_frozen_changes_fields_and_clear_boundary() {
        for mode in [1, 2] {
            let mut profile = profile(mode);
            let original = profile.clone();
            let mut panel = Panel::default();
            panel.preview(&profile, false);
            let ctx = egui::Context::default();
            ctx.memory_mut(|m| m.set_everything_is_visible(true));
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1800.0, 10000.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        assert!(!panel.draw(ui, &mut profile, false));
                    });
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
            for expected in [
                "Frozen mode PDO preview",
                "No device mapping",
                "Before Tx decoder fields",
                "After Rx decoder fields",
                "Custom output",
                "FEFF",
                "Mapping source",
                "Big endian",
                "Candidate profile SHA-256",
                "do not prove the actual device mapping",
                "Apply mode PDO preview offline",
            ] {
                assert!(
                    text.contains(expected),
                    "mode {mode} missing {expected:?}: {text}"
                );
            }
            assert_eq!(text.contains("Discard staged Rx bytes"), mode == 2);
            assert_eq!(profile, original);
            assert!(panel.pending.is_some() && !panel.clear_staged_rx);
        }
    }
}

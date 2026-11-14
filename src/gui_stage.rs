use eframe::egui;
use ethercat_workbench::{
    model::Profile,
    output_stage::{self, Assignment, Plan},
};

#[derive(Default)]
struct Edit {
    field: usize,
    value: String,
}

pub struct Panel {
    edits: Vec<Edit>,
    zero: bool,
    pending: Option<Plan>,
    message: String,
}
impl Default for Panel {
    fn default() -> Self {
        Self {
            edits: vec![Edit::default()],
            zero: false,
            pending: None,
            message: String::new(),
        }
    }
}

impl Panel {
    fn preview(&mut self, profile: &Profile) {
        let assignments = self
            .edits
            .iter()
            .map(|edit| Assignment {
                field: edit.field,
                value: edit.value.clone(),
            })
            .collect::<Vec<_>>();
        match output_stage::prepare(profile, &assignments, self.zero) {
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

    fn apply(&mut self, profile: &mut Profile) {
        if let Some(plan) = &self.pending {
            match plan.apply(profile) {
                Ok(()) => {
                    self.pending = None;
                    self.zero = false;
                    self.message = "Offline staged bytes updated in memory. Save the profile to a new path to retain them.".into();
                }
                Err(error) => {
                    self.pending = None;
                    self.message = format!("{error:#}");
                }
            }
        }
    }

    pub fn draw(&mut self, ui: &mut egui::Ui, profile: &mut Profile) {
        egui::CollapsingHeader::new("Stage typed RxPDO values offline").default_open(true).show(ui, |ui| {
            ui.label("Prepare and review bytes, then apply them to this profile's offline image. These controls cannot publish outputs or enter OP.");
            if profile.rx.is_empty() { ui.label("Add an RxPDO mapping before staging typed values."); }
            let mut changed = false;
            let mut remove = None;
            ui.add_enabled_ui(!profile.rx.is_empty(), |ui| {
                for (index, edit) in self.edits.iter_mut().enumerate() {
                    ui.push_id(index, |ui| {
                        ui.horizontal(|ui| {
                            egui::ComboBox::from_id_salt("field")
                                .selected_text(profile.rx.get(edit.field).map_or("Missing field".into(), |f| format!("{} · {} ({:?})", edit.field, f.name, f.kind)))
                                .show_ui(ui, |ui| {
                                    for (field, definition) in profile.rx.iter().enumerate() {
                                        changed |= ui.selectable_value(&mut edit.field, field, format!("{field} · {} ({:?})", definition.name, definition.kind)).changed();
                                    }
                                });
                            changed |= ui.add(egui::TextEdit::singleline(&mut edit.value).hint_text("Typed value").desired_width(180.0)).changed();
                            if ui.small_button("Remove assignment").clicked() { remove = Some(index); }
                        });
                    });
                }
                if ui.add_enabled(self.edits.len() < 128, egui::Button::new("Add typed assignment")).clicked() {
                    self.edits.push(Edit::default()); changed = true;
                }
                changed |= ui.checkbox(&mut self.zero, "Initialize from zero only when the staged image is empty").changed();
            });
            if let Some(index) = remove { self.edits.remove(index); changed = true; }
            if changed { self.pending = None; }
            ui.label("Unsigned: decimal/0x hex; signed: decimal; bool: true/false/1/0; floats: finite decimal; raw: exact hex bytes. Existing padding and unselected bits are preserved.");
            if ui.add_enabled(!self.edits.is_empty() && !profile.rx.is_empty(), egui::Button::new("Preview typed staging")).clicked() {
                self.preview(profile);
            }
            if !self.message.is_empty() { ui.label(&self.message); }
            if let Some(plan) = &self.pending {
                let review = plan.review();
                ui.separator();
                ui.strong(format!("Frozen offline preview · {} · {} changed bits", review.profile_name, review.changed_bits));
                if let Some(identity) = &review.expected_identity { ui.label(format!("Profile's expected identity · {identity}")); }
                ui.label(if review.initialized_from_zero { "Before bytes assume an explicitly requested zero-filled image." } else { "Before bytes come from the staged image." });
                ui.label("Before"); ui.monospace(&review.before_hex);
                ui.label("After"); ui.monospace(&review.after_hex);
                egui::Grid::new("typed-stage-impact").striped(true).show(ui, |ui| {
                    for text in ["Field", "Mapping source", "Selected", "Before", "After", "Bits changed"] { ui.strong(text); }
                    ui.end_row();
                    for impact in &review.impacts {
                        ui.label(format!("{} · {}", impact.field, impact.name));
                        ui.label(format!("{:?}", impact.mapping_source)); ui.label(impact.selected.to_string());
                        ui.label(impact.before.as_deref().unwrap_or("unavailable"));
                        ui.label(impact.after.as_deref().unwrap_or("unavailable")); ui.label(impact.bits_changed.to_string()); ui.end_row();
                    }
                });
                for assignment in &review.assignments { ui.label(format!("Requested field {} = {}", assignment.field, assignment.value)); }
                ui.label("Values are manual offline entries. Changed overlapping views are listed even when not selected. Apply rechecks the full profile against this preview.");
                if ui.button("Apply preview to offline image").clicked() { self.apply(profile); }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethercat_workbench::model::{Field, Kind};

    fn profile() -> Profile {
        Profile {
            rx_bytes: 2,
            rx: vec![
                Field {
                    name: "Setpoint".into(),
                    kind: Kind::Signed,
                    ..Field::default()
                },
                Field {
                    name: "Raw overlapping view".into(),
                    kind: Kind::Raw,
                    ..Field::default()
                },
            ],
            staged_rx_hex: "0000".into(),
            ..Profile::default()
        }
    }

    #[test]
    fn preview_is_separate_from_apply_and_stale_or_invalid_values_cannot_apply() {
        let mut panel = Panel::default();
        panel.edits[0].value = "-2".into();
        let mut profile = profile();
        let original = profile.clone();
        panel.preview(&profile);
        assert!(panel.pending.is_some());
        assert_eq!(profile, original);
        profile.staged_rx_hex = "ABCD".into();
        panel.apply(&mut profile);
        assert!(panel.pending.is_none() && panel.message.contains("profile changed"));
        assert_eq!(profile.staged_rx_hex, "ABCD");
        panel.edits[0].value = "32768".into();
        panel.preview(&profile);
        assert!(panel.pending.is_none() && panel.message.contains("exceeds"));
        panel.edits[0].value = "-4".into();
        panel.preview(&profile);
        panel.apply(&mut profile);
        let mut expected = original;
        expected.staged_rx_hex = "FCFF".into();
        assert_eq!(profile, expected);
        assert!(panel.pending.is_none() && panel.message.contains("in memory"));
    }

    #[test]
    fn headless_layout_shows_raw_bytes_aliases_and_offline_boundary_without_applying() {
        let mut panel = Panel::default();
        panel.edits[0].value = "-2".into();
        let mut profile = profile();
        panel.preview(&profile);
        let ctx = egui::Context::default();
        ctx.memory_mut(|m| m.set_everything_is_visible(true));
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1100.0, 3000.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| panel.draw(ui, &mut profile));
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
            "cannot publish outputs or enter OP",
            "Frozen offline preview",
            "FEFF",
            "Raw overlapping view",
            "Values are manual offline entries",
            "Apply preview to offline image",
        ] {
            assert!(text.contains(expected), "missing {expected:?}: {text}");
        }
        assert_eq!(profile.staged_rx_hex, "0000");
        assert!(panel.pending.is_some());
    }
}

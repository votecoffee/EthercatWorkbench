use eframe::egui;
use ethercat_workbench::{esi::register_pdos::bundle::Review, model::payload_hex, review::Task};
use std::path::PathBuf;

#[derive(Default)]
pub(super) struct Panel {
    pub(super) path: String,
}

impl Panel {
    pub(super) fn task(&self) -> Task {
        Task::ReviewRegisterBundle {
            directory: PathBuf::from(self.path.trim()),
        }
    }

    pub(super) fn controls(&mut self, ui: &mut egui::Ui, enabled: bool) -> Option<Task> {
        let clicked = ui
            .add_enabled_ui(enabled, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label("Bundle folder");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.path)
                            .hint_text(".local/register-decoder-bundle")
                            .desired_width(320.0),
                    );
                    ui.add_enabled(
                        !self.path.trim().is_empty(),
                        egui::Button::new("Verify register decoder bundle"),
                    )
                    .clicked()
                })
                .inner
            })
            .inner;
        clicked.then(|| self.task())
    }
}

pub(super) fn show(ui: &mut egui::Ui, result: &Review) {
    ui.separator();
    ui.strong("Verified register decoder bundle");
    ui.label(result.verified.directory.display().to_string());
    let Some(decoder) = &result.profile.register_decoder else {
        return;
    };
    ui.label(format!(
        "Saved register data · station {:#06x} · {} bytes",
        decoder.station_address, result.profile.tx_bytes
    ));
    if let Ok(data) = payload_hex(&decoder.packed_hex) {
        egui::Grid::new("saved_register_fields")
            .striped(true)
            .show(ui, |ui| {
                ui.strong("Field");
                ui.strong("Value");
                ui.end_row();
                for field in &result.profile.tx {
                    ui.label(&field.name);
                    ui.monospace(field.decode(&data).unwrap_or_else(|| "Unavailable".into()));
                    ui.end_row();
                }
            });
    }
    ui.collapsing("Packed sample and evidence", |ui| {
        ui.monospace(&decoder.packed_hex);
        ui.label(format!(
            "Bundle receipt SHA-256 {}",
            result.verified.receipt_sha256
        ));
        ui.label(format!("Original reply · {}", decoder.reply_file_name));
        if let Some(identity) = &result.profile.expected_identity {
            ui.label(format!("ESI identity · {identity}"));
        }
        if let Some(index) = decoder.pdo_index {
            ui.label(format!("PDO {index:#06x} · {} bits", decoder.packed_bits));
        }
        for pdo in &decoder.pdos {
            ui.label(format!(
                "PDO {:#06x} · bit {} · {} bits",
                pdo.pdo_index, pdo.bit_offset, pdo.width_bits
            ));
        }
        if !decoder.withheld_bits.is_empty() {
            ui.label(format!(
                "Withheld field offsets · {:?}",
                decoder.withheld_bits
            ));
        }
    });
}

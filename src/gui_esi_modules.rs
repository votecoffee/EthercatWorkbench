use eframe::egui;
use ethercat_workbench::{esi::modular::Choice, model::EsiSource, pdo_catalog::Direction};

pub(super) fn show(ui: &mut egui::Ui, source: &EsiSource) {
    let Some(modular) = &source.modular else {
        if let Some(group) = source.device_pdo_group {
            ui.small(format!("ESI device PDO group {group}"));
        }
        return;
    };
    ui.collapsing("ESI modules and slots", |ui| {
        ui.small("ESI declarations only. Module positions and the resulting PDO layout require separate verification.");
        if let Some(group) = source.device_pdo_group {
            ui.label(format!("Device PDO group {group}"));
        }
        if !modular.slot_attributes.is_empty() {
            ui.collapsing("Slot settings", |ui| {
                for (name, value) in &modular.slot_attributes {
                    ui.label(format!("{name}  {value}"));
                }
            });
        }
        for (index, slot) in modular.slots.iter().enumerate() {
            ui.push_id(index, |ui| {
                let name = slot.name.as_deref().unwrap_or("Unnamed slot");
                ui.collapsing(format!("Slot declaration {} · {name}", index + 1), |ui| {
                    if let Some(group) = slot.group {
                        ui.label(format!("Declared slot group {group}"));
                    }
                    ui.label(format!(
                        "Instance range {}–{}",
                        optional(slot.min_instances),
                        optional(slot.max_instances)
                    ));
                    for (name, value) in &slot.attributes {
                        ui.label(format!("{name}  {value}"));
                    }
                    for choice in &slot.choices {
                        let label = match choice {
                            Choice::Ident { ident, default_instances } => format!(
                                "Module {ident:#010x} · Default instances {}",
                                optional(*default_instances)
                            ),
                            Choice::Class { class, vendor_id } => match vendor_id {
                                Some(vendor) => format!("Module class {class} · Vendor {vendor:#010x}"),
                                None => format!("Module class {class}"),
                            },
                        };
                        let local = modular.modules.iter().filter(|module| {
                            choice.matches(module.ident, module.class.as_deref(), source.identity.vendor)
                        }).count();
                        ui.label(format!("{label} · {local} local definitions"));
                    }
                    if slot.choices.is_empty() {
                        ui.label("No direct module identity or class declarations");
                    }
                });
            });
        }
        ui.collapsing(format!("Local module definitions ({})", modular.modules.len()), |ui| {
            for (index, module) in modular.modules.iter().enumerate() {
                ui.push_id(index, |ui| {
                    ui.collapsing(format!("{:#010x} · {}", module.ident, module.name), |ui| {
                        if let Some(class) = &module.class {
                            ui.label(format!("Module class {class}"));
                        }
                        if let Some(group) = module.pdo_group {
                            ui.label(format!("Module PDO group {group}"));
                        }
                        if module.pdo_templates.is_empty() {
                            ui.label("No declared TxPDO or RxPDO templates");
                        }
                        for pdo in &module.pdo_templates {
                            let name = pdo.name.as_deref().unwrap_or("Unnamed PDO");
                            let direction = match pdo.direction {
                                Direction::Tx => "TxPDO",
                                Direction::Rx => "RxPDO",
                            };
                            ui.label(format!(
                                "{direction} {:#06x} · {name} · {} bits across {} entries",
                                pdo.index, pdo.declared_bits, pdo.entry_count
                            ));
                            if pdo.depends_on_slot || pdo.depends_on_slot_group {
                                let dependency = match (pdo.depends_on_slot, pdo.depends_on_slot_group) {
                                    (true, true) => "slot and slot group",
                                    (true, false) => "slot",
                                    _ => "slot group",
                                };
                                ui.small(format!("Index dependencies include {dependency}"));
                            }
                        }
                    });
                });
            }
        });
        if !modular.additional_elements.is_empty() {
            ui.small(format!("Additional declarations require separate review · {}", modular.additional_elements.join(", ")));
        }
    });
}

fn optional(value: Option<u32>) -> String {
    value.map_or_else(|| "unspecified".into(), |value| value.to_string())
}

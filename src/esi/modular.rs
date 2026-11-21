//! Descriptive ESI slot and module information. Module templates never become PDO assignments.
use super::{bool_attr, child, dc_text, label, named, node_number, number, unique_child};
use crate::pdo_catalog::Direction;
use anyhow::{Context, Result, ensure};
use roxmltree::Node;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_DECLARATIONS: usize = 512;
const MAX_TEXT: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Description {
    pub slot_attributes: BTreeMap<String, String>,
    pub slots: Vec<Slot>,
    pub modules: Vec<Module>,
    /// Structure present in the document that requires a separate interpretation.
    pub additional_elements: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Slot {
    pub name: Option<String>,
    pub group: Option<u32>,
    pub min_instances: Option<u32>,
    pub max_instances: Option<u32>,
    pub attributes: BTreeMap<String, String>,
    pub choices: Vec<Choice>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum Choice {
    Ident {
        ident: u32,
        default_instances: Option<u32>,
    },
    Class {
        class: String,
        vendor_id: Option<u32>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Module {
    pub ident: u32,
    pub name: String,
    pub class: Option<String>,
    pub pdo_templates: Vec<PdoTemplate>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdoTemplate {
    pub direction: Direction,
    pub index: u16,
    pub name: Option<String>,
    pub entry_count: usize,
    pub declared_bits: u32,
    pub depends_on_slot: bool,
    pub depends_on_slot_group: bool,
}

impl Choice {
    pub fn matches(&self, ident: u32, class: Option<&str>, vendor: u32) -> bool {
        match self {
            Self::Ident { ident: wanted, .. } => *wanted == ident,
            Self::Class {
                class: wanted,
                vendor_id,
            } => class == Some(wanted) && vendor_id.is_none_or(|id| id == vendor),
        }
    }
}

impl Description {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.slots.len() <= MAX_DECLARATIONS
                && self.modules.len() <= MAX_DECLARATIONS
                && self.additional_elements.len() <= MAX_DECLARATIONS,
            "ESI modular description exceeds the retained declaration limit"
        );
        validate_attributes(&self.slot_attributes)?;
        for slot in &self.slots {
            ensure!(
                slot.min_instances
                    .zip(slot.max_instances)
                    .is_none_or(|(min, max)| min <= max),
                "ESI slot minimum instances exceeds maximum"
            );
            ensure!(
                slot.choices.len() <= MAX_DECLARATIONS
                    && slot.name.as_ref().is_none_or(|name| name.len() <= MAX_TEXT),
                "ESI slot declaration exceeds limit"
            );
            validate_attributes(&slot.attributes)?;
            for choice in &slot.choices {
                if let Choice::Class { class, .. } = choice {
                    ensure!(
                        !class.is_empty() && class.len() <= MAX_TEXT,
                        "invalid ESI module class"
                    );
                }
            }
        }
        for module in &self.modules {
            ensure!(
                module.name.len() <= MAX_TEXT
                    && module
                        .class
                        .as_ref()
                        .is_none_or(|class| class.len() <= MAX_TEXT)
                    && module.pdo_templates.len() <= MAX_DECLARATIONS,
                "ESI module declaration exceeds limit"
            );
            for template in &module.pdo_templates {
                ensure!(
                    template.entry_count <= 255
                        && template
                            .name
                            .as_ref()
                            .is_none_or(|name| name.len() <= MAX_TEXT),
                    "ESI module PDO template exceeds limit"
                );
            }
        }
        ensure!(
            self.additional_elements
                .iter()
                .all(|name| name.len() <= MAX_TEXT),
            "ESI modular element name exceeds limit"
        );
        Ok(())
    }
}

fn validate_attributes(attributes: &BTreeMap<String, String>) -> Result<()> {
    ensure!(
        attributes.len() <= 32
            && attributes
                .iter()
                .all(|(name, value)| name.len() <= MAX_TEXT && value.len() <= MAX_TEXT),
        "ESI slot attributes exceed limit"
    );
    Ok(())
}

pub(super) fn parse(
    device: Node<'_, '_>,
    descriptions: Node<'_, '_>,
    vendor: u32,
) -> Result<Option<Description>> {
    let Some(slots) = unique_child(device, "Slots")? else {
        return Ok(None);
    };
    let mut result = Description {
        slot_attributes: attributes(slots, &[]),
        slots: Vec::new(),
        modules: Vec::new(),
        additional_elements: Vec::new(),
    };
    let mut additional = BTreeSet::new();
    for node in slots.children().filter(Node::is_element) {
        if named(node, "Slot") {
            ensure!(
                result.slots.len() < MAX_DECLARATIONS,
                "ESI modular description exceeds 512 slot declarations"
            );
            result.slots.push(parse_slot(node, &mut additional)?);
        } else {
            additional.insert(node.tag_name().name().to_owned());
        }
    }
    if child(descriptions, "ModuleGroups").is_some() {
        additional.insert("ModuleGroups".into());
    }
    let mut identifiers = BTreeSet::new();
    let mut classes = BTreeSet::new();
    for choice in result.slots.iter().flat_map(|slot| &slot.choices) {
        match choice {
            Choice::Ident { ident, .. } => {
                identifiers.insert(*ident);
            }
            Choice::Class { class, vendor_id } if vendor_id.is_none_or(|id| id == vendor) => {
                classes.insert(class.as_str());
            }
            Choice::Class { .. } => {}
        }
    }
    if let Some(modules) = unique_child(descriptions, "Modules")? {
        for node in modules.children().filter(|n| named(*n, "Module")) {
            let Some(ty) = child(node, "Type") else {
                continue;
            };
            let Some(ident) = ty.attribute("ModuleIdent").and_then(|id| number(id).ok()) else {
                continue;
            };
            let class = ty.attribute("ModuleClass").map(str::trim);
            if identifiers.contains(&ident) || class.is_some_and(|name| classes.contains(name)) {
                ensure!(
                    result.modules.len() < MAX_DECLARATIONS,
                    "ESI modular description exceeds 512 matching module definitions"
                );
                result.modules.push(parse_module(node, ty, ident, class)?);
            }
        }
    }
    result.additional_elements = additional.into_iter().collect();
    result.validate()?;
    Ok(Some(result))
}

fn attributes(node: Node<'_, '_>, excluded: &[&str]) -> BTreeMap<String, String> {
    node.attributes()
        .filter(|attribute| !excluded.contains(&attribute.name()))
        .map(|attribute| (attribute.name().into(), attribute.value().into()))
        .collect()
}

fn parse_slot(node: Node<'_, '_>, additional: &mut BTreeSet<String>) -> Result<Slot> {
    let mut choices = Vec::new();
    for entry in node.children().filter(Node::is_element) {
        let choice = match entry.tag_name().name() {
            "ModuleIdent" => Some(Choice::Ident {
                ident: number(&dc_text(entry)).context("invalid ESI slot ModuleIdent")?,
                default_instances: entry.attribute("Default").map(number).transpose()?,
            }),
            "ModuleClass" => Some(Choice::Class {
                class: dc_text(
                    unique_child(entry, "Class")?.context("ESI slot ModuleClass requires Class")?,
                )
                .trim()
                .into(),
                vendor_id: unique_child(entry, "VendorId")?
                    .map(|value| number(&dc_text(value)))
                    .transpose()?,
            }),
            "Name" | "Image16x14" | "ImageFile16x14" | "ImageData16x14" => None,
            name => {
                additional.insert(format!("Slot/{name}"));
                None
            }
        };
        if let Some(choice) = choice {
            ensure!(
                choices.len() < MAX_DECLARATIONS,
                "ESI slot exceeds 512 choices"
            );
            choices.push(choice);
        }
    }
    let attr_number = |attr| node.attribute(attr).map(number).transpose();
    Ok(Slot {
        name: label(node, "Name").map(str::to_owned),
        group: attr_number("SlotGroup")?,
        min_instances: attr_number("MinInstances")?,
        max_instances: attr_number("MaxInstances")?,
        attributes: attributes(node, &["SlotGroup", "MinInstances", "MaxInstances"]),
        choices,
    })
}

fn parse_module(
    node: Node<'_, '_>,
    ty: Node<'_, '_>,
    ident: u32,
    class: Option<&str>,
) -> Result<Module> {
    let mut pdo_templates = Vec::new();
    for pdo in node
        .children()
        .filter(|n| named(*n, "TxPdo") || named(*n, "RxPdo"))
    {
        ensure!(
            pdo_templates.len() < MAX_DECLARATIONS,
            "ESI module exceeds 512 PDO templates"
        );
        let index = unique_child(pdo, "Index")?.context("ESI module PDO Index missing")?;
        let mut depends_on_slot = false;
        let mut depends_on_slot_group = false;
        let mut read_dependency = |index| -> Result<()> {
            depends_on_slot |= bool_attr(index, "DependOnSlot")?;
            depends_on_slot_group |= bool_attr(index, "DependOnSlotGroup")?;
            Ok(())
        };
        read_dependency(index)?;
        for exclude in pdo.children().filter(|n| named(*n, "Exclude")) {
            read_dependency(exclude)?;
        }
        let mut declared_bits = 0u32;
        let mut entry_count = 0;
        for entry in pdo.children().filter(|n| named(*n, "Entry")) {
            entry_count += 1;
            ensure!(entry_count <= 255, "ESI module PDO exceeds 255 entries");
            if let Some(object) = unique_child(entry, "Index")? {
                read_dependency(object)?;
            }
            declared_bits = declared_bits
                .checked_add(node_number(entry, "BitLen")?)
                .context("ESI module PDO bit total overflow")?;
        }
        pdo_templates.push(PdoTemplate {
            direction: if named(pdo, "TxPdo") {
                Direction::Tx
            } else {
                Direction::Rx
            },
            index: u16::try_from(number(&dc_text(index))?)?,
            name: label(pdo, "Name").map(str::to_owned),
            entry_count,
            declared_bits,
            depends_on_slot,
            depends_on_slot_group,
        });
    }
    Ok(Module {
        ident,
        name: label(node, "Name")
            .or_else(|| ty.text())
            .unwrap_or("Unnamed module")
            .into(),
        class: class.map(str::to_owned),
        pdo_templates,
    })
}

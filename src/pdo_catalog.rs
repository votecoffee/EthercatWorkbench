//! ESI PDO candidates and offline assignments. No configuration writes are performed here.
use crate::{
    model::{Field, Kind, MAX_FIELDS, MAX_PAYLOAD, Profile, Source},
    pdo::{Layout, MappingSource, Pdo, SyncManager},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Tx,
    Rx,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub index: u16,
    pub subindex: u8,
    pub width: usize,
    pub name: String,
    pub data_type: String,
    pub fixed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    pub direction: Direction,
    pub index: u16,
    pub name: String,
    pub default_sm: Option<u8>,
    pub mandatory: bool,
    pub fixed: bool,
    pub virtual_pdo: bool,
    pub excludes: Vec<u16>,
    pub entries: Vec<Entry>,
    pub notes: Vec<String>,
    pub unsupported: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    pub index: u16,
    pub sm: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Selection {
    pub tx: Vec<Assignment>,
    pub rx: Vec<Assignment>,
}

impl Selection {
    pub fn assignments(&self, direction: Direction) -> &Vec<Assignment> {
        match direction {
            Direction::Tx => &self.tx,
            Direction::Rx => &self.rx,
        }
    }
    pub fn assignments_mut(&mut self, direction: Direction) -> &mut Vec<Assignment> {
        match direction {
            Direction::Tx => &mut self.tx,
            Direction::Rx => &mut self.rx,
        }
    }
}

pub fn defaults(catalog: &[Definition]) -> Selection {
    let mut result = Selection::default();
    for pdo in catalog.iter().filter(|p| !p.virtual_pdo) {
        if let Some(sm) = pdo.default_sm {
            result.assignments_mut(pdo.direction).push(Assignment {
                index: pdo.index,
                sm,
            });
        }
    }
    result
}

pub fn validate_catalog(catalog: &[Definition]) -> Result<()> {
    ensure!(
        catalog.len() <= 512,
        "ESI PDO catalog exceeds 512 candidates"
    );
    let mut seen = HashSet::new();
    let mut total_entries = 0;
    for pdo in catalog {
        ensure!(
            (0x1600..=0x1bff).contains(&pdo.index),
            "PDO index outside supported mapping range"
        );
        ensure!(
            seen.insert((pdo.direction as u8, pdo.index)),
            "duplicate ESI PDO index in one direction"
        );
        ensure!(
            pdo.default_sm.is_none_or(|sm| sm < 16),
            "ESI default SyncManager exceeds 15"
        );
        ensure!(
            pdo.name.len() <= 1024 && pdo.entries.len() <= 255 && pdo.excludes.len() <= 512,
            "ESI PDO metadata exceeds limit"
        );
        ensure!(
            pdo.notes.len() <= 1024 && pdo.notes.iter().all(|n| n.len() <= 4096),
            "ESI PDO notes exceed limit"
        );
        total_entries += pdo.entries.len();
        for entry in &pdo.entries {
            ensure!(
                (1..=MAX_PAYLOAD * 8).contains(&entry.width),
                "ESI PDO entry has invalid bit length"
            );
            ensure!(
                entry.index != 0 || entry.subindex == 0,
                "ESI PDO padding must have subindex zero"
            );
            ensure!(
                entry.name.len() <= 1024 && entry.data_type.len() <= 256,
                "ESI PDO entry text exceeds limit"
            );
        }
    }
    ensure!(
        total_entries <= 8192,
        "ESI PDO catalog exceeds 8192 entries"
    );
    Ok(())
}

pub struct Built {
    pub tx: Vec<Field>,
    pub rx: Vec<Field>,
    pub tx_layout: Layout,
    pub rx_layout: Layout,
    pub tx_bytes: usize,
    pub rx_bytes: usize,
}

pub fn build(catalog: &[Definition], selection: &Selection) -> Result<Built> {
    validate_catalog(catalog)?;
    let chosen: Vec<_> = [Direction::Tx, Direction::Rx]
        .into_iter()
        .map(|direction| -> Result<Vec<_>> {
            let assignments = selection.assignments(direction);
            ensure!(assignments.len() <= 512, "too many selected PDOs");
            let mut seen = HashSet::new();
            let mut selected = Vec::new();
            for assignment in assignments {
                ensure!(
                    assignment.sm < 16 && seen.insert(assignment.index),
                    "invalid SyncManager or repeated PDO assignment"
                );
                let pdo = catalog
                    .iter()
                    .find(|p| p.direction == direction && p.index == assignment.index)
                    .context("selected PDO is absent from this ESI direction")?;
                ensure!(
                    !pdo.virtual_pdo && !pdo.unsupported,
                    "PDO {:#06x} requires unsupported virtual/module/vendor interpretation",
                    pdo.index
                );
                ensure!(
                    !pdo.entries.is_empty(),
                    "selected PDO {:#06x} has no recorded entries",
                    pdo.index
                );
                selected.push((assignment, pdo));
            }
            for pdo in catalog
                .iter()
                .filter(|p| p.direction == direction && p.mandatory)
            {
                ensure!(
                    seen.contains(&pdo.index),
                    "mandatory PDO {:#06x} must be assigned",
                    pdo.index
                );
            }
            Ok(selected)
        })
        .collect::<Result<_>>()?;
    let all = chosen
        .iter()
        .flatten()
        .map(|(_, p)| p.index)
        .collect::<HashSet<_>>();
    for (_, pdo) in chosen.iter().flatten() {
        ensure!(
            !pdo.excludes.iter().any(|index| all.contains(index)),
            "PDO {:#06x} excludes another selected PDO",
            pdo.index
        );
    }
    let tx_sms = selection.tx.iter().map(|a| a.sm).collect::<HashSet<_>>();
    ensure!(
        !selection.rx.iter().any(|a| tx_sms.contains(&a.sm)),
        "one SyncManager cannot contain both TxPDO and RxPDO assignments"
    );
    let defaults = defaults(catalog);
    let (tx, tx_layout, tx_bytes) =
        direction(&chosen[0], Direction::Tx, selection.tx != defaults.tx)?;
    let (rx, rx_layout, rx_bytes) =
        direction(&chosen[1], Direction::Rx, selection.rx != defaults.rx)?;
    Ok(Built {
        tx,
        rx,
        tx_layout,
        rx_layout,
        tx_bytes,
        rx_bytes,
    })
}

fn direction(
    selected: &[(&Assignment, &Definition)],
    dir: Direction,
    overridden: bool,
) -> Result<(Vec<Field>, Layout, usize)> {
    let mut sorted = selected.to_vec();
    sorted.sort_by_key(|(a, _)| a.sm); // Stable: the chosen order is retained within each SM.
    let mut layout = Layout {
        mapping_source: MappingSource::Esi,
        sync_managers: Vec::new(),
    };
    let mut fields = Vec::new();
    let mut bit: usize = 0;
    for (assignment, pdo) in sorted {
        if layout
            .sync_managers
            .last()
            .is_none_or(|sm| sm.index != assignment.sm)
        {
            bit = bit.div_ceil(8) * 8;
            layout.sync_managers.push(SyncManager {
                index: assignment.sm,
                configured_bytes: None,
                pdos: Vec::new(),
            });
        }
        let mut descriptors = Vec::new();
        let source = if !overridden && pdo.default_sm == Some(assignment.sm) {
            Source::Esi
        } else {
            Source::Override
        };
        for entry in &pdo.entries {
            let width = u8::try_from(entry.width)
                .context("selected PDO entry exceeds the 8-bit mapping descriptor width")?;
            descriptors.push(
                (u32::from(entry.index) << 16)
                    | (u32::from(entry.subindex) << 8)
                    | u32::from(width),
            );
            if entry.index != 0 {
                let kind = match entry.data_type.as_str() {
                    "BOOL" | "BIT" if entry.width == 1 => Kind::Bool,
                    "SINT" | "INT" | "DINT" | "LINT" | "INT24" | "INT40" | "INT48" | "INT56" => {
                        Kind::Signed
                    }
                    "REAL" | "REAL32" if entry.width == 32 && bit.is_multiple_of(8) => Kind::F32,
                    "LREAL" | "REAL64" if entry.width == 64 && bit.is_multiple_of(8) => Kind::F64,
                    _ if entry.width <= 64 => Kind::Unsigned,
                    _ => Kind::Raw,
                };
                let mut name = format!(
                    "{} [{:04X}/{:04X}:{:02X}]",
                    entry.name, pdo.index, entry.index, entry.subindex
                );
                if fields.iter().any(|f: &Field| f.name == name) {
                    name.push_str(&format!(" @{bit}"));
                }
                let field = Field {
                    name,
                    bit,
                    width: entry.width,
                    kind,
                    log: dir == Direction::Tx,
                    source: source.clone(),
                    pdo_index: Some(pdo.index),
                    object_index: Some(entry.index),
                    subindex: Some(entry.subindex),
                    ..Field::default()
                };
                field.validate()?;
                fields.push(field);
            }
            bit = bit
                .checked_add(entry.width)
                .context("PDO image size overflow")?;
            ensure!(
                bit <= MAX_PAYLOAD * 8 && fields.len() <= MAX_FIELDS,
                "selected PDO image exceeds bench limits"
            );
        }
        layout
            .sync_managers
            .last_mut()
            .expect("SM created")
            .pdos
            .push(Pdo {
                index: pdo.index,
                entries: descriptors,
            });
    }
    let bytes = bit.div_ceil(8);
    layout.entries()?;
    Ok((fields, layout, bytes))
}

pub fn apply(profile: &mut Profile, selection: Selection) -> Result<()> {
    let esi = profile
        .esi
        .as_ref()
        .context("PDO selection requires an ESI catalog")?;
    ensure!(
        profile.expected_identity.as_ref() == Some(&esi.identity),
        "PDO selection requires the exact ESI identity baseline"
    );
    ensure!(
        !esi.pdo_catalog.is_empty(),
        "profile has no retained ESI PDO catalog; reimport the ESI"
    );
    let built = build(&esi.pdo_catalog, &selection)?;
    let mut candidate = profile.clone();
    candidate.tx = built.tx;
    candidate.rx = built.rx;
    candidate.tx_bytes = built.tx_bytes;
    candidate.rx_bytes = built.rx_bytes;
    candidate.esi_pdo_selection = Some(selection);
    candidate.staged_rx_hex.clear();
    candidate.validate()?;
    *profile = candidate;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{esi, pdo::Readback};

    fn fixture() -> crate::esi::Device {
        esi::parse(
            "choices.xml",
            include_bytes!("../samples/pdo-choices.esi.xml"),
        )
        .unwrap()
        .remove(0)
    }

    #[test]
    fn preserves_unassigned_candidates_padding_and_constraint_checks() {
        let device = fixture();
        let catalog = &device.source.pdo_catalog;
        assert_eq!(catalog.len(), 5);
        assert_eq!(catalog[2].default_sm, None);
        assert!(catalog[0].mandatory && catalog[0].fixed && catalog[0].entries[0].fixed);
        let mut selection = defaults(catalog);
        let built = build(catalog, &selection).unwrap();
        assert_eq!((built.tx_bytes, built.rx_bytes), (8, 2));
        selection.tx = vec![Assignment {
            index: 0x1a01,
            sm: 3,
        }];
        let built = build(catalog, &selection).unwrap();
        assert_eq!(built.tx_bytes, 8);
        assert_eq!(
            built.tx_layout.sync_managers[0].pdos[0].entries,
            [0x6010_0110, 48]
        );
        assert_eq!(built.tx[0].source, Source::Override);
        selection.tx.push(Assignment {
            index: 0x1a00,
            sm: 4,
        });
        assert!(build(catalog, &selection).is_err());
        selection = defaults(catalog);
        selection.rx.clear();
        assert!(build(catalog, &selection).is_err());
        selection = defaults(catalog);
        selection.tx[0].sm = 2;
        assert!(build(catalog, &selection).is_err());
        selection = defaults(catalog);
        selection.tx.push(selection.tx[0].clone());
        assert!(build(catalog, &selection).is_err());
        selection = defaults(catalog);
        selection.tx = vec![Assignment {
            index: 0x1a03,
            sm: 3,
        }];
        assert!(build(catalog, &selection).is_err());
    }

    #[test]
    fn compares_full_sm_and_padding_even_when_named_fields_match() {
        let device = fixture();
        let mut profile = Profile::default();
        device.apply(&mut profile).unwrap();
        let actual: Readback =
            serde_json::from_str(include_str!("../samples/synthetic-pdo.json")).unwrap();
        assert!(actual.clone().verify(&profile, "fixture").compatible());
        let mut changed_sm = actual.clone();
        changed_sm.tx.as_mut().unwrap().sync_managers[0].index = 4;
        let check = changed_sm.verify(&profile, "fixture");
        assert_eq!(check.matched_fields(), 4);
        assert!(!check.compatible());
        assert!(check.tx.expected_selection.is_some());
        let mut changed_padding = actual;
        changed_padding.tx.as_mut().unwrap().sync_managers[0].pdos[0].entries[2] = 0x600f_000f;
        let check = changed_padding.verify(&profile, "fixture");
        assert_eq!(check.matched_fields(), 4);
        assert!(!check.compatible());
        let prior = serde_json::to_string(&profile).unwrap();
        let mut bad = defaults(&device.source.pdo_catalog);
        bad.rx.clear();
        assert!(apply(&mut profile, bad).is_err());
        assert_eq!(serde_json::to_string(&profile).unwrap(), prior);
    }

    #[test]
    fn retains_dtype_annotations_without_implicitly_scaling_or_swapping() {
        let xml = std::str::from_utf8(include_bytes!("../samples/pdo-choices.esi.xml"))
            .unwrap()
            .replace(
                "<DataType>UINT",
                "<DataType DScale=\"0.1\" SwapData=\"true\">UINT",
            );
        let device = esi::parse("annotations.xml", xml.as_bytes())
            .unwrap()
            .remove(0);
        let pdo = &device.source.pdo_catalog[1];
        assert!(pdo.notes.iter().any(|n| n.contains("DScale=0.1")));
        assert!(pdo.notes.iter().any(|n| n.contains("SwapData=true")));
        let built = build(
            &device.source.pdo_catalog,
            &defaults(&device.source.pdo_catalog),
        )
        .unwrap();
        assert_eq!(built.tx[0].decode(&[4, 0]).as_deref(), Some("4"));
        assert!(!built.tx[0].swap_bytes_in_words);
    }
}

//! Review-bound offline PDO selection from plain ESI operating-mode hints.
use crate::{
    model::{Field, Profile},
    pdo_catalog::{self, Assignment, Selection},
    sync_review::ModeSyncManager,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::collections::HashSet;

#[derive(Clone, Debug, Serialize)]
pub struct Image {
    pub selection: Selection,
    pub tx_bytes: usize,
    pub rx_bytes: usize,
    pub tx_fields: Vec<Field>,
    pub rx_fields: Vec<Field>,
}

impl Image {
    fn from_profile(profile: &Profile) -> Self {
        Self {
            selection: profile.esi_pdo_selection.clone().unwrap(),
            tx_bytes: profile.tx_bytes,
            rx_bytes: profile.rx_bytes,
            tx_fields: profile.tx.clone(),
            rx_fields: profile.rx.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Review {
    pub schema: u32,
    pub app_version: String,
    pub scope: String,
    pub profile_name: String,
    pub profile_sha256: String,
    pub candidate_profile_sha256: String,
    pub esi_file_name: String,
    pub esi_sha256: String,
    pub mode_index: usize,
    pub mode_name: String,
    pub hints: Vec<ModeSyncManager>,
    pub before: Image,
    pub after: Image,
    pub tx_layout_changed: bool,
    pub rx_layout_changed: bool,
    pub staged_rx_before_hex: String,
    pub staged_rx_after_hex: String,
    pub staged_rx_will_clear: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Plan {
    review: Review,
    candidate: Profile,
}

fn profile_hash(profile: &Profile) -> Result<String> {
    Ok(crate::benchmark::hash(&serde_json::to_vec(profile)?))
}

impl Plan {
    pub fn review(&self) -> &Review {
        &self.review
    }

    /// Changes only the reviewed offline profile, after checking the complete baseline.
    pub fn apply(&self, profile: &mut Profile, clear_staged_rx: bool) -> Result<()> {
        ensure!(
            profile_hash(profile)? == self.review.profile_sha256,
            "profile changed since preview; build a new mode PDO preview"
        );
        ensure!(
            !self.review.staged_rx_will_clear || clear_staged_rx,
            "RxPDO layout changes: saving requires --clear-staged-rx to discard staged bytes"
        );
        self.candidate.validate()?;
        *profile = self.candidate.clone();
        Ok(())
    }
}

pub fn prepare(profile: &Profile) -> Result<Plan> {
    profile.validate()?;
    let esi = profile.esi.as_ref().context("profile has no ESI catalog")?;
    let before = profile
        .esi_pdo_selection
        .as_ref()
        .context("mode PDO staging requires an attached ESI PDO selection")?;
    let mode_index = profile
        .staged_esi_dc_mode
        .context("select an ESI mode first")?;
    let mode = esi
        .dc_modes
        .get(mode_index)
        .context("ESI mode index out of range")?;
    mode.validate()?;
    ensure!(
        mode.notes.is_empty() && mode.sync_managers.iter().all(|sm| sm.notes.is_empty()),
        "mode contains unsupported annotations; select PDOs manually after reviewing the ESI"
    );
    let hints = mode
        .sync_managers
        .iter()
        .filter(|sm| !sm.pdo_indexes.is_empty())
        .collect::<Vec<_>>();
    ensure!(
        !hints.is_empty(),
        "selected mode has no PDO assignment hints"
    );
    let mut indexes = HashSet::new();
    let mut replacements = Vec::new();
    for sm in &hints {
        ensure!(
            sm.index >= 2,
            "PDO hints must target process SyncManagers 2..15"
        );
        let mut direction = None;
        for &index in &sm.pdo_indexes {
            ensure!(
                indexes.insert(index),
                "PDO {index:#06x} occurs in multiple mode SyncManagers"
            );
            let matching = esi
                .pdo_catalog
                .iter()
                .filter(|pdo| pdo.index == index)
                .collect::<Vec<_>>();
            ensure!(
                matching.len() == 1,
                "mode PDO {index:#06x} is missing or ambiguous in the ESI catalog"
            );
            let found = matching[0].direction;
            ensure!(
                direction.is_none_or(|dir| dir == found),
                "mode mixes TxPDO and RxPDO on one SyncManager"
            );
            direction = Some(found);
            replacements.push((
                found,
                Assignment {
                    index,
                    sm: sm.index,
                },
            ));
        }
    }
    let mut selection = before.clone();
    // A nonempty list replaces its entire SM. Explicit PDO moves remove old positions.
    for assignments in [&mut selection.tx, &mut selection.rx] {
        assignments
            .retain(|a| !hints.iter().any(|sm| sm.index == a.sm) && !indexes.contains(&a.index));
    }
    for (direction, assignment) in replacements {
        selection.assignments_mut(direction).push(assignment);
    }
    let old = pdo_catalog::build(&esi.pdo_catalog, before)?;
    let new = pdo_catalog::build(&esi.pdo_catalog, &selection)?;
    let tx_layout_changed = old.tx_layout != new.tx_layout;
    let rx_layout_changed = old.rx_layout != new.rx_layout;
    let mut candidate = profile.clone();
    pdo_catalog::apply(&mut candidate, selection)?;
    if !tx_layout_changed {
        candidate.tx = profile.tx.clone();
    }
    if !rx_layout_changed {
        candidate.rx = profile.rx.clone();
        candidate.staged_rx_hex = profile.staged_rx_hex.clone();
    }
    candidate.validate()?;
    let review = Review {
        schema: 1,
        app_version: env!("CARGO_PKG_VERSION").into(),
        scope: "offline_profile_only".into(),
        profile_name: profile.name.clone(),
        profile_sha256: profile_hash(profile)?,
        candidate_profile_sha256: profile_hash(&candidate)?,
        esi_file_name: esi.file_name.clone(),
        esi_sha256: esi.sha256.clone(),
        mode_index,
        mode_name: mode.name.clone(),
        hints: mode.sync_managers.clone(),
        before: Image::from_profile(profile),
        after: Image::from_profile(&candidate),
        tx_layout_changed,
        rx_layout_changed,
        staged_rx_before_hex: profile.staged_rx_hex.clone(),
        staged_rx_after_hex: candidate.staged_rx_hex.clone(),
        staged_rx_will_clear: rx_layout_changed && !profile.staged_rx_hex.is_empty(),
        notes: vec![
            "Offline candidate only: no PDO downloads, live outputs, SyncType or DC configuration writes.".into(),
            "Nonempty SM PDO lists replace that SM; absent lists preserve existing choices. Explicit PDO moves remove old positions.".into(),
            "Changed directions rebuild decoder fields from the catalog. Unchanged directions preserve decoder edits and staged RxPDO bytes.".into(),
            "The device's actual mapping must still be verified; matching offline mode hints do not establish bus compatibility.".into(),
        ],
    };
    Ok(Plan { review, candidate })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{esi, model::Source};

    fn fixture(mode: usize) -> Profile {
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
        profile.tx[0].name = "Custom input".into();
        profile.tx[0].log = false;
        profile.tx[0].big_endian = true;
        profile.tx[0].source = Source::Override;
        profile.rx[0].name = "Custom output".into();
        profile.rx[0].source = Source::Override;
        profile.validate().unwrap();
        profile
    }

    #[test]
    fn identical_layout_preserves_decoder_edits_and_staged_bytes() {
        let mut profile = fixture(0);
        let original = profile.clone();
        let plan = prepare(&profile).unwrap();
        assert_eq!(profile, original);
        assert!(!plan.review.tx_layout_changed && !plan.review.rx_layout_changed);
        plan.apply(&mut profile, false).unwrap();
        assert_eq!(profile, original);
    }

    #[test]
    fn tx_change_preserves_rx_and_every_unrelated_setting() {
        let mut profile = fixture(1);
        let mut expected = profile.clone();
        pdo_catalog::apply(
            &mut expected,
            Selection {
                tx: vec![Assignment {
                    index: 0x1a01,
                    sm: 3,
                }],
                rx: profile.esi_pdo_selection.as_ref().unwrap().rx.clone(),
            },
        )
        .unwrap();
        expected.rx = profile.rx.clone();
        expected.staged_rx_hex = profile.staged_rx_hex.clone();
        let plan = prepare(&profile).unwrap();
        assert!(plan.review.tx_layout_changed && !plan.review.rx_layout_changed);
        plan.apply(&mut profile, false).unwrap();
        assert_eq!(profile, expected);
        assert_eq!(profile.tx[0].source, Source::Override);
    }

    #[test]
    fn rx_change_requires_explicit_clear_and_is_atomic() {
        let mut profile = fixture(2);
        let original = profile.clone();
        let plan = prepare(&profile).unwrap();
        assert!(plan.review.staged_rx_will_clear);
        assert!(plan.apply(&mut profile, false).is_err());
        assert_eq!(profile, original);
        plan.apply(&mut profile, true).unwrap();
        assert_eq!(profile.rx_bytes, 4);
        assert!(profile.staged_rx_hex.is_empty());
        assert_eq!(profile.tx, original.tx);
    }

    #[test]
    fn stale_preview_and_unsupported_or_unresolved_hints_are_rejected() {
        let original = fixture(1);
        let plan = prepare(&original).unwrap();
        let mut changed = original.clone();
        changed.name.push('x');
        let before = changed.clone();
        assert!(plan.apply(&mut changed, true).is_err());
        assert_eq!(changed, before);
        assert!(prepare(&fixture(3)).is_err());
        for fault in 0..7 {
            let mut profile = original.clone();
            match fault {
                0 => profile.esi_pdo_selection = None,
                1 => profile.staged_esi_dc_mode = None,
                _ => {
                    let mode = &mut profile.esi.as_mut().unwrap().dc_modes[1];
                    match fault {
                        2 => mode.sync_managers.clear(),
                        3 => mode.sync_managers[0].pdo_indexes = vec![0x1aff],
                        4 => mode.sync_managers[0].pdo_indexes.push(0x1600),
                        5 => {
                            let mut sm = mode.sync_managers[0].clone();
                            sm.index = 4;
                            mode.sync_managers.push(sm);
                        }
                        _ => mode.sync_managers[0].index = 1,
                    }
                }
            }
            let before = profile.clone();
            assert!(prepare(&profile).is_err(), "fault {fault}");
            assert_eq!(profile, before);
        }
    }

    #[test]
    fn ambiguous_candidates_and_catalog_constraints_are_rejected() {
        for fault in 0..3 {
            let mut profile = fixture(1);
            let catalog = &mut profile.esi.as_mut().unwrap().pdo_catalog;
            match fault {
                0 => {
                    let mut duplicate = catalog.iter().find(|p| p.index == 0x1a01).unwrap().clone();
                    duplicate.direction = pdo_catalog::Direction::Rx;
                    catalog.push(duplicate);
                }
                1 => {
                    catalog
                        .iter_mut()
                        .find(|p| p.index == 0x1a00)
                        .unwrap()
                        .mandatory = true
                }
                _ => catalog
                    .iter_mut()
                    .find(|p| p.index == 0x1a01)
                    .unwrap()
                    .excludes
                    .push(0x1600),
            }
            let before = profile.clone();
            assert!(prepare(&profile).is_err(), "fault {fault}");
            assert_eq!(profile, before);
        }
    }

    #[test]
    fn explicit_moves_and_unmentioned_sync_managers_are_preserved() {
        let mut profile = fixture(0);
        let mode = &mut profile.esi.as_mut().unwrap().dc_modes[0];
        mode.sync_managers.remove(0); // Rx is unmentioned.
        mode.sync_managers[0].index = 4; // Move the existing TxPDO.
        let plan = prepare(&profile).unwrap();
        plan.apply(&mut profile, false).unwrap();
        assert_eq!(
            profile.esi_pdo_selection.as_ref().unwrap().tx,
            vec![Assignment {
                index: 0x1a00,
                sm: 4
            }]
        );
        assert_eq!(profile.esi_pdo_selection.as_ref().unwrap().rx[0].sm, 2);
        assert_eq!(profile.staged_rx_hex, "FEFF");
    }
}

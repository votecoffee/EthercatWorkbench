//! Rebuild a saved offline decoder and compare it with the supplied source files.
use super::{Review, profile::Provenance};
use crate::{input_group::read_json, model::Profile};
use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

const MAX_PROFILE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct Verification {
    schema: u32,
    scope: &'static str,
    profile_file_name: String,
    profile_sha256: String,
    pdo_indexes: Vec<u16>,
    rebuilt: bool,
    pub verified: bool,
    issues: Vec<Issue>,
}

pub(super) struct SavedProfile {
    pub(super) profile: Profile,
    file_name: String,
    pub(super) sha256: String,
}

impl SavedProfile {
    pub(super) fn load(path: &Path) -> Result<Self> {
        let (profile, raw): (Profile, _) = read_json(path, MAX_PROFILE_BYTES)?;
        profile
            .validate()
            .context("validate saved decoder profile")?;
        Ok(Self {
            profile,
            file_name: path
                .file_name()
                .context("profile path has no file name")?
                .to_string_lossy()
                .into_owned(),
            sha256: hex::encode(Sha256::digest(&raw)),
        })
    }
}

#[derive(Debug, Serialize)]
struct Issue {
    check: &'static str,
    detail: String,
}

impl Verification {
    pub(super) fn require_verified(&self) -> Result<()> {
        if let Some(issue) = self.issues.first() {
            anyhow::bail!("{}: {}", issue.check, issue.detail);
        }
        Ok(())
    }

    fn check(&mut self, matched: bool, check: &'static str, detail: impl Into<String>) {
        if !matched {
            self.issues.push(Issue {
                check,
                detail: detail.into(),
            });
        }
    }

    fn digest(&mut self, check: &'static str, recorded: &str, supplied: Option<&str>) {
        if !supplied.is_some_and(|digest| digest.eq_ignore_ascii_case(recorded)) {
            let supplied = supplied.unwrap_or("unavailable");
            self.check(
                false,
                check,
                format!("profile SHA-256 {recorded}, supplied SHA-256 {supplied}"),
            );
        }
    }
}

impl Review {
    pub fn verify_offline_profile(&self, path: &Path) -> Result<Verification> {
        self.verify_loaded_profile(&SavedProfile::load(path)?)
    }

    pub(super) fn verify_loaded_profile(&self, source: &SavedProfile) -> Result<Verification> {
        let saved = &source.profile;
        let provenance = saved
            .register_decoder
            .as_ref()
            .context("profile has no register decoder provenance")?;
        let pdo_indexes = match provenance.pdo_index {
            Some(index) => vec![index],
            None => provenance.pdos.iter().map(|pdo| pdo.pdo_index).collect(),
        };
        let saved_esi = saved
            .esi
            .as_ref()
            .context("profile has no ESI provenance")?;
        let mut result = Verification {
            schema: 1,
            scope: "saved_register_decoder_reconstruction",
            profile_file_name: source.file_name.clone(),
            profile_sha256: source.sha256.clone(),
            pdo_indexes,
            rebuilt: false,
            verified: false,
            issues: Vec::new(),
        };
        result.check(
            saved_esi.identity == self.identity,
            "identity",
            "supplied ESI identity differs from the profile",
        );
        result.digest("esi_hash", &saved_esi.sha256, Some(&self.esi_sha256));
        result.digest(
            "fmmu_hash",
            &provenance.fmmu_sha256,
            self.fmmu.as_ref().map(|source| source.sha256.as_str()),
        );
        result.digest(
            "reply_hash",
            &provenance.reply_sha256,
            self.logical_payload
                .as_ref()
                .map(|source| source.sha256.as_str()),
        );
        result.check(
            self.fmmu
                .as_ref()
                .is_some_and(|source| source.station_address == provenance.station_address),
            "station",
            "supplied station differs from the profile",
        );
        if let Some(digest) = provenance.manual_layout_sha256.as_deref().or_else(|| {
            provenance
                .pdos
                .iter()
                .find_map(|pdo| pdo.manual_layout_sha256.as_deref())
        }) {
            result.digest(
                "manual_layout_hash",
                digest,
                self.manual_register_layout
                    .as_ref()
                    .map(|source| source.sha256.as_str()),
            );
        }
        match self.offline_profile_for_pdos(&result.pdo_indexes) {
            Ok(rebuilt) => {
                result.rebuilt = true;
                compare_reconstruction(&mut result, saved, provenance, &rebuilt)?;
            }
            Err(error) => result.check(false, "reconstruction", format!("{error:#}")),
        }
        result.verified = result.issues.is_empty();
        Ok(result)
    }
}

fn compare_reconstruction(
    result: &mut Verification,
    saved: &Profile,
    old: &Provenance,
    rebuilt: &Profile,
) -> Result<()> {
    let new = rebuilt
        .register_decoder
        .as_ref()
        .context("rebuilt profile has no register decoder provenance")?;
    result.check(
        old.packed_bits == new.packed_bits
            && old.pdos.len() == new.pdos.len()
            && old.pdos.iter().zip(&new.pdos).all(|(a, b)| {
                (a.pdo_index, a.bit_offset, a.width_bits)
                    == (b.pdo_index, b.bit_offset, b.width_bits)
            }),
        "pdo_ranges",
        "packed PDO offsets, widths or image size differ from the reconstruction",
    );
    let manual_matches = |old_bit, old_hash: Option<&str>, new_bit, new_hash: Option<&str>| {
        old_bit == new_bit
            && old_hash
                .unwrap_or("")
                .eq_ignore_ascii_case(new_hash.unwrap_or(""))
    };
    result.check(
        manual_matches(
            old.manual_start_bit,
            old.manual_layout_sha256.as_deref(),
            new.manual_start_bit,
            new.manual_layout_sha256.as_deref(),
        ) && old.pdos.iter().zip(&new.pdos).all(|(a, b)| {
            manual_matches(
                a.manual_start_bit,
                a.manual_layout_sha256.as_deref(),
                b.manual_start_bit,
                b.manual_layout_sha256.as_deref(),
            )
        }),
        "manual_placement",
        "manual bit or per-PDO layout provenance differs from the reconstruction",
    );
    result.check(
        old.packed_hex.eq_ignore_ascii_case(&new.packed_hex),
        "packed_sample",
        "saved packed sample differs from the reconstructed bytes",
    );
    result.check(
        old.withheld_bits == new.withheld_bits
            && saved.tx.len() == rebuilt.tx.len()
            && saved.tx.iter().zip(&rebuilt.tx).all(|(field, expected)| {
                let mut field = field.clone();
                field.log = expected.log;
                field == *expected
            }),
        "decoder_fields",
        "typed fields or withheld bit offsets differ from the reconstruction",
    );
    Ok(())
}

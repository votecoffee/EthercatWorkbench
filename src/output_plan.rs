//! Review and bind an offline one-shot output proposal.
use crate::{
    benchmark::hash,
    model::{Identity, Profile, Source, payload_hex},
    output_stage::profile_hash,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read, path::Path};

const MAX_PLAN_BYTES: u64 = 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StopPlan {
    pub safe_rx_hex: String,
    pub watchdog_us: u64,
    pub max_op_us: u64,
    pub stop_observation: String,
    pub expected_serial: Option<u32>,
}

#[derive(Serialize)]
struct Field<'a> {
    name: &'a str,
    bit: usize,
    width: usize,
    source: &'a Source,
    staged: Option<String>,
    safe: Option<String>,
}

#[derive(Serialize)]
struct Proposal<'a> {
    schema: u32,
    scope: &'static str,
    profile_sha256: String,
    nic: &'a str,
    expected_identity: &'a Identity,
    rx_bytes: usize,
    staged_rx_hex: String,
    stop: StopPlan,
    fields: Vec<Field<'a>>,
    steps: [&'static str; 6],
    unknown_write_outcome: &'static str,
}

#[derive(Serialize)]
pub struct Review<'a> {
    pub plan_sha256: String,
    proposal: Proposal<'a>,
}

impl Review<'_> {
    pub(crate) fn check_profile(&self, profile_sha256: &str) -> Result<()> {
        ensure!(
            self.proposal.profile_sha256 == profile_sha256,
            "profile changed after output plan review"
        );
        Ok(())
    }

    pub(crate) fn stop(&self) -> &StopPlan {
        &self.proposal.stop
    }
}

pub fn prepare(profile: &Profile, mut stop: StopPlan) -> Result<Review<'_>> {
    profile.validate()?;
    let expected_identity = profile
        .expected_identity
        .as_ref()
        .context("output plan requires an exact identity")?;
    ensure!(
        !profile.nic.trim().is_empty() && profile.nic == profile.nic.trim(),
        "output plan requires the exact isolated NIC in the profile"
    );
    let staged = payload_hex(&profile.staged_rx_hex)?;
    let safe = payload_hex(&stop.safe_rx_hex)?;
    ensure!(
        profile.rx_bytes > 0 && staged.len() == profile.rx_bytes && safe.len() == profile.rx_bytes,
        "both staged and safe images must contain exactly {} RxPDO bytes",
        profile.rx_bytes
    );
    ensure!(
        stop.watchdog_us > 0 && stop.max_op_us > 0,
        "watchdog and maximum OP time must be positive"
    );
    ensure!(
        !stop.stop_observation.trim().is_empty() && stop.stop_observation.len() <= 2048,
        "describe the independent stop observation in 1–2048 bytes"
    );
    stop.safe_rx_hex = hex::encode_upper(&safe);
    let proposal = Proposal {
        schema: 1,
        scope: "offline_one_shot_output_plan",
        profile_sha256: profile_hash(profile)?,
        nic: &profile.nic,
        expected_identity,
        rx_bytes: profile.rx_bytes,
        staged_rx_hex: hex::encode_upper(&staged),
        stop,
        fields: profile
            .rx
            .iter()
            .map(|field| Field {
                name: &field.name,
                bit: field.bit,
                width: field.width,
                source: &field.source,
                staged: field.decode(&staged),
                safe: field.decode(&safe),
            })
            .collect(),
        steps: [
            "verify_identity_and_mapping",
            "preload_safe_image",
            "confirm_op",
            "write_staged_image_once",
            "restore_safe_image_on_confirmed_write",
            "confirm_init",
        ],
        unknown_write_outcome: "skip further output writes, attempt INIT, verify stop independently",
    };
    let review = Review {
        plan_sha256: hash(&serde_json::to_vec(&proposal)?),
        proposal,
    };
    ensure!(
        (serde_json::to_vec_pretty(&review)?.len() as u64) < MAX_PLAN_BYTES,
        "output plan exceeds 1 MiB"
    );
    Ok(review)
}

pub fn verify<'a>(profile: &'a Profile, path: &Path, expected: &str) -> Result<Review<'a>> {
    ensure!(
        expected.len() == 64 && expected.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "expected a 64-digit review SHA-256"
    );
    let mut data = Vec::new();
    File::open(path)
        .with_context(|| format!("open output plan {}", path.display()))?
        .take(MAX_PLAN_BYTES + 1)
        .read_to_end(&mut data)?;
    ensure!(
        data.len() as u64 <= MAX_PLAN_BYTES,
        "output plan exceeds 1 MiB"
    );
    let saved: serde_json::Value =
        serde_json::from_slice(data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&data))?;
    let stop: StopPlan = serde_json::from_value(
        saved
            .pointer("/proposal/stop")
            .context("output plan stop policy is missing")?
            .clone(),
    )?;
    let current = prepare(profile, stop)?;
    ensure!(
        current.plan_sha256.eq_ignore_ascii_case(expected)
            && saved == serde_json::to_value(&current)?,
        "output plan differs from the reviewed digest or current profile"
    );
    Ok(current)
}

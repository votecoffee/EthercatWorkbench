//! Export a complete or partial group replay audit with its original source bytes.
use super::{
    InputGroup, MAX_DEVICES,
    audit::{self, Audit, Evidence},
    read_json,
};
use crate::{
    capture::part_path,
    comparison_bundle::{copy_checked, json_bytes, require_entry, write_new},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

const COMPLETION: &str = "bundle.json";
const MANIFEST: &str = "manifest.json";
const FIXTURE: &str = "fixture.json";
const REPLAY: &str = "replay.json";
const EVIDENCE: [&str; 3] = ["fmmu.json", "sync-managers.json", "pdo.json"];
const CSV_BASE: &str = "csv/capture.csv";
const MAX_RECEIPT_BYTES: u64 = 1024 * 1024;
// A failed rotation may leave one additional header-only part.
const MAX_CSV_PARTS: usize = 4097;

pub struct Sources<'a> {
    pub manifest: &'a Path,
    pub fixture: &'a Path,
    pub replay: &'a Path,
    pub csv: &'a Path,
    pub evidence: Evidence<'a>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stamp {
    bytes: u64,
    sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    schema: u32,
    source: String,
    manifest: Stamp,
    fixture: Stamp,
    replay: Stamp,
    profiles: Vec<Stamp>,
    fmmu: Option<Stamp>,
    sync_managers: Option<Stamp>,
    pdo: Option<Stamp>,
    rotated: bool,
    csv: Vec<Stamp>,
    expected_rows: u64,
    verified_rows: u64,
    complete: bool,
}

#[derive(Serialize)]
pub struct VerifiedBundle {
    directory: PathBuf,
    receipt_sha256: String,
    receipt: Receipt,
    audit: Audit,
}

impl Receipt {
    fn from_audit(sources: &Sources<'_>, group: &InputGroup, checked: &Audit) -> Result<Self> {
        let [fmmu, sync_managers, pdo] = [
            sources.evidence.fmmu,
            sources.evidence.sync_managers,
            sources.evidence.pdo,
        ]
        .into_iter()
        .zip(&checked.evidence_hashes)
        .map(|(path, hash)| {
            path.zip(hash.as_deref())
                .map(|(path, hash)| stamp(path, hash))
                .transpose()
        })
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .expect("three evidence roles");
        Ok(Self {
            schema: 1,
            source: "group_replay_bundle".into(),
            manifest: stamp(sources.manifest, &group.manifest_sha256)?,
            fixture: stamp(sources.fixture, &checked.fixture_sha256)?,
            replay: stamp(sources.replay, &checked.receipt_sha256)?,
            profiles: group
                .bindings
                .iter()
                .map(|binding| stamp(&binding.profile_file, &binding.profile_sha256))
                .collect::<Result<_>>()?,
            fmmu,
            sync_managers,
            pdo,
            rotated: checked.rotated,
            csv: checked
                .parts
                .iter()
                .map(|part| Stamp {
                    bytes: part.bytes,
                    sha256: part.sha256.clone(),
                })
                .collect(),
            expected_rows: checked.expected_rows,
            verified_rows: checked.verified_rows,
            complete: checked.complete,
        })
    }

    fn entries(&self) -> Result<Vec<(PathBuf, &Stamp)>> {
        let mut files = vec![
            (PathBuf::from(MANIFEST), &self.manifest),
            (PathBuf::from(FIXTURE), &self.fixture),
            (PathBuf::from(REPLAY), &self.replay),
        ];
        files.extend(
            self.profiles
                .iter()
                .enumerate()
                .map(|(position, stamp)| (profile_path(position), stamp)),
        );
        files.extend(
            EVIDENCE
                .into_iter()
                .zip([&self.fmmu, &self.sync_managers, &self.pdo])
                .filter_map(|(name, stamp)| stamp.as_ref().map(|stamp| (name.into(), stamp))),
        );
        for (index, stamp) in self.csv.iter().enumerate() {
            let path = part_path(
                Path::new(CSV_BASE),
                index as u64 + 1,
                u64::from(self.rotated),
            )?;
            files.push((path, stamp));
        }
        Ok(files)
    }
}

pub fn create(sources: Sources<'_>, output: &Path) -> Result<Receipt> {
    let root = std::path::absolute(output).context("resolve group bundle directory")?;
    match fs::symlink_metadata(&root) {
        Ok(_) => bail!("bundle destination already exists: {}", root.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect bundle destination"),
    }
    let group = InputGroup::load(sources.manifest)?;
    let checked = audit::verify(
        &group,
        sources.fixture,
        sources.replay,
        sources.csv,
        sources.evidence,
    )?;
    let receipt = Receipt::from_audit(&sources, &group, &checked)?;
    let entries = receipt.entries()?;
    let sources = [sources.manifest, sources.fixture, sources.replay]
        .into_iter()
        .chain(
            group
                .bindings
                .iter()
                .map(|binding| binding.profile_file.as_path()),
        )
        .chain(
            [
                sources.evidence.fmmu,
                sources.evidence.sync_managers,
                sources.evidence.pdo,
            ]
            .into_iter()
            .flatten(),
        )
        .chain(checked.parts.iter().map(|part| part.file.as_path()));
    let sources: Vec<_> = sources.collect();
    ensure!(
        sources.len() == entries.len(),
        "audited sources differ from bundle inventory"
    );
    fs::create_dir(&root)
        .with_context(|| format!("create new bundle directory {}", root.display()))?;
    (|| -> Result<()> {
        fs::create_dir(root.join("profiles"))?;
        fs::create_dir(root.join("csv"))?;
        let stop = AtomicBool::new(false);
        for (source, (path, stamp)) in sources.into_iter().zip(entries) {
            copy_checked(source, &root.join(&path), stamp.bytes, &stamp.sha256, &stop)
                .with_context(|| format!("archive {}", path.display()))?;
        }
        // Publish the completion marker only after all copied evidence has been flushed.
        write_new(&root.join(COMPLETION), &json_bytes(&receipt)?)
    })()
    .with_context(|| format!("group bundle did not complete in {}", root.display()))?;
    Ok(receipt)
}

pub fn verify(directory: &Path) -> Result<VerifiedBundle> {
    let directory = std::path::absolute(directory).context("resolve group bundle directory")?;
    require_entry(&directory, true)?;
    let completion = directory.join(COMPLETION);
    require_entry(&completion, false)?;
    let (receipt, bytes) = read_json::<Receipt>(&completion, MAX_RECEIPT_BYTES)?;
    ensure!(
        receipt.schema == 1 && receipt.source == "group_replay_bundle",
        "expected a schema 1 group replay bundle"
    );
    ensure!(
        (1..=MAX_DEVICES).contains(&receipt.profiles.len())
            && (1..=MAX_CSV_PARTS).contains(&receipt.csv.len())
            && (receipt.rotated || receipt.csv.len() == 1)
            && (receipt.sync_managers.is_none() || receipt.fmmu.is_some())
            && (receipt.pdo.is_none() || receipt.sync_managers.is_some()),
        "invalid group bundle inventory"
    );
    require_entry(&directory.join("profiles"), true)?;
    require_entry(&directory.join("csv"), true)?;
    let entries = receipt.entries()?;
    for (path, stamp) in &entries {
        let path = directory.join(path);
        require_entry(&path, false)?;
        ensure!(
            fs::metadata(&path)?.len() == stamp.bytes,
            "bundle size differs for {}",
            path.display()
        );
    }
    let manifest = directory.join(MANIFEST);
    let fixture = directory.join(FIXTURE);
    let replay = directory.join(REPLAY);
    let csv = directory.join(CSV_BASE);
    let [fmmu, sync_managers, pdo] = EVIDENCE.map(|name| directory.join(name));
    let sources = Sources {
        manifest: &manifest,
        fixture: &fixture,
        replay: &replay,
        csv: &csv,
        evidence: Evidence {
            fmmu: receipt.fmmu.as_ref().map(|_| fmmu.as_path()),
            sync_managers: receipt
                .sync_managers
                .as_ref()
                .map(|_| sync_managers.as_path()),
            pdo: receipt.pdo.as_ref().map(|_| pdo.as_path()),
        },
    };
    let profiles: Vec<_> = (0..receipt.profiles.len())
        .map(|i| directory.join(profile_path(i)))
        .collect();
    let group = InputGroup::load_profiles(sources.manifest, Some(&profiles))?;
    let checked = audit::verify_with_layout(
        &group,
        sources.fixture,
        sources.replay,
        sources.csv,
        sources.evidence,
        Some((receipt.csv.len() as u64, receipt.rotated)),
    )?;
    let observed = Receipt::from_audit(&sources, &group, &checked)?;
    ensure!(
        (
            receipt.complete,
            receipt.expected_rows,
            receipt.verified_rows
        ) == (
            checked.complete,
            checked.expected_rows,
            checked.verified_rows
        ),
        "bundle completion or row counts differ from replay audit"
    );
    ensure!(
        entries == observed.entries()?,
        "bundle SHA-256 or file length differs from audited evidence"
    );
    Ok(VerifiedBundle {
        directory,
        receipt_sha256: hex::encode(Sha256::digest(&bytes)),
        receipt,
        audit: checked,
    })
}

fn profile_path(position: usize) -> PathBuf {
    Path::new("profiles").join(format!("{position:02}.json"))
}

fn stamp(path: &Path, sha256: &str) -> Result<Stamp> {
    let metadata = fs::metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "expected a regular evidence file at {}",
        path.display()
    );
    Ok(Stamp {
        bytes: metadata.len(),
        sha256: sha256.to_owned(),
    })
}

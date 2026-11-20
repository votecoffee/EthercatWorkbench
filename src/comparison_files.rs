//! Byte checks for the source files recorded in a saved scheduler comparison.
use crate::{
    benchmark::{self, SavedComparison},
    review::check_cancel,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering::Relaxed},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Match,
    Changed,
    Missing,
    Unreadable,
    Unresolved,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Self::Match => "Match",
            Self::Changed => "Changed",
            Self::Missing => "Missing",
            Self::Unreadable => "Unreadable",
            Self::Unresolved => "Unresolved",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct FileCheck {
    pub trial: usize,
    pub csv_part: Option<usize>,
    pub recorded_path: PathBuf,
    pub resolved_path: Option<PathBuf>,
    pub expected_sha256: String,
    pub observed_sha256: Option<String>,
    pub expected_bytes: Option<u64>,
    pub observed_bytes: Option<u64>,
    pub status: Status,
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub comparison_file: PathBuf,
    pub comparison_sha256: String,
    pub base: Option<PathBuf>,
    pub csv_hashes_recorded: bool,
    pub all_match: bool,
    pub files: Vec<FileCheck>,
}

#[derive(Debug, Serialize)]
pub struct CheckedComparison {
    #[serde(skip)]
    pub saved: SavedComparison,
    #[serde(flatten)]
    pub report: Report,
}

pub fn check(
    file: &Path,
    base: Option<&Path>,
    expected_comparison_sha256: Option<&str>,
    stop: &AtomicBool,
) -> Result<CheckedComparison> {
    let saved = benchmark::inspect_saved_comparison(file, stop)?;
    ensure!(
        expected_comparison_sha256.is_none_or(|expected| expected == saved.sha256),
        "the comparison JSON changed; reopen it before checking source hashes"
    );
    check_saved(saved, base, stop)
}

pub(crate) fn check_saved(
    saved: SavedComparison,
    base: Option<&Path>,
    stop: &AtomicBool,
) -> Result<CheckedComparison> {
    let base = base
        .map(std::path::absolute)
        .transpose()
        .context("resolve relative-reference base folder")?;
    let mut files = Vec::new();
    for (index, trial) in saved.comparison.trials.iter().enumerate() {
        check_cancel(Some(stop))?;
        let number = index + 1;
        files.push(
            new_file(number, None, &trial.file, &trial.sha256, None)
                .with_context(|| format!("trial {number} report reference"))?,
        );
        if let Some(audits) = &saved.comparison.csv_audits {
            let audit = &audits[index];
            ensure!(
                audit.report == trial.file
                    && audit.report_sha256.eq_ignore_ascii_case(&trial.sha256)
                    && audit.parts.len() as u64 == trial.capture.parts,
                "trial {number} CSV audit does not match its report reference or part count"
            );
            for (part, source) in audit.parts.iter().enumerate() {
                check_cancel(Some(stop))?;
                files.push(
                    new_file(
                        number,
                        Some(part + 1),
                        &source.file,
                        &source.sha256,
                        Some(source.bytes),
                    )
                    .with_context(|| format!("trial {number} CSV part {} reference", part + 1))?,
                );
            }
        }
    }
    // Resolve and read files only after checking the comparison's reference inventory.
    for entry in &mut files {
        check_cancel(Some(stop))?;
        inspect(entry, base.as_deref(), stop);
        check_cancel(Some(stop))?;
    }
    let report = Report {
        schema: 1,
        comparison_file: saved.file.clone(),
        comparison_sha256: saved.sha256.clone(),
        base,
        csv_hashes_recorded: saved.comparison.csv_audits.is_some(),
        all_match: files.iter().all(|entry| entry.status == Status::Match),
        files,
    };
    Ok(CheckedComparison { saved, report })
}

fn new_file(
    trial: usize,
    csv_part: Option<usize>,
    path: &Path,
    sha: &str,
    expected_bytes: Option<u64>,
) -> Result<FileCheck> {
    ensure!(!path.as_os_str().is_empty(), "recorded file path is empty");
    ensure!(
        sha.len() == 64 && sha.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid recorded SHA-256"
    );
    Ok(FileCheck {
        trial,
        csv_part,
        recorded_path: path.to_owned(),
        resolved_path: None,
        expected_sha256: sha.to_owned(),
        observed_sha256: None,
        expected_bytes,
        observed_bytes: None,
        status: Status::Unresolved,
        detail: None,
    })
}

fn resolve(path: &Path, base: Option<&Path>) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_owned());
    }
    ensure!(
        !path.has_root() && !matches!(path.components().next(), Some(Component::Prefix(_))),
        "recorded path needs a full drive or a folder-relative reference"
    );
    Ok(base
        .context("provide the original working folder for relative references")?
        .join(path))
}

fn inspect(entry: &mut FileCheck, base: Option<&Path>, stop: &AtomicBool) {
    let path = match resolve(&entry.recorded_path, base) {
        Ok(path) => path,
        Err(error) => {
            entry.detail = Some(error.to_string());
            return;
        }
    };
    let observation = observe(&path, entry.expected_bytes, stop);
    entry.resolved_path = Some(path);
    match observation {
        Ok((bytes, sha)) => {
            entry.observed_bytes = Some(bytes);
            entry.status = if sha
                .as_ref()
                .is_some_and(|hash| hash.eq_ignore_ascii_case(&entry.expected_sha256))
            {
                Status::Match
            } else {
                Status::Changed
            };
            entry.observed_sha256 = sha;
        }
        Err(error) => {
            entry.status = if error.kind() == io::ErrorKind::NotFound {
                Status::Missing
            } else {
                Status::Unreadable
            };
            entry.detail = Some(error.to_string());
        }
    }
}

fn observe(
    path: &Path,
    expected_bytes: Option<u64>,
    stop: &AtomicBool,
) -> io::Result<(u64, Option<String>)> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(io::Error::other("source is not a regular file"));
    }
    let file = File::open(path)?;
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(io::Error::other("source is not a regular file"));
    }
    if expected_bytes.is_some_and(|expected| expected != before.len()) {
        return Ok((before.len(), None));
    }
    let limit = expected_bytes.unwrap_or(benchmark::MAX_REPORT_BYTES);
    if before.len() > limit {
        return Err(io::Error::other("source report exceeds 16 MiB"));
    }
    let mut reader = (&file).take(limit.saturating_add(1));
    let mut digest = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        if stop.load(Relaxed) {
            return Err(io::Error::other("source hash check cancelled"));
        }
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        digest.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    if bytes != before.len()
        || after.len() != before.len()
        || after.modified().ok() != before.modified().ok()
    {
        return Err(io::Error::other("source changed while it was being read"));
    }
    Ok((bytes, Some(hex::encode(digest.finalize()))))
}

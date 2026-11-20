//! Create and verify a portable directory of saved comparison evidence.
use crate::{
    benchmark::{self, Comparison},
    capture::part_path,
    comparison_files,
    review::check_cancel,
    trial_set::{Row, TrialSet},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

const ORIGINAL: &str = "original-comparison.json";
const PORTABLE: &str = "comparison.json";
const TRIAL_SET: &str = "trials.json";
const RECEIPT: &str = "bundle.json";
const MAX_RECEIPT_BYTES: u64 = 16 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema: u32,
    pub original_comparison: String,
    pub original_comparison_sha256: String,
    pub portable_comparison: String,
    pub portable_comparison_sha256: String,
    pub trial_set: String,
    pub trial_set_sha256: String,
    pub reports: usize,
    pub csv_parts: usize,
    pub csv_hashes_recorded: bool,
}

#[derive(Debug, Serialize)]
pub struct VerifiedBundle {
    pub directory: PathBuf,
    pub receipt_sha256: String,
    pub receipt: Receipt,
    pub comparison: comparison_files::CheckedComparison,
}

struct BundleFiles {
    directory: PathBuf,
    receipt_sha256: String,
    receipt: Receipt,
    saved: benchmark::SavedComparison,
}

pub fn verify(directory: &Path, stop: &AtomicBool) -> Result<VerifiedBundle> {
    let BundleFiles {
        directory,
        receipt_sha256,
        receipt,
        saved,
    } = read_bundle(directory, None, stop)?;
    let comparison = comparison_files::check_saved(saved, Some(&directory), stop)?;
    require_matching(&comparison)?;
    Ok(VerifiedBundle {
        directory,
        receipt_sha256,
        receipt,
        comparison,
    })
}

pub fn compare(
    directory: &Path,
    expected_receipt_sha256: Option<&str>,
    stop: &AtomicBool,
) -> Result<Comparison> {
    let bundle = read_bundle(directory, expected_receipt_sha256, stop)?;
    let saved = bundle.saved.comparison;
    let reports: Vec<_> = saved
        .trials
        .iter()
        .map(|trial| bundle.directory.join(&trial.file))
        .collect();
    let bases: Option<Vec<_>> = saved.csv_audits.as_ref().map(|audits| {
        audits
            .iter()
            .map(|audit| bundle.directory.join(&audit.csv_base))
            .collect()
    });
    let result = benchmark::compare_cancelable(&reports, bases.as_deref(), stop)?;
    for (index, (expected, fresh)) in saved.trials.iter().zip(&result.trials).enumerate() {
        ensure!(
            expected.sha256.eq_ignore_ascii_case(&fresh.sha256),
            "trial {} report changed since the bundle was created",
            index + 1
        );
    }
    if let (Some(expected), Some(fresh)) = (&saved.csv_audits, &result.csv_audits) {
        for (index, (expected, fresh)) in expected.iter().zip(fresh).enumerate() {
            let trial = index + 1;
            ensure!(
                expected.parts.len() == fresh.parts.len(),
                "trial {trial} CSV part count changed since the bundle was created"
            );
            for (part, (expected, fresh)) in expected.parts.iter().zip(&fresh.parts).enumerate() {
                check_cancel(Some(stop))?;
                ensure!(
                    bundle.directory.join(&expected.file) == fresh.file
                        && expected.bytes == fresh.bytes
                        && expected.sha256.eq_ignore_ascii_case(&fresh.sha256),
                    "trial {trial} CSV part {} changed since the bundle was created",
                    part + 1
                );
            }
        }
    }
    check_cancel(Some(stop))?;
    Ok(result)
}

fn read_bundle(
    directory: &Path,
    expected_receipt_sha256: Option<&str>,
    stop: &AtomicBool,
) -> Result<BundleFiles> {
    check_cancel(Some(stop))?;
    let directory = std::path::absolute(directory).context("resolve bundle directory")?;
    require_entry(&directory, true)?;
    for name in [RECEIPT, ORIGINAL, PORTABLE, TRIAL_SET] {
        require_entry(&directory.join(name), false)?;
    }

    let mut bytes = Vec::new();
    File::open(directory.join(RECEIPT))?
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read bundle.json")?;
    ensure!(
        bytes.len() as u64 <= MAX_RECEIPT_BYTES,
        "bundle.json exceeds 16 KiB"
    );
    let receipt_sha256 = benchmark::hash(&bytes);
    ensure!(
        expected_receipt_sha256
            .is_none_or(|expected| expected.eq_ignore_ascii_case(&receipt_sha256)),
        "bundle.json changed; verify and open the bundle again"
    );
    let receipt: Receipt = serde_json::from_slice(&bytes).context("parse bundle.json")?;
    ensure!(
        receipt.schema == 1,
        "unsupported bundle schema {}",
        receipt.schema
    );
    ensure!(
        receipt.original_comparison == ORIGINAL
            && receipt.portable_comparison == PORTABLE
            && receipt.trial_set == TRIAL_SET,
        "bundle.json file names do not match schema 1"
    );
    let original = benchmark::read_report_bytes_with_stop(&directory.join(ORIGINAL), Some(stop))?;
    require_hash(
        ORIGINAL,
        &receipt.original_comparison_sha256,
        &benchmark::hash(&original),
    )?;
    let portable = benchmark::inspect_saved_comparison(&directory.join(PORTABLE), stop)?;
    require_hash(
        PORTABLE,
        &receipt.portable_comparison_sha256,
        &portable.sha256,
    )?;
    let set_bytes = TrialSet::read_bytes(&directory.join(TRIAL_SET))?;
    require_hash(
        TRIAL_SET,
        &receipt.trial_set_sha256,
        &benchmark::hash(&set_bytes),
    )?;
    let set = TrialSet::parse(&set_bytes)?;
    verify_layout(&directory, &receipt, &portable.comparison, &set, stop)?;

    Ok(BundleFiles {
        directory,
        receipt_sha256,
        receipt,
        saved: portable,
    })
}

fn require_hash(name: &str, expected: &str, observed: &str) -> Result<()> {
    ensure!(
        expected.eq_ignore_ascii_case(observed),
        "{name} SHA-256 does not match bundle.json"
    );
    Ok(())
}

fn verify_layout(
    directory: &Path,
    receipt: &Receipt,
    comparison: &Comparison,
    set: &TrialSet,
    stop: &AtomicBool,
) -> Result<()> {
    let audits = comparison.csv_audits.as_deref();
    let csv_parts = audits.map_or(0, |items| items.iter().map(|audit| audit.parts.len()).sum());
    ensure!(
        receipt.reports == comparison.trials.len()
            && receipt.csv_parts == csv_parts
            && receipt.csv_hashes_recorded == audits.is_some(),
        "bundle.json coverage does not match comparison.json"
    );
    ensure!(
        set.audit_csv == receipt.csv_hashes_recorded && set.trials.len() == receipt.reports,
        "trials.json coverage does not match comparison.json"
    );
    let rotate = rotation(comparison)?;
    for (index, (trial, row)) in comparison.trials.iter().zip(&set.trials).enumerate() {
        check_cancel(Some(stop))?;
        let number = index + 1;
        let expected_report = report_path(number);
        let expected_csv = audits.map(|_| csv_base(number));
        let row = row.input();
        ensure!(
            trial.file == expected_report
                && row.report == expected_report
                && row.csv == expected_csv,
            "trial {number} paths do not match the bundle layout"
        );
        require_entry(&directory.join(trial_dir(number)), true)?;
        require_entry(&directory.join(expected_report), false)?;
        if let Some(audits) = audits {
            let audit = &audits[index];
            let csv = csv_base(number);
            ensure!(
                audit.report == trial.file
                    && audit.csv_base == csv
                    && audit.report_sha256.eq_ignore_ascii_case(&trial.sha256)
                    && audit.parts.len() as u64 == trial.capture.parts
                    && !audit.parts.is_empty()
                    && (rotate != 0 || audit.parts.len() == 1),
                "trial {number} CSV audit does not match the bundle layout"
            );
            for (part, entry) in audit.parts.iter().enumerate() {
                check_cancel(Some(stop))?;
                let expected = part_path(&csv, (part + 1) as u64, rotate)?;
                ensure!(
                    entry.file == expected,
                    "trial {number} CSV part {} does not match the bundle layout",
                    part + 1
                );
                require_entry(&directory.join(expected), false)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn require_entry(path: &Path, directory: bool) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    let kind = metadata.file_type();
    #[cfg(windows)]
    let reparse = {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    };
    #[cfg(not(windows))]
    let reparse = kind.is_symlink();
    ensure!(
        !reparse
            && if directory {
                kind.is_dir()
            } else {
                kind.is_file()
            },
        "expected an ordinary {} at {}",
        if directory { "directory" } else { "file" },
        path.display()
    );
    Ok(())
}

pub fn create(
    file: &Path,
    base: Option<&Path>,
    output: &Path,
    stop: &AtomicBool,
) -> Result<Receipt> {
    create_checked(file, base, output, None, stop)
}

pub(crate) fn create_checked(
    file: &Path,
    base: Option<&Path>,
    output: &Path,
    expected_sha256: Option<&str>,
    stop: &AtomicBool,
) -> Result<Receipt> {
    let root = std::path::absolute(output).context("resolve bundle directory")?;
    match fs::symlink_metadata(&root) {
        Ok(_) => bail!("bundle destination already exists: {}", root.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect bundle destination"),
    }
    let checked = comparison_files::check(file, base, expected_sha256, stop)?;
    require_matching(&checked)?;
    let original = benchmark::read_report_bytes_with_stop(file, Some(stop))?;
    let original_hash = benchmark::hash(&original);
    ensure!(
        original_hash == checked.saved.sha256,
        "comparison changed during bundling"
    );

    let mut comparison = checked.saved.comparison;
    let audit_csv = comparison.csv_audits.is_some();
    let rotate = rotation(&comparison)?;
    let rows = rebase(&root, &mut comparison, rotate)?;
    let portable = json_bytes(&comparison)?;
    ensure!(
        portable.len() as u64 <= benchmark::MAX_REPORT_BYTES,
        "portable comparison exceeds 16 MiB"
    );

    check_cancel(Some(stop))?;
    fs::create_dir(&root)
        .with_context(|| format!("create new bundle directory {}", root.display()))?;
    let write_bundle = || -> Result<Receipt> {
        for trial in 1..=rows.len() {
            fs::create_dir(root.join(trial_dir(trial)))?;
        }
        for entry in &checked.report.files {
            let source = entry
                .resolved_path
                .as_deref()
                .context("source path is unresolved")?;
            let dest = match entry.csv_part {
                Some(part) => part_path(&csv_base(entry.trial), part as u64, rotate)?,
                None => report_path(entry.trial),
            };
            copy_checked(
                source,
                &root.join(dest),
                entry.observed_bytes.context("source size is unknown")?,
                &entry.expected_sha256,
                stop,
            )
            .with_context(|| format!("copy checked source {}", source.display()))?;
        }
        write_new(&root.join(ORIGINAL), &original)?;
        write_new(&root.join(PORTABLE), &portable)?;
        let set_path = root.join(TRIAL_SET);
        TrialSet::save_new(&set_path, &rows, audit_csv)?;
        let receipt = Receipt {
            schema: 1,
            original_comparison: ORIGINAL.into(),
            original_comparison_sha256: original_hash,
            portable_comparison: PORTABLE.into(),
            portable_comparison_sha256: benchmark::hash(&portable),
            trial_set: TRIAL_SET.into(),
            trial_set_sha256: benchmark::hash(&TrialSet::read_bytes(&set_path)?),
            reports: rows.len(),
            csv_parts: checked.report.files.len() - rows.len(),
            csv_hashes_recorded: audit_csv,
        };
        check_cancel(Some(stop))?;
        // A readable receipt is the completion marker for the folder.
        write_new(&root.join(RECEIPT), &json_bytes(&receipt)?)?;
        Ok(receipt)
    };
    write_bundle().with_context(|| format!("bundle did not complete in {}", root.display()))
}

fn require_matching(checked: &comparison_files::CheckedComparison) -> Result<()> {
    if let Some(problem) = checked
        .report
        .files
        .iter()
        .find(|entry| entry.status != comparison_files::Status::Match)
    {
        bail!(
            "source check found {} for trial {} at {}. Run check-comparison for the full list",
            problem.status.label(),
            problem.trial,
            problem.recorded_path.display()
        );
    }
    Ok(())
}

fn rotation(comparison: &Comparison) -> Result<u64> {
    if comparison.csv_audits.is_some() {
        comparison.common_profile_settings["rotate_rows"]
            .as_u64()
            .context("saved comparison needs a numeric CSV rotation setting")
    } else {
        Ok(0)
    }
}

fn trial_dir(number: usize) -> PathBuf {
    PathBuf::from(format!("trial-{number:02}"))
}
fn report_path(number: usize) -> PathBuf {
    trial_dir(number).join("run.json")
}
fn csv_base(number: usize) -> PathBuf {
    trial_dir(number).join("capture.csv")
}

fn rebase(root: &Path, comparison: &mut Comparison, rotate: u64) -> Result<Vec<Row>> {
    let mut rows = Vec::with_capacity(comparison.trials.len());
    for (index, trial) in comparison.trials.iter_mut().enumerate() {
        trial.file = report_path(index + 1);
        let mut csv = String::new();
        if let Some(audits) = &mut comparison.csv_audits {
            let audit = &mut audits[index];
            ensure!(
                !audit.parts.is_empty() && (rotate != 0 || audit.parts.len() == 1),
                "trial {} CSV parts do not match its rotation setting",
                index + 1
            );
            audit.report = trial.file.clone();
            audit.csv_base = csv_base(index + 1);
            for (part, entry) in audit.parts.iter_mut().enumerate() {
                entry.file = part_path(&audit.csv_base, (part + 1) as u64, rotate)?;
            }
            csv = path_text(&root.join(&audit.csv_base))?;
        }
        rows.push(Row {
            report: path_text(&root.join(&trial.file))?,
            csv,
        });
    }
    Ok(rows)
}

fn path_text(path: &Path) -> Result<String> {
    Ok(path
        .to_str()
        .context("bundle paths must be representable as Unicode")?
        .to_owned())
}

pub(crate) fn copy_checked(
    source: &Path,
    dest: &Path,
    bytes: u64,
    hash: &str,
    stop: &AtomicBool,
) -> Result<()> {
    check_cancel(Some(stop))?;
    ensure!(
        fs::metadata(source)?.is_file(),
        "source is not a regular file"
    );
    let file = File::open(source)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() == bytes,
        "source changed before copying"
    );
    let mut reader = file.take(bytes.saturating_add(1));
    let mut output = File::create_new(dest)?;
    let mut digest = Sha256::new();
    let mut copied = 0u64;
    let mut buffer = [0; 64 * 1024];
    loop {
        check_cancel(Some(stop))?;
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        copied += count as u64;
        ensure!(copied <= bytes, "source grew during copying");
        digest.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
    }
    ensure!(
        copied == bytes && hex::encode(digest.finalize()).eq_ignore_ascii_case(hash),
        "source changed during copying"
    );
    output.sync_all().context("flush copied source")
}

pub(crate) fn json_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file =
        File::create_new(path).with_context(|| format!("create new {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

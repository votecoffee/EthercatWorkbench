//! Copy the evidence referenced by a comparison into a portable directory.
use crate::{
    benchmark::{self, Comparison},
    capture::part_path,
    comparison_files,
    review::check_cancel,
    trial_set::{Row, TrialSet},
};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

#[derive(Debug, Serialize)]
pub struct Receipt {
    pub schema: u32,
    pub original_comparison: &'static str,
    pub original_comparison_sha256: String,
    pub portable_comparison: &'static str,
    pub portable_comparison_sha256: String,
    pub trial_set: &'static str,
    pub trial_set_sha256: String,
    pub reports: usize,
    pub csv_parts: usize,
    pub csv_hashes_recorded: bool,
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
    let original = benchmark::read_report_bytes_with_stop(file, Some(stop))?;
    let original_hash = benchmark::hash(&original);
    ensure!(
        original_hash == checked.saved.sha256,
        "comparison changed during bundling"
    );

    let mut comparison = checked.saved.comparison;
    let audit_csv = comparison.csv_audits.is_some();
    let rotate = if audit_csv {
        comparison.common_profile_settings["rotate_rows"]
            .as_u64()
            .context("saved comparison needs a numeric CSV rotation setting")?
    } else {
        0
    };
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
        write_new(&root.join("original-comparison.json"), &original)?;
        write_new(&root.join("comparison.json"), &portable)?;
        let set_path = root.join("trials.json");
        TrialSet::save_new(&set_path, &rows, audit_csv)?;
        let receipt = Receipt {
            schema: 1,
            original_comparison: "original-comparison.json",
            original_comparison_sha256: original_hash,
            portable_comparison: "comparison.json",
            portable_comparison_sha256: benchmark::hash(&portable),
            trial_set: "trials.json",
            trial_set_sha256: benchmark::hash(&fs::read(set_path)?),
            reports: rows.len(),
            csv_parts: checked.report.files.len() - rows.len(),
            csv_hashes_recorded: audit_csv,
        };
        check_cancel(Some(stop))?;
        // A readable receipt is the completion marker for the folder.
        write_new(&root.join("bundle.json"), &json_bytes(&receipt)?)?;
        Ok(receipt)
    };
    write_bundle().with_context(|| format!("bundle did not complete in {}", root.display()))
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

fn copy_checked(
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

fn json_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file =
        File::create_new(path).with_context(|| format!("create new {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

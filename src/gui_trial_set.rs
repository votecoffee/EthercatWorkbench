//! A saved desktop trial list stores ordered file references and the audit option.
use anyhow::{Context, Result, ensure};
use ethercat_workbench::review::Input;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

pub(super) const MAX_TRIALS: usize = 32;
const MAX_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Row {
    pub report: String,
    pub csv: String,
}

impl Row {
    pub fn is_empty(&self) -> bool {
        self.report.trim().is_empty() && self.csv.trim().is_empty()
    }

    pub fn input(&self) -> Input {
        Input {
            report: PathBuf::from(self.report.trim()),
            csv: (!self.csv.trim().is_empty()).then(|| PathBuf::from(self.csv.trim())),
        }
    }

    fn map_paths(&self, mut map: impl FnMut(&str) -> Result<String>) -> Result<Self> {
        Ok(Self {
            report: map(self.report.trim())?,
            csv: map(self.csv.trim())?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TrialSet {
    schema: u32,
    pub audit_csv: bool,
    pub trials: Vec<Row>,
}

impl TrialSet {
    pub fn load(path: &Path) -> Result<Self> {
        let path = std::path::absolute(path).context("resolve trial set path")?;
        let parent = path.parent().context("trial set needs a file name")?;
        let mut bytes = Vec::new();
        File::open(&path)
            .with_context(|| format!("open {}", path.display()))?
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("read trial set")?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "trial set is larger than 2 MiB"
        );
        let mut set: Self =
            serde_json::from_slice(bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes))
                .context("parse trial set JSON")?;
        ensure!(
            set.schema == 1,
            "unsupported trial set schema {}",
            set.schema
        );
        check_count(set.trials.len())?;
        set.trials = set
            .trials
            .iter()
            .map(|row| {
                row.map_paths(|text| {
                    if text.is_empty() {
                        return Ok(String::new());
                    }
                    let reference = Path::new(text);
                    ensure!(
                        reference.is_absolute()
                            || (!reference.has_root()
                                && !matches!(
                                    reference.components().next(),
                                    Some(Component::Prefix(_))
                                )),
                        "use an absolute or trial-set-relative path: {text}"
                    );
                    let absolute = if reference.is_absolute() {
                        reference.to_path_buf()
                    } else {
                        parent.join(reference)
                    };
                    path_text(&absolute)
                })
            })
            .collect::<Result<_>>()?;
        Ok(set)
    }

    pub fn save_new(path: &Path, rows: &[Row], audit_csv: bool) -> Result<()> {
        check_count(rows.len())?;
        ensure!(
            path.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json")),
            "choose a trial set path ending in .json"
        );
        let path = std::path::absolute(path).context("resolve trial set path")?;
        let parent = path.parent().context("trial set needs a file name")?;
        let trials = rows
            .iter()
            .map(|row| {
                row.map_paths(|text| {
                    if text.is_empty() {
                        return Ok(String::new());
                    }
                    let absolute = std::path::absolute(text)
                        .with_context(|| format!("resolve trial reference {text}"))?;
                    let reference = absolute
                        .strip_prefix(parent)
                        .ok()
                        .filter(|relative| {
                            !relative.as_os_str().is_empty()
                                && !relative
                                    .components()
                                    .any(|part| matches!(part, Component::ParentDir))
                        })
                        .unwrap_or(&absolute);
                    path_text(reference)
                })
            })
            .collect::<Result<_>>()?;
        let mut bytes = serde_json::to_vec_pretty(&Self {
            schema: 1,
            audit_csv,
            trials,
        })?;
        bytes.push(b'\n');
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "trial set is larger than 2 MiB"
        );
        let mut file =
            File::create_new(&path).with_context(|| format!("create new {}", path.display()))?;
        file.write_all(&bytes).context("write trial set")?;
        file.sync_all().context("flush trial set")
    }
}

fn check_count(count: usize) -> Result<()> {
    ensure!(
        (1..=MAX_TRIALS).contains(&count),
        "trial set must contain 1–{MAX_TRIALS} rows"
    );
    Ok(())
}

fn path_text(path: &Path) -> Result<String> {
    Ok(path
        .to_str()
        .context("trial reference must be representable as Unicode")?
        .to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_dir() -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::path::absolute(format!(".local/trial-set-{}-{nonce}", std::process::id()))
            .unwrap();
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn round_trip_relocates_local_references_and_preserves_partial_rows() {
        let dir = fixture_dir();
        let set_path = dir.join("trials.json");
        let outside = dir.parent().unwrap().join("outside.run.json");
        let local = dir.join("captures/nonexistent.run.json");
        let csv = dir.join("captures/nonexistent.csv");
        let rows = vec![
            Row {
                report: path_text(&local).unwrap(),
                csv: path_text(&csv).unwrap(),
            },
            Row {
                report: path_text(&outside).unwrap(),
                csv: String::new(),
            },
            Row::default(),
        ];
        TrialSet::save_new(&set_path, &rows, false).unwrap();
        let bytes = std::fs::read(&set_path).unwrap();
        assert!(bytes.ends_with(b"\n"));
        let raw: TrialSet = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            Path::new(&raw.trials[0].report),
            Path::new("captures/nonexistent.run.json")
        );
        assert_eq!(Path::new(&raw.trials[1].report), outside);
        let loaded = TrialSet::load(&set_path).unwrap();
        assert_eq!(loaded.trials.len(), rows.len());
        for (actual, expected) in loaded.trials.iter().zip(&rows) {
            assert_eq!(actual.input(), expected.input());
        }
        assert!(!loaded.audit_csv);
        assert!(TrialSet::save_new(&set_path, &rows, true).is_err());
        assert_eq!(std::fs::read(&set_path).unwrap(), bytes);

        let relocated = dir.join("relocated");
        std::fs::create_dir(&relocated).unwrap();
        let copied = relocated.join("copy.json");
        std::fs::copy(&set_path, &copied).unwrap();
        let loaded = TrialSet::load(&copied).unwrap();
        assert_eq!(
            loaded.trials[0].input().report,
            relocated.join("captures/nonexistent.run.json")
        );
        assert_eq!(
            loaded.trials[0].input().csv,
            Some(relocated.join("captures/nonexistent.csv"))
        );
        assert_eq!(loaded.trials[1], rows[1]);
        assert!(loaded.trials[2].is_empty());
        std::fs::remove_file(copied).unwrap();
        std::fs::remove_dir(relocated).unwrap();
        std::fs::remove_file(set_path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn accepts_utf8_bom_and_rejects_invalid_schema_rows_and_size() {
        let dir = fixture_dir();
        let file = dir.join("draft.json");
        let valid = br#"{"schema":1,"audit_csv":true,"trials":[{"report":"","csv":""}]}"#;
        let mut bom = b"\xef\xbb\xbf".to_vec();
        bom.extend_from_slice(valid);
        std::fs::write(&file, bom).unwrap();
        assert!(TrialSet::load(&file).unwrap().trials[0].is_empty());
        for (bytes, message) in [
            (
                br#"{"schema":2,"audit_csv":true,"trials":[{"report":"","csv":""}]}"#.as_slice(),
                "unsupported trial set schema",
            ),
            (
                br#"{"schema":1,"audit_csv":true,"trials":[]}"#.as_slice(),
                "must contain",
            ),
            (
                br#"{"schema":1,"schema":1,"audit_csv":true,"trials":[]}"#.as_slice(),
                "duplicate field",
            ),
            (
                br#"{"schema":1,"audit_csv":true,"trials":[{"report":"C:drive.json","csv":""}]}"#
                    .as_slice(),
                "use an absolute or trial-set-relative path",
            ),
        ] {
            std::fs::write(&file, bytes).unwrap();
            assert!(format!("{:#}", TrialSet::load(&file).unwrap_err()).contains(message));
        }
        File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_len(MAX_BYTES + 1)
            .unwrap();
        assert!(
            TrialSet::load(&file)
                .unwrap_err()
                .to_string()
                .contains("larger than 2 MiB")
        );
        std::fs::remove_file(file).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}

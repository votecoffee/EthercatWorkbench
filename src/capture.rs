use crate::model::{Field, LogMode, MAX_PAYLOAD, Profile};
use anyhow::{Context, Result, ensure};
use chrono::{SecondsFormat, Utc};
use crossbeam_queue::ArrayQueue;
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
struct Sample {
    elapsed_us: u64,
    index: u64,
    generation: u64,
    cycle: u64,
    data: [u8; MAX_PAYLOAD],
}

pub(crate) const METADATA: [&str; 5] = [
    "capture_start_utc",
    "elapsed_us",
    "sample_index",
    "connection_generation",
    "cycle_index",
];

struct Shared {
    queue: ArrayQueue<Sample>,
    done: AtomicBool,
    failed: AtomicBool,
    written: AtomicU64,
    parts: AtomicU64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CaptureStats {
    pub selected: u64,
    pub written: u64,
    pub overruns: u64,
    pub utc_start: String,
    pub parts: u64,
}

pub struct Capture {
    shared: Arc<Shared>,
    writer: Option<JoinHandle<Result<u64>>>,
    start: Instant,
    utc: String,
    fields: Vec<Field>,
    len: usize,
    mode: LogMode,
    previous: Option<Sample>,
    selected: u64,
    overruns: u64,
}

impl Capture {
    pub fn start(path: &Path, profile: &Profile) -> Result<Self> {
        let fields: Vec<_> = profile.tx.iter().filter(|f| f.log).cloned().collect();
        ensure!(
            !fields.is_empty(),
            "select at least one TxPDO field for CSV"
        );
        ensure!(
            path.extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("csv")),
            "capture path must end in .csv"
        );
        ensure!(
            fields
                .iter()
                .all(|field| !METADATA.contains(&field.name.as_str())),
            "field name conflicts with a CSV metadata column"
        );
        let shared = Arc::new(Shared {
            queue: ArrayQueue::new(profile.queue_capacity),
            done: false.into(),
            failed: false.into(),
            written: 0.into(),
            parts: 1.into(),
        });
        let start = Instant::now();
        let utc = Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true);
        let first = part(path, 1, profile.rotate_rows, &fields)?;
        let writer = thread::Builder::new().name("csv-writer".into()).spawn({
            let shared = shared.clone();
            let path = path.to_owned();
            let fields = fields.clone();
            let utc = utc.clone();
            let rotate = profile.rotate_rows;
            let len = profile.tx_bytes;
            move || {
                let result = drain(&shared, &path, first, &fields, &utc, len, rotate);
                if result.is_err() {
                    shared.failed.store(true, Relaxed);
                }
                result
            }
        })?;
        Ok(Self {
            shared,
            writer: Some(writer),
            start,
            utc,
            fields,
            len: profile.tx_bytes,
            mode: profile.mode,
            previous: None,
            selected: 0,
            overruns: 0,
        })
    }

    pub fn submit(
        &mut self,
        received: Instant,
        generation: u64,
        cycle: u64,
        data: &[u8; MAX_PAYLOAD],
    ) {
        if self.mode == LogMode::Change
            && self.previous.as_ref().is_some_and(|previous| {
                previous.generation == generation
                    && self
                        .fields
                        .iter()
                        .all(|f| !f.changed(&data[..self.len], &previous.data[..self.len]))
            })
        {
            return;
        }
        self.selected += 1;
        let sample = Sample {
            elapsed_us: received.saturating_duration_since(self.start).as_micros() as u64,
            index: self.selected,
            generation,
            cycle,
            data: *data,
        };
        if self.shared.queue.push(sample).is_ok() {
            self.previous = Some(sample);
        } else {
            self.overruns += 1;
        }
    }

    pub fn failed(&self) -> bool {
        self.shared.failed.load(Relaxed)
    }

    pub fn stats(&self) -> CaptureStats {
        CaptureStats {
            selected: self.selected,
            written: self.shared.written.load(Relaxed),
            overruns: self.overruns,
            utc_start: self.utc.clone(),
            parts: self.shared.parts.load(Relaxed),
        }
    }

    pub fn finish(mut self) -> (CaptureStats, Result<()>) {
        let result = self.join();
        let mut stats = self.stats();
        if let Ok(parts) = result {
            stats.parts = parts;
        }
        (stats, result.map(|_| ()))
    }

    fn join(&mut self) -> Result<u64> {
        self.shared
            .done
            .store(true, std::sync::atomic::Ordering::Release);
        let Some(writer) = self.writer.take() else {
            return Ok(0);
        };
        writer.thread().unpark();
        writer
            .join()
            .map_err(|_| anyhow::anyhow!("CSV writer panicked"))?
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        let _ = self.join();
    }
}

type Writer = csv::Writer<std::fs::File>;

pub(crate) fn part_path(base: &Path, index: u64, rotate: u64) -> Result<PathBuf> {
    let path = if rotate == 0 {
        base.to_owned()
    } else {
        let mut name = base
            .file_stem()
            .context("capture path needs a file stem")?
            .to_os_string();
        name.push(format!(".{index:04}.csv"));
        let mut path = PathBuf::from(base);
        path.set_file_name(name);
        path
    };
    Ok(path)
}

fn part(base: &Path, index: u64, rotate: u64, fields: &[Field]) -> Result<Writer> {
    let path = part_path(base, index, rotate)?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("create capture {}", path.display()))?;
    let mut writer = csv::WriterBuilder::new()
        .buffer_capacity(128 * 1024)
        .from_writer(file);
    writer.write_record(
        METADATA
            .into_iter()
            .chain(fields.iter().map(|field| field.name.as_str())),
    )?;
    Ok(writer)
}

fn drain(
    shared: &Shared,
    path: &Path,
    mut writer: Writer,
    fields: &[Field],
    utc: &str,
    len: usize,
    rotate: u64,
) -> Result<u64> {
    let mut part_index = 1;
    let mut rows_in_part = 0;
    let mut record = Vec::with_capacity(fields.len() + 5);
    loop {
        let done = shared.done.load(std::sync::atomic::Ordering::Acquire);
        let mut batch = 0;
        for _ in 0..256 {
            let Some(sample) = shared.queue.pop() else {
                break;
            };
            if rotate > 0 && rows_in_part == rotate {
                writer.flush()?;
                shared.written.fetch_add(batch, Relaxed);
                batch = 0;
                part_index += 1;
                writer = part(path, part_index, rotate, fields)?;
                shared.parts.store(part_index, Relaxed);
                rows_in_part = 0;
            }
            record.clear();
            record.extend([
                utc.to_owned(),
                sample.elapsed_us.to_string(),
                sample.index.to_string(),
                sample.generation.to_string(),
                sample.cycle.to_string(),
            ]);
            record.extend(
                fields
                    .iter()
                    .map(|f| f.decode(&sample.data[..len]).unwrap_or_default()),
            );
            writer
                .write_record(&record)
                .with_context(|| format!("write CSV part {part_index}"))?;
            rows_in_part += 1;
            batch += 1;
        }
        writer
            .flush()
            .with_context(|| format!("flush CSV part {part_index}"))?;
        shared.written.fetch_add(batch, Relaxed);
        if done && shared.queue.is_empty() {
            writer.get_ref().sync_all()?;
            return Ok(part_index);
        }
        if shared.queue.is_empty() {
            thread::park_timeout(Duration::from_millis(10));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dropped_change_is_retried_and_leaves_a_visible_index_gap() {
        let mut capture = Capture {
            shared: Arc::new(Shared {
                queue: ArrayQueue::new(1),
                done: false.into(),
                failed: false.into(),
                written: 0.into(),
                parts: 1.into(),
            }),
            writer: None,
            start: Instant::now(),
            utc: String::new(),
            fields: vec![Field {
                width: 8,
                ..Field::default()
            }],
            len: 1,
            mode: LogMode::Change,
            previous: None,
            selected: 0,
            overruns: 0,
        };
        let mut data = [0; MAX_PAYLOAD];
        capture.submit(Instant::now(), 1, 1, &data);
        capture.submit(Instant::now(), 1, 2, &data);
        data[0] = 5;
        capture.submit(Instant::now(), 1, 3, &data);
        assert_eq!(capture.shared.queue.pop().unwrap().index, 1);
        capture.submit(Instant::now(), 1, 4, &data);
        let recovered = capture.shared.queue.pop().unwrap();
        assert_eq!(
            (recovered.index, recovered.cycle, recovered.data[0]),
            (3, 4, 5)
        );
        assert_eq!(capture.stats().overruns, 1);
        capture.submit(Instant::now(), 2, 1, &data);
        assert_eq!(capture.shared.queue.pop().unwrap().generation, 2);
    }
}

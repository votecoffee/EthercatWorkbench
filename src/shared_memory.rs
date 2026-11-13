//! Latest raw input, copied by a separate worker into a fixed Windows byte layout.
pub mod reader;
use crate::{
    input_feed::{self, Observation, Record},
    model::{MAX_PAYLOAD, Profile},
    run::Report,
};
use anyhow::{Context, Result, ensure};
use crossbeam_queue::ArrayQueue;
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        Arc,
        atomic::{
            AtomicBool, AtomicU64,
            Ordering::{Acquire, Relaxed, Release},
        },
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::Mapping;
#[cfg(not(windows))]
mod windows {
    use anyhow::{Result, bail};
    pub(super) struct Mapping {
        pub frequency: u64,
        pub process_created: u64,
    }
    impl Mapping {
        pub fn new(_: &str) -> Result<Self> {
            bail!("Shared memory requires Windows")
        }
        pub fn write(&mut self, _: impl FnOnce(u64, bool) -> [u8; super::SIZE]) -> Result<bool> {
            bail!("Shared memory requires Windows")
        }
    }
}
#[cfg(not(windows))]
use windows::Mapping;

pub const HEADER: usize = 512;
pub const SIZE: usize = HEADER + 2 * MAX_PAYLOAD;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub name: String,
    pub queue_capacity: usize,
    pub period_ms: u64,
    pub freshness_ms: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            name: "bench".into(),
            queue_capacity: 4096,
            period_ms: 10,
            freshness_ms: 100,
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(cfg!(windows), "Shared memory requires Windows");
        ensure!(
            (1..=64).contains(&self.name.len())
                && self
                    .name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'),
            "Shared memory name must be 1..64 ASCII letters, digits, _ or -"
        );
        ensure!(
            (1..=8192).contains(&self.queue_capacity),
            "Shared memory queue must be 1..8192"
        );
        ensure!(
            (1..=60000).contains(&self.period_ms) && (1..=60000).contains(&self.freshness_ms),
            "Shared memory period/freshness must be 1..60000 ms"
        );
        Ok(())
    }
    pub fn prefix(&self) -> String {
        format!("Local\\EtherCATWorkbench.{}", self.name)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Stats {
    pub mapping: String,
    pub mutex: String,
    pub stream_id: String,
    pub stream_start_utc: String,
    pub active: bool,
    pub offered: u64,
    pub drained: u64,
    pub queue_drops: u64,
    pub queue_pending: u64,
    pub coalesced: u64,
    pub written_events: u64,
    pub unsent_events: u64,
    pub publication_attempts: u64,
    pub writes: u64,
    pub lock_misses: u64,
    pub abandoned_recoveries: u64,
    pub shutdown_written: bool,
    pub worker_failed: bool,
    pub worker_error: Option<String>,
}
struct Shared {
    queue: ArrayQueue<Record>,
    active: AtomicBool,
    done: AtomicBool,
    worker_failed: AtomicBool,
    offered: AtomicU64,
    drained: AtomicU64,
    dropped: AtomicU64,
    coalesced: AtomicU64,
    written_events: AtomicU64,
    unsent: AtomicU64,
    attempts: AtomicU64,
    writes: AtomicU64,
    lock_misses: AtomicU64,
    abandoned: AtomicU64,
    shutdown_written: AtomicBool,
}
impl Shared {
    fn new(capacity: usize) -> Self {
        Self {
            queue: ArrayQueue::new(capacity),
            active: true.into(),
            done: false.into(),
            worker_failed: false.into(),
            offered: 0.into(),
            drained: 0.into(),
            dropped: 0.into(),
            coalesced: 0.into(),
            written_events: 0.into(),
            unsent: 0.into(),
            attempts: 0.into(),
            writes: 0.into(),
            lock_misses: 0.into(),
            abandoned: 0.into(),
            shutdown_written: false.into(),
        }
    }
}
pub(crate) struct Bound {
    mapping: Mapping,
    config: Config,
}
impl Bound {
    pub(crate) fn bind(config: &Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            mapping: Mapping::new(&config.prefix())
                .context("reserve shared memory before bus setup")?,
            config: config.clone(),
        })
    }
    pub(crate) fn stats(&self) -> Stats {
        Stats {
            mapping: format!("{}.data", self.config.prefix()),
            mutex: format!("{}.lock", self.config.prefix()),
            ..Default::default()
        }
    }
}
pub(crate) struct Hub {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<Result<()>>>,
    start: Instant,
    config: Config,
    id: String,
    utc: String,
    offered: u64,
}
impl Hub {
    pub(crate) fn start(bound: Bound, profile: &Profile, report: &Report) -> Result<Self> {
        let (start, utc, id) = input_feed::anchor();
        let shared = Arc::new(Shared::new(bound.config.queue_capacity));
        let metadata = Metadata {
            utc_us: chrono::DateTime::parse_from_rfc3339(&utc)?.timestamp_micros(),
            generation: report.connection_generation,
            expected: profile.expected_identity.clone(),
            observed: report.devices.first().and_then(|d| d.identity.clone()),
            station: report.devices.first().map_or(0, |d| d.station_address),
            position: report.devices.first().map_or(0, |d| d.position),
            profile_hash: report
                .context
                .as_ref()
                .map(|c| hex::decode(&c.profile_sha256))
                .transpose()?
                .map(|h| h.try_into().expect("SHA256 length")),
            backend: report.backend.clone(),
            tx_bytes: profile.tx_bytes,
            cycle_us: profile.requested_cycle_us,
        };
        let runtime = Runtime {
            config: bound.config.clone(),
            metadata,
            start,
            id: id.clone(),
            mapping: bound.mapping,
        };
        let worker_shared = shared.clone();
        let worker = thread::Builder::new()
            .name("shared-input-feed".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    runtime.serve(&worker_shared)
                }))
                .unwrap_or_else(|_| Err(anyhow::anyhow!("Shared memory worker panicked")));
                worker_shared.active.store(false, Release);
                worker_shared.worker_failed.store(result.is_err(), Release);
                result
            })
            .context("start shared memory worker")?;
        Ok(Self {
            shared,
            worker: Some(worker),
            start,
            config: bound.config,
            id,
            utc,
            offered: 0,
        })
    }
    pub(crate) fn offer(&mut self, observation: Observation<'_>) {
        self.offered += 1;
        let record = Record::new(self.offered, self.start, observation);
        self.shared.offered.store(self.offered, Release);
        if self.shared.queue.push(record).is_err() {
            self.shared.dropped.fetch_add(1, Relaxed);
        }
    }
    pub(crate) fn deactivate(&self) {
        self.shared.active.store(false, Release);
    }
    pub(crate) fn stats(&self) -> Stats {
        snapshot(&self.shared, &self.config, &self.id, &self.utc)
    }
    pub(crate) fn finish(mut self) -> Stats {
        self.join()
    }
    fn join(&mut self) -> Stats {
        self.deactivate();
        self.shared.done.store(true, Release);
        let error = self.worker.take().and_then(|w| match w.join() {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(format!("{e:#}")),
            Err(_) => Some("Shared memory worker panicked".into()),
        });
        let mut stats = self.stats();
        stats.worker_error = error;
        stats
    }
}
impl Drop for Hub {
    fn drop(&mut self) {
        if self.worker.is_some() {
            let _ = self.join();
        }
    }
}
fn snapshot(s: &Shared, c: &Config, id: &str, utc: &str) -> Stats {
    Stats {
        mapping: format!("{}.data", c.prefix()),
        mutex: format!("{}.lock", c.prefix()),
        stream_id: id.into(),
        stream_start_utc: utc.into(),
        active: s.active.load(Acquire),
        offered: s.offered.load(Acquire),
        drained: s.drained.load(Relaxed),
        queue_drops: s.dropped.load(Relaxed),
        queue_pending: s.queue.len() as u64,
        coalesced: s.coalesced.load(Relaxed),
        written_events: s.written_events.load(Relaxed),
        unsent_events: s.unsent.load(Relaxed),
        publication_attempts: s.attempts.load(Relaxed),
        writes: s.writes.load(Relaxed),
        lock_misses: s.lock_misses.load(Relaxed),
        abandoned_recoveries: s.abandoned.load(Relaxed),
        shutdown_written: s.shutdown_written.load(Relaxed),
        worker_failed: s.worker_failed.load(Acquire),
        worker_error: None,
    }
}
#[derive(Default)]
struct Latest {
    latest: Option<Record>,
    last_valid: Option<Record>,
    pending: bool,
}
impl Latest {
    fn drain(&mut self, s: &Shared) {
        for _ in 0..s.queue.capacity() {
            let Some(r) = s.queue.pop() else {
                break;
            };
            if self.pending {
                s.coalesced.fetch_add(1, Relaxed);
            }
            if r.valid {
                self.last_valid = Some(r);
            }
            self.latest = Some(r);
            self.pending = true;
            s.unsent.store(1, Relaxed);
            s.drained.fetch_add(1, Relaxed);
        }
    }
}
struct Metadata {
    utc_us: i64,
    generation: u64,
    expected: Option<crate::model::Identity>,
    observed: Option<crate::model::Identity>,
    station: u16,
    position: u16,
    profile_hash: Option<[u8; 32]>,
    backend: String,
    tx_bytes: usize,
    cycle_us: u64,
}
struct Runtime {
    config: Config,
    metadata: Metadata,
    start: Instant,
    id: String,
    mapping: Mapping,
}
impl Runtime {
    fn publish(&mut self, state: &mut Latest, s: &Shared, finishing: bool) -> Result<bool> {
        s.attempts.fetch_add(1, Relaxed);
        let elapsed = self.start.elapsed().as_micros() as u64;
        let mut stats = snapshot(s, &self.config, &self.id, "");
        stats.writes += 1;
        stats.written_events += u64::from(state.pending);
        let frequency = self.mapping.frequency;
        let created = self.mapping.process_created;
        let wrote = self.mapping.write(|qpc, abandoned| {
            stats.abandoned_recoveries += u64::from(abandoned);
            encode(
                &self.metadata,
                &self.config,
                &self.id,
                state,
                &stats,
                Clock {
                    elapsed,
                    qpc,
                    frequency,
                    created,
                },
                finishing,
            )
        })?;
        if wrote {
            s.writes.fetch_add(1, Relaxed);
            if stats.abandoned_recoveries > s.abandoned.load(Relaxed) {
                s.abandoned.fetch_add(1, Relaxed);
            }
            if state.pending {
                s.written_events.fetch_add(1, Relaxed);
                state.pending = false;
                s.unsent.store(0, Relaxed);
            }
        } else {
            s.lock_misses.fetch_add(1, Relaxed);
        }
        Ok(wrote)
    }
    fn serve(mut self, s: &Shared) -> Result<()> {
        let mut state = Latest::default();
        let mut next = Instant::now();
        loop {
            state.drain(s);
            if s.done.load(Acquire) {
                s.shutdown_written
                    .store(self.publish(&mut state, s, true)?, Relaxed);
                return Ok(());
            }
            if Instant::now() >= next {
                self.publish(&mut state, s, false)?;
                next = Instant::now() + Duration::from_millis(self.config.period_ms);
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}
struct Clock {
    elapsed: u64,
    qpc: u64,
    frequency: u64,
    created: u64,
}
fn encode(
    m: &Metadata,
    c: &Config,
    id: &str,
    state: &Latest,
    s: &Stats,
    clock: Clock,
    finishing: bool,
) -> [u8; SIZE] {
    let mut b = [0; SIZE];
    b[..8].copy_from_slice(b"ECWBIN01");
    let u64s = [
        (24, s.publication_attempts),
        (32, m.utc_us as u64),
        (40, m.generation),
        (48, clock.elapsed),
        (56, s.offered),
        (64, state.latest.map_or(0, |r| r.event_index)),
        (72, state.latest.map_or(0, |r| r.cycle_index)),
        (80, state.latest.map_or(0, |r| r.elapsed_us)),
        (88, state.last_valid.map_or(0, |r| r.event_index)),
        (96, state.last_valid.map_or(0, |r| r.cycle_index)),
        (104, state.last_valid.map_or(0, |r| r.elapsed_us)),
        (112, s.queue_drops),
        (120, s.drained),
        (128, s.coalesced),
        (136, s.lock_misses),
        (144, s.written_events),
        (152, s.queue_pending),
        (160, s.writes),
        (248, clock.qpc),
        (256, clock.frequency),
        (336, clock.created),
        (504, s.abandoned_recoveries),
    ];
    for (o, v) in u64s {
        b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }
    let mut flags = u32::from(s.active && !finishing);
    if let Some(r) = state.latest {
        flags |= 2;
        flags |= u32::from(r.valid) * 4;
        flags |= u32::from(r.received) * 16;
        flags |= u32::from(r.actual_wkc.is_some()) * 32;
        flags |= u32::from(r.al.is_some()) * 64;
        for (o, v) in [
            (272, r.expected_wkc),
            (274, r.actual_wkc.unwrap_or(0)),
            (276, r.al.map_or(0, |a| a.0)),
            (278, r.al.map_or(0, |a| a.1)),
        ] {
            b[o..o + 2].copy_from_slice(&v.to_le_bytes());
        }
        let issue = match r.issue {
            None => 0,
            Some(crate::health::InputIssue::Timeout) => 1,
            Some(crate::health::InputIssue::WorkingCounter) => 2,
            Some(crate::health::InputIssue::AlStatus) => 3,
            Some(crate::health::InputIssue::WorkingCounterAndAlStatus) => 4,
            Some(crate::health::InputIssue::TransportError) => 5,
        };
        b[280..284].copy_from_slice(&(issue as u32).to_le_bytes());
        let counts = r.counts;
        for (o, v) in [
            (168, counts.cycles),
            (176, counts.valid),
            (184, counts.timeouts),
            (192, counts.wkc_mismatches),
            (200, counts.al_mismatches),
            (208, counts.transport_errors),
            (216, counts.missed_deadlines),
        ] {
            b[o..o + 8].copy_from_slice(&v.to_le_bytes());
        }
        if let Some(csv) = counts.csv {
            flags |= 2048;
            for (o, v) in [(224, csv.selected), (232, csv.written), (240, csv.overruns)] {
                b[o..o + 8].copy_from_slice(&v.to_le_bytes());
            }
        }
        if r.valid {
            b[HEADER..HEADER + m.tx_bytes].copy_from_slice(&r.data[..m.tx_bytes]);
            b[288..292].copy_from_slice(&(m.tx_bytes as u32).to_le_bytes());
        }
    }
    if let Some(r) = state.last_valid {
        flags |= 8;
        b[HEADER + MAX_PAYLOAD..HEADER + MAX_PAYLOAD + m.tx_bytes]
            .copy_from_slice(&r.data[..m.tx_bytes]);
        b[292..296].copy_from_slice(&(m.tx_bytes as u32).to_le_bytes());
    }
    if let Some(i) = &m.expected {
        flags |= 128;
        for (o, v) in [(296, i.vendor), (300, i.product), (304, i.revision)] {
            b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        }
    }
    if let Some(i) = &m.observed {
        flags |= 1024;
        for (o, v) in [(308, i.vendor), (312, i.product), (316, i.revision)] {
            b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        }
    }
    if input_feed::is_fresh(
        s.active && !finishing,
        s.offered,
        state.latest.as_ref(),
        clock.elapsed,
        c.freshness_ms,
    ) {
        flags |= 256;
    }
    if let Some(hash) = m.profile_hash {
        flags |= 512;
        b[408..440].copy_from_slice(&hash);
    }
    for (o, v) in [
        (8, 1),
        (12, SIZE as u32),
        (16, HEADER as u32),
        (20, MAX_PAYLOAD as u32),
        (264, std::process::id()),
        (268, flags),
        (284, m.tx_bytes as u32),
        (320, m.cycle_us as u32),
        (324, c.freshness_ms as u32),
        (328, c.period_ms as u32),
    ] {
        b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
    b[332..334].copy_from_slice(&m.station.to_le_bytes());
    b[334..336].copy_from_slice(&m.position.to_le_bytes());
    for (offset, text) in [(344, id), (440, m.backend.as_str())] {
        let mut len = text.len().min(63);
        while !text.is_char_boundary(len) {
            len -= 1;
        }
        b[offset..offset + len].copy_from_slice(&text.as_bytes()[..len]);
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{health::InputIssue, input_feed::Counts};
    fn metadata() -> Metadata {
        Metadata {
            utc_us: 123456,
            generation: 9,
            expected: None,
            observed: None,
            station: 1000,
            position: 0,
            profile_hash: Some([0xAB; 32]),
            backend: "Authored fixture".into(),
            tx_bytes: 2,
            cycle_us: 1000,
        }
    }
    fn record(index: u64, valid: bool) -> Record {
        Record {
            event_index: index,
            cycle_index: index + 7,
            elapsed_us: 100 + index,
            received: valid,
            valid,
            expected_wkc: 1,
            actual_wkc: valid.then_some(1),
            al: valid.then_some((4, 0)),
            issue: (!valid).then_some(InputIssue::Timeout),
            counts: Counts {
                cycles: index,
                valid: u64::from(valid),
                ..Default::default()
            },
            data: [0xCD; MAX_PAYLOAD],
        }
    }
    #[test]
    fn binary_layout_keeps_raw_quality_and_historical_data_separate() {
        let state = Latest {
            latest: Some(record(3, false)),
            last_valid: Some(record(2, true)),
            pending: true,
        };
        let stats = Stats {
            active: true,
            offered: 3,
            ..Default::default()
        };
        let bytes = encode(
            &metadata(),
            &Config::default(),
            "fixture-stream",
            &state,
            &stats,
            Clock {
                elapsed: 400,
                qpc: 10000,
                frequency: 1000000,
                created: 456,
            },
            false,
        );
        assert_eq!(&bytes[..8], b"ECWBIN01");
        assert_eq!(
            u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
            SIZE as u32
        );
        assert!(bytes[HEADER..HEADER + MAX_PAYLOAD].iter().all(|b| *b == 0));
        assert_eq!(
            &bytes[HEADER + MAX_PAYLOAD..HEADER + MAX_PAYLOAD + 3],
            &[0xCD, 0xCD, 0]
        );
        assert_eq!(u32::from_le_bytes(bytes[280..284].try_into().unwrap()), 1);
        let flags = u32::from_le_bytes(bytes[268..272].try_into().unwrap());
        assert_ne!(flags & 8, 0);
        assert_eq!(flags & (4 | 16 | 32 | 64 | 256), 0);
        assert_ne!(flags & 512, 0);
        assert_eq!(&bytes[408..440], &[0xAB; 32]);
        assert_eq!(u64::from_le_bytes(bytes[336..344].try_into().unwrap()), 456);
        let mut state = state;
        state.latest = Some(record(4, true));
        let bytes = encode(
            &metadata(),
            &Config::default(),
            "fixture-stream",
            &state,
            &Stats {
                active: true,
                offered: 4,
                ..Default::default()
            },
            Clock {
                elapsed: 400,
                qpc: u64::MAX,
                frequency: 1000000,
                created: 456,
            },
            false,
        );
        assert_eq!(&bytes[HEADER..HEADER + 3], &[0xCD, 0xCD, 0]);
        assert_eq!(
            u64::from_le_bytes(bytes[248..256].try_into().unwrap()),
            u64::MAX
        );
        assert_ne!(
            u32::from_le_bytes(bytes[268..272].try_into().unwrap()) & 256,
            0
        );
        let stopped = encode(
            &metadata(),
            &Config::default(),
            "fixture-stream",
            &state,
            &stats,
            Clock {
                elapsed: 400,
                qpc: 0,
                frequency: 1,
                created: 456,
            },
            true,
        );
        assert_eq!(
            u32::from_le_bytes(stopped[268..272].try_into().unwrap()) & (1 | 256),
            0
        );
    }
    #[test]
    fn queue_overflow_coalescing_and_unwritten_latest_have_distinct_accounting() {
        let s = Shared::new(1);
        let mut state = Latest::default();
        s.offered.store(1, Release);
        s.queue.push(record(1, true)).ok().unwrap();
        s.offered.store(2, Release);
        assert!(s.queue.push(record(2, false)).is_err());
        s.dropped.fetch_add(1, Relaxed);
        state.drain(&s);
        s.offered.store(3, Release);
        s.queue.push(record(3, false)).ok().unwrap();
        state.drain(&s);
        let stats = snapshot(&s, &Config::default(), "id", "utc");
        assert_eq!(
            stats.offered,
            stats.drained + stats.queue_drops + stats.queue_pending
        );
        assert_eq!(
            stats.drained,
            stats.coalesced + stats.written_events + stats.unsent_events
        );
        assert_eq!(stats.unsent_events, 1);
        assert_eq!(state.last_valid.unwrap().event_index, 1);
    }
    #[test]
    fn configuration_and_disabled_profile_serialization_are_bounded() {
        if cfg!(windows) {
            assert!(Config::default().validate().is_ok());
        }
        for name in ["", "has space", "../other", "Global\\x", "a.b", "é"] {
            assert!(
                Config {
                    name: name.into(),
                    ..Default::default()
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            Config {
                queue_capacity: 0,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Config {
                period_ms: 60001,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            serde_json::to_value(Profile::default())
                .unwrap()
                .get("shared_memory")
                .is_none()
        );
        assert!(serde_json::from_str::<Config>(r#"{"global":true}"#).is_err());
    }
}

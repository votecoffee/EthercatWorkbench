//! Opt-in loopback input feed. The cycle offers fixed records; this worker owns all HTTP/JSON.
use crate::{
    health::InputIssue,
    model::{Field, MAX_PAYLOAD, Profile},
    run::Report,
};
use anyhow::{Context, Result, ensure};
use crossbeam_queue::ArrayQueue;
use serde::{Deserialize, Serialize, ser::SerializeMap};
use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
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

const MAX_RESPONSE: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub port: u16,
    pub queue_capacity: usize,
    pub history_capacity: usize,
    pub freshness_ms: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            port: 8766,
            queue_capacity: 4096,
            history_capacity: 1024,
            freshness_ms: 100,
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=8192).contains(&self.queue_capacity),
            "HTTP queue capacity must be 1..8192"
        );
        ensure!(
            (1..=4096).contains(&self.history_capacity),
            "HTTP history capacity must be 1..4096"
        );
        ensure!(
            (1..=60000).contains(&self.freshness_ms),
            "HTTP freshness must be 1..60000 ms"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct CsvCounts {
    pub selected: u64,
    pub written: u64,
    pub overruns: u64,
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Counts {
    pub cycles: u64,
    pub valid: u64,
    pub timeouts: u64,
    pub wkc_mismatches: u64,
    pub al_mismatches: u64,
    pub transport_errors: u64,
    pub missed_deadlines: u64,
    pub csv: Option<CsvCounts>,
}
#[derive(Clone, Copy)]
struct Record {
    event_index: u64,
    elapsed_us: u64,
    cycle_index: u64,
    received: bool,
    valid: bool,
    expected_wkc: u16,
    actual_wkc: Option<u16>,
    al: Option<(u16, u16)>,
    issue: Option<InputIssue>,
    counts: Counts,
    data: [u8; MAX_PAYLOAD],
}
pub(crate) struct Observation<'a> {
    pub cycle_index: u64,
    pub received: Option<Instant>,
    pub observed: Instant,
    pub valid: bool,
    pub expected_wkc: u16,
    pub actual_wkc: Option<u16>,
    pub al: Option<(u16, u16)>,
    pub issue: Option<InputIssue>,
    pub counts: Counts,
    pub data: &'a [u8; MAX_PAYLOAD],
}

struct Shared {
    queue: ArrayQueue<Record>,
    active: AtomicBool,
    done: AtomicBool,
    offered: AtomicU64,
    dropped: AtomicU64,
    dispatched: AtomicU64,
    evicted: AtomicU64,
    requests: AtomicU64,
    rejected: AtomicU64,
    io_errors: AtomicU64,
    worker_failed: AtomicBool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Stats {
    pub address: String,
    pub stream_id: String,
    pub stream_start_utc: String,
    pub active: bool,
    pub offered: u64,
    pub dispatched: u64,
    pub queue_drops: u64,
    pub pending: u64,
    pub history_evictions: u64,
    pub requests: u64,
    pub rejected_requests: u64,
    pub io_errors: u64,
    pub worker_error: Option<String>,
    pub worker_failed: bool,
}
pub(crate) struct Bound {
    listener: TcpListener,
    config: Config,
}
impl Bound {
    pub fn bind(config: &Config) -> Result<Self> {
        config.validate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, config.port))
            .context("bind read-only loopback HTTP feed before bus setup")?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            config: config.clone(),
        })
    }
    pub fn stats(&self) -> Stats {
        Stats {
            address: format!(
                "http://{}",
                self.listener.local_addr().expect("bound listener")
            ),
            ..Stats::default()
        }
    }
}

#[derive(Serialize)]
struct Metadata {
    app_version: String,
    backend: String,
    profile_sha256: Option<String>,
    requested_cycle_us: u64,
    expected_identity: Option<crate::model::Identity>,
    tx_bytes: usize,
    fields: Vec<Field>,
    device_setup_snapshot: Vec<crate::run::DeviceInfo>,
    pdo_verification: Option<Arc<crate::pdo::Verification>>,
    synchronization: Option<crate::sync::Synchronization>,
}

pub(crate) struct Hub {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<Result<()>>>,
    start: Instant,
    address: String,
    stream_id: String,
    utc: String,
    offered: u64,
}
impl Hub {
    pub fn start(bound: Bound, profile: &Profile, report: &Report) -> Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let now = chrono::Utc::now();
        let start = Instant::now();
        let utc = now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
        let stream_id = format!(
            "{}-{}-{}",
            now.timestamp_micros(),
            std::process::id(),
            NEXT.fetch_add(1, Relaxed)
        );
        let address = format!("http://{}", bound.listener.local_addr()?);
        let shared = Arc::new(Shared {
            queue: ArrayQueue::new(bound.config.queue_capacity),
            active: true.into(),
            done: false.into(),
            offered: 0.into(),
            dropped: 0.into(),
            dispatched: 0.into(),
            evicted: 0.into(),
            requests: 0.into(),
            rejected: 0.into(),
            io_errors: 0.into(),
            worker_failed: false.into(),
        });
        let metadata = Metadata {
            app_version: env!("CARGO_PKG_VERSION").into(),
            backend: report.backend.clone(),
            profile_sha256: report.context.as_ref().map(|c| c.profile_sha256.clone()),
            requested_cycle_us: profile.requested_cycle_us,
            expected_identity: profile.expected_identity.clone(),
            tx_bytes: profile.tx_bytes,
            fields: profile.tx.clone(),
            device_setup_snapshot: report.devices.clone(),
            pdo_verification: report.pdo_verification.clone(),
            synchronization: report.synchronization.clone(),
        };
        let shared_worker = shared.clone();
        let id = stream_id.clone();
        let anchor = utc.clone();
        let generation = report.connection_generation;
        let worker = thread::Builder::new()
            .name("http-input-feed".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    serve(
                        bound,
                        metadata,
                        &shared_worker,
                        &id,
                        &anchor,
                        generation,
                        start,
                    )
                }))
                .unwrap_or_else(|_| Err(anyhow::anyhow!("HTTP worker panicked")));
                shared_worker.active.store(false, Release);
                shared_worker.worker_failed.store(result.is_err(), Release);
                result
            })
            .context("start HTTP feed worker")?;
        Ok(Self {
            shared,
            worker: Some(worker),
            start,
            address,
            stream_id,
            utc,
            offered: 0,
        })
    }
    pub fn offer(&mut self, event: Observation<'_>) {
        self.offered += 1;
        let record = Record {
            event_index: self.offered,
            elapsed_us: event
                .received
                .unwrap_or(event.observed)
                .saturating_duration_since(self.start)
                .as_micros() as u64,
            cycle_index: event.cycle_index,
            received: event.received.is_some(),
            valid: event.valid,
            expected_wkc: event.expected_wkc,
            actual_wkc: event.actual_wkc,
            al: event.al,
            issue: event.issue,
            counts: event.counts,
            data: if event.valid {
                *event.data
            } else {
                [0; MAX_PAYLOAD]
            },
        };
        self.shared.offered.store(self.offered, Release);
        if self.shared.queue.push(record).is_err() {
            self.shared.dropped.fetch_add(1, Relaxed);
        }
    }
    pub fn deactivate(&self) {
        self.shared.active.store(false, Release);
    }
    pub fn stats(&self) -> Stats {
        snapshot(&self.shared, &self.address, &self.stream_id, &self.utc)
    }
    pub fn finish(mut self) -> Stats {
        self.join()
    }
    fn join(&mut self) -> Stats {
        self.deactivate();
        self.shared.done.store(true, Release);
        let error = self.worker.take().and_then(|w| match w.join() {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(format!("{e:#}")),
            Err(_) => Some("HTTP worker panicked".into()),
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

fn snapshot(shared: &Shared, address: &str, id: &str, utc: &str) -> Stats {
    Stats {
        address: address.into(),
        stream_id: id.into(),
        stream_start_utc: utc.into(),
        active: shared.active.load(Acquire),
        offered: shared.offered.load(Acquire),
        dispatched: shared.dispatched.load(Relaxed),
        queue_drops: shared.dropped.load(Relaxed),
        pending: shared.queue.len() as u64,
        history_evictions: shared.evicted.load(Relaxed),
        requests: shared.requests.load(Relaxed),
        rejected_requests: shared.rejected.load(Relaxed),
        io_errors: shared.io_errors.load(Relaxed),
        worker_error: None,
        worker_failed: shared.worker_failed.load(Acquire),
    }
}

struct History {
    records: VecDeque<Record>,
    last_valid: Option<Record>,
    capacity: usize,
}
impl History {
    fn drain(&mut self, shared: &Shared) {
        // Bound each drain pass so a fast producer cannot starve request/shutdown handling.
        for _ in 0..shared.queue.capacity() {
            let Some(record) = shared.queue.pop() else {
                break;
            };
            if record.valid {
                self.last_valid = Some(record);
            }
            if self.records.len() == self.capacity {
                self.records.pop_front();
                shared.evicted.fetch_add(1, Relaxed);
            }
            self.records.push_back(record);
            shared.dispatched.fetch_add(1, Relaxed);
        }
    }
}

struct Values<'a> {
    record: &'a Record,
    metadata: &'a Metadata,
}
impl Serialize for Values<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(self.metadata.fields.len()))?;
        for field in &self.metadata.fields {
            map.serialize_entry(
                &field.name,
                &field.decode(&self.record.data[..self.metadata.tx_bytes]),
            )?;
        }
        map.end()
    }
}
#[derive(Serialize)]
struct Sample<'a> {
    event_index: u64,
    cycle_index: u64,
    elapsed_us: u64,
    timestamp_kind: &'static str,
    age_us: u64,
    valid: bool,
    expected_wkc: u16,
    actual_wkc: Option<u16>,
    al_status: Option<u16>,
    al_code: Option<u16>,
    issue: Option<InputIssue>,
    counts: Counts,
    payload_hex: Option<String>,
    values: Option<Values<'a>>,
}
fn sample<'a>(record: &'a Record, metadata: &'a Metadata, now: u64) -> Sample<'a> {
    Sample {
        event_index: record.event_index,
        cycle_index: record.cycle_index,
        elapsed_us: record.elapsed_us,
        timestamp_kind: if record.received {
            "receive"
        } else {
            "failed_attempt_observed"
        },
        age_us: now.saturating_sub(record.elapsed_us),
        valid: record.valid,
        expected_wkc: record.expected_wkc,
        actual_wkc: record.actual_wkc,
        al_status: record.al.map(|v| v.0),
        al_code: record.al.map(|v| v.1),
        issue: record.issue,
        counts: record.counts,
        payload_hex: record
            .valid
            .then(|| hex::encode_upper(&record.data[..metadata.tx_bytes])),
        values: record.valid.then_some(Values { record, metadata }),
    }
}

fn is_fresh(
    active: bool,
    offered: u64,
    latest: Option<&Record>,
    now: u64,
    freshness_ms: u64,
) -> bool {
    active
        && latest.is_some_and(|r| {
            r.valid
                && r.event_index == offered
                && now.saturating_sub(r.elapsed_us) <= freshness_ms * 1000
        })
}

#[derive(Debug, PartialEq, Eq)]
enum Route {
    Status,
    Latest,
    Metadata,
    Samples { after: u64, limit: usize },
}
fn request(bytes: &[u8], authority: &str) -> std::result::Result<Route, u16> {
    let text = std::str::from_utf8(bytes).map_err(|_| 400u16)?;
    let Some(header) = text.strip_suffix("\r\n\r\n") else {
        return Err(400);
    };
    let mut lines = header.split("\r\n");
    let start = lines.next().ok_or(400u16)?.split(' ').collect::<Vec<_>>();
    if start.len() != 3 || start[2] != "HTTP/1.1" {
        return Err(400);
    }
    if start[0] != "GET" {
        return Err(405);
    }
    let mut host = None;
    let mut content_length = false;
    let mut count = 0;
    for line in lines {
        count += 1;
        if count > 32 {
            return Err(431);
        }
        let (name, value) = line.split_once(':').ok_or(400u16)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || !value.bytes().all(|b| b == b'\t' || (32..=126).contains(&b))
        {
            return Err(400);
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("host") {
            if host.replace(value).is_some() {
                return Err(400);
            }
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length || value != "0" {
                return Err(400);
            }
            content_length = true;
        } else if ["transfer-encoding", "expect", "upgrade"]
            .iter()
            .any(|v| name.eq_ignore_ascii_case(v))
        {
            return Err(400);
        }
    }
    let localhost = authority.replacen("127.0.0.1", "localhost", 1);
    if host != Some(authority) && host != Some(localhost.as_str()) {
        return Err(400);
    }
    match start[1] {
        "/v1/status" => Ok(Route::Status),
        "/v1/latest" => Ok(Route::Latest),
        "/v1/metadata" => Ok(Route::Metadata),
        path if path == "/v1/samples" || path.starts_with("/v1/samples?") => {
            let mut after = None;
            let mut limit = None;
            if let Some((_, query)) = path.split_once('?') {
                for item in query.split('&') {
                    let (key, value) = item.split_once('=').ok_or(400u16)?;
                    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(400);
                    }
                    match key {
                        "after" if after.is_none() => {
                            after = Some(value.parse::<u64>().map_err(|_| 400u16)?)
                        }
                        "limit" if limit.is_none() => {
                            limit = Some(value.parse::<usize>().map_err(|_| 400u16)?)
                        }
                        _ => return Err(400),
                    }
                }
            }
            let limit = limit.unwrap_or(16);
            if !(1..=64).contains(&limit) {
                return Err(400);
            }
            Ok(Route::Samples {
                after: after.unwrap_or(0),
                limit,
            })
        }
        _ => Err(404),
    }
}

struct Limited(Vec<u8>);
impl Write for Limited {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_RESPONSE - self.0.len() {
            return Err(io::Error::other(
                "HTTP response exceeds 2 MiB; request fewer samples",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn json(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut out = Limited(Vec::new());
    serde_json::to_writer(&mut out, value)?;
    Ok(out.0)
}

fn read_request(socket: &mut TcpStream, shared: &Shared) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_millis(25);
    let mut bytes = vec![0; 4096];
    let mut len = 0;
    loop {
        if shared.done.load(Acquire) || Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP header deadline",
            ));
        }
        match socket.read(&mut bytes[len..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete HTTP header",
                ));
            }
            Ok(n) => {
                len += n;
                if let Some(end) = bytes[..len].windows(4).position(|v| v == b"\r\n\r\n") {
                    if end + 4 != len {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "HTTP bodies/pipelining unsupported",
                        ));
                    }
                    bytes.truncate(len);
                    return Ok(bytes);
                }
                if len == bytes.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HTTP header exceeds 4096 bytes",
                    ));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1))
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}
fn respond(socket: &mut TcpStream, code: u16, body: &[u8], shared: &Shared) -> io::Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        _ => "Service Unavailable",
    };
    let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT");
    let header = format!(
        "HTTP/1.1 {code} {reason}\r\nDate: {date}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nAllow: GET\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        body.len()
    );
    let deadline = Instant::now() + Duration::from_millis(25);
    for bytes in [header.as_bytes(), body] {
        let mut sent = 0;
        while sent < bytes.len() {
            if shared.done.load(Acquire) || Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTP response deadline",
                ));
            }
            match socket.write(&bytes[sent..]) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "HTTP peer closed")),
                Ok(n) => sent += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

fn serve(
    bound: Bound,
    metadata: Metadata,
    shared: &Shared,
    id: &str,
    utc: &str,
    generation: u64,
    start: Instant,
) -> Result<()> {
    let authority = bound.listener.local_addr()?.to_string();
    let address = format!("http://{authority}");
    let mut history = History {
        records: VecDeque::with_capacity(bound.config.history_capacity),
        last_valid: None,
        capacity: bound.config.history_capacity,
    };
    loop {
        history.drain(shared);
        if shared.done.load(Acquire) && shared.queue.is_empty() {
            return Ok(());
        }
        let mut socket = match bound.listener.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        shared.requests.fetch_add(1, Relaxed);
        socket.set_nonblocking(true)?;
        let input = match read_request(&mut socket, shared) {
            Ok(input) => input,
            Err(_) => {
                shared.io_errors.fetch_add(1, Relaxed);
                continue;
            }
        };
        history.drain(shared);
        let route = request(&input, &authority);
        let now = start.elapsed().as_micros() as u64;
        let stats = snapshot(shared, &address, id, utc);
        let latest = history.records.back();
        let fresh = is_fresh(
            stats.active,
            stats.offered,
            latest,
            now,
            bound.config.freshness_ms,
        );
        #[derive(Serialize)]
        struct Envelope<'a, T: Serialize> {
            schema: u32,
            stream_id: &'a str,
            stream_start_utc: &'a str,
            connection_generation: u64,
            response_elapsed_us: u64,
            active: bool,
            fresh: bool,
            data: T,
        }
        macro_rules! encode {
            ($data:expr) => {
                json(&Envelope {
                    schema: 1,
                    stream_id: id,
                    stream_start_utc: utc,
                    connection_generation: generation,
                    response_elapsed_us: now,
                    active: stats.active,
                    fresh,
                    data: $data,
                })
            };
        }
        let oldest = history.records.front().map(|r| r.event_index);
        let (mut code, result) = match route {
            Ok(Route::Metadata) => (200, encode!(&metadata)),
            Ok(Route::Status) => (
                200,
                encode!(
                    serde_json::json!({"feed":stats,"oldest_event_index":oldest,"latest_event_index":latest.map(|r|r.event_index),
                "history_len":history.records.len(),"queue_capacity":bound.config.queue_capacity,"history_capacity":bound.config.history_capacity,
                "freshness_ms":bound.config.freshness_ms,"acquisition":latest.map(|r|r.counts)})
                ),
            ),
            Ok(Route::Latest) => {
                #[derive(Serialize)]
                struct Latest<'a> {
                    latest: Option<Sample<'a>>,
                    last_valid: Option<Sample<'a>>,
                }
                (
                    200,
                    encode!(Latest {
                        latest: latest.map(|r| sample(r, &metadata, now)),
                        last_valid: history
                            .last_valid
                            .as_ref()
                            .map(|r| sample(r, &metadata, now))
                    }),
                )
            }
            Ok(Route::Samples { after, limit }) if after <= stats.offered => {
                #[derive(Serialize)]
                struct Samples<'a> {
                    oldest_event_index: Option<u64>,
                    newest_event_index: Option<u64>,
                    producer_event_index: u64,
                    next_after: u64,
                    samples: Vec<Sample<'a>>,
                }
                let samples = history
                    .records
                    .iter()
                    .filter(|r| r.event_index > after)
                    .take(limit)
                    .map(|r| sample(r, &metadata, now))
                    .collect::<Vec<_>>();
                let next_after = samples.last().map_or(after, |r| r.event_index);
                (
                    200,
                    encode!(Samples {
                        oldest_event_index: oldest,
                        newest_event_index: latest.map(|r| r.event_index),
                        producer_event_index: stats.offered,
                        next_after,
                        samples
                    }),
                )
            }
            Ok(Route::Samples { .. }) => (
                400,
                encode!(
                    serde_json::json!({"error":"cursor exceeds this stream; reset after when stream_id changes"})
                ),
            ),
            Err(code) => (
                code,
                encode!(
                    serde_json::json!({"error":"unsupported or malformed read-only HTTP request"})
                ),
            ),
        };
        let body = match result {
            Ok(body) => body,
            Err(_) => {
                code = 503;
                encode!(
                    serde_json::json!({"error":"response exceeds bound; request fewer samples"})
                )?
            }
        };
        if code != 200 {
            shared.rejected.fetch_add(1, Relaxed);
        }
        if respond(&mut socket, code, &body, shared).is_err() {
            shared.io_errors.fetch_add(1, Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> Profile {
        Profile {
            tx_bytes: 1,
            tx: vec![Field {
                name: "Input".into(),
                width: 8,
                log: false,
                ..Field::default()
            }],
            ..Profile::default()
        }
    }
    fn metadata() -> Metadata {
        Metadata {
            app_version: env!("CARGO_PKG_VERSION").into(),
            backend: "Authored fixture".into(),
            profile_sha256: None,
            requested_cycle_us: 1000,
            expected_identity: None,
            tx_bytes: 1,
            fields: profile().tx,
            device_setup_snapshot: vec![],
            pdo_verification: None,
            synchronization: None,
        }
    }
    fn hub() -> Hub {
        let bound = Bound::bind(&Config {
            port: 0,
            freshness_ms: 10000,
            ..Config::default()
        })
        .unwrap();
        let report = Report {
            backend: "Authored fixture".into(),
            connection_generation: 3,
            ..Report::default()
        };
        Hub::start(bound, &profile(), &report).unwrap()
    }
    fn offer(hub: &mut Hub, valid: bool) {
        let now = Instant::now();
        let index = hub.offered + 1;
        hub.offer(Observation {
            cycle_index: index,
            received: valid.then_some(now),
            observed: now,
            valid,
            expected_wkc: 1,
            actual_wkc: valid.then_some(1),
            al: valid.then_some((4, 0)),
            issue: (!valid).then_some(InputIssue::Timeout),
            counts: Counts {
                cycles: index,
                valid: u64::from(valid),
                ..Counts::default()
            },
            data: &[7; MAX_PAYLOAD],
        });
    }
    fn wait_for(mut ready: impl FnMut() -> bool) {
        let end = Instant::now() + Duration::from_secs(3);
        while !ready() {
            assert!(Instant::now() < end, "HTTP worker test timed out");
            thread::sleep(Duration::from_millis(1));
        }
    }
    fn get(hub: &Hub, target: &str) -> (u16, serde_json::Value) {
        let authority = hub.address.strip_prefix("http://").unwrap();
        let mut socket = TcpStream::connect(authority).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        write!(socket, "GET {target} HTTP/1.1\r\nHost: {authority}\r\n\r\n").unwrap();
        let mut bytes = Vec::new();
        socket.read_to_end(&mut bytes).unwrap();
        let end = bytes.windows(4).position(|b| b == b"\r\n\r\n").unwrap();
        let header = std::str::from_utf8(&bytes[..end]).unwrap();
        assert!(header.contains("Connection: close") && header.contains("Cache-Control: no-store"));
        let code = header.split(' ').nth(1).unwrap().parse().unwrap();
        (code, serde_json::from_slice(&bytes[end + 4..]).unwrap())
    }

    #[test]
    fn real_loopback_feed_separates_invalid_latest_last_good_and_stopped_state() {
        let mut hub = hub();
        offer(&mut hub, true);
        wait_for(|| hub.stats().dispatched == 1);
        let (code, latest) = get(&hub, "/v1/latest");
        assert_eq!(code, 200);
        assert_eq!(latest["fresh"], true);
        assert_eq!(latest["connection_generation"], 3);
        assert_eq!(latest["data"]["latest"]["payload_hex"], "07");
        assert_eq!(latest["data"]["latest"]["values"]["Input"], "7"); // log=false still exported
        offer(&mut hub, false);
        wait_for(|| hub.stats().dispatched == 2);
        let (_, latest) = get(&hub, "/v1/latest");
        assert_eq!(latest["fresh"], false);
        assert!(
            latest["data"]["latest"]["payload_hex"].is_null()
                && latest["data"]["latest"]["values"].is_null()
        );
        assert_eq!(latest["data"]["latest"]["issue"], "timeout");
        assert_eq!(latest["data"]["last_valid"]["event_index"], 1);
        let (_, history) = get(&hub, "/v1/samples?after=0&limit=64");
        assert_eq!(history["data"]["samples"].as_array().unwrap().len(), 2);
        assert_eq!(history["data"]["next_after"], 2);
        assert_eq!(get(&hub, "/v1/samples?after=3").0, 400);
        let (_, meta) = get(&hub, "/v1/metadata");
        assert_eq!(meta["data"]["backend"], "Authored fixture");
        hub.deactivate();
        let (_, status) = get(&hub, "/v1/status");
        assert_eq!(status["active"], false);
        assert_eq!(status["fresh"], false);
        let address = hub.address.clone();
        let stats = hub.finish();
        assert_eq!(stats.offered, 2);
        assert_eq!(stats.dispatched, 2);
        assert_eq!(stats.pending, 0);
        assert!(TcpStream::connect(address.strip_prefix("http://").unwrap()).is_err());
    }

    #[test]
    fn queue_drop_and_history_eviction_have_independent_visible_counters() {
        let shared = Arc::new(Shared {
            queue: ArrayQueue::new(1),
            active: true.into(),
            done: false.into(),
            offered: 0.into(),
            dropped: 0.into(),
            dispatched: 0.into(),
            evicted: 0.into(),
            requests: 0.into(),
            rejected: 0.into(),
            io_errors: 0.into(),
            worker_failed: false.into(),
        });
        let mut hub = Hub {
            shared,
            worker: None,
            start: Instant::now(),
            address: "unused".into(),
            stream_id: "authored".into(),
            utc: "authored".into(),
            offered: 0,
        };
        let mut history = History {
            records: VecDeque::new(),
            last_valid: None,
            capacity: 1,
        };
        offer(&mut hub, true);
        offer(&mut hub, false);
        history.drain(&hub.shared);
        assert_eq!(hub.stats().queue_drops, 1);
        assert_eq!(hub.stats().history_evictions, 0);
        assert!(!is_fresh(true, 2, history.records.back(), 100, 1000)); // dropped invalid event invalidates old valid view
        offer(&mut hub, false);
        history.drain(&hub.shared);
        assert_eq!(hub.stats().history_evictions, 1);
        assert_eq!(history.records[0].event_index, 3);
        assert!(history.records[0].data.iter().all(|b| *b == 0));
        assert_eq!(history.last_valid.unwrap().event_index, 1);
        let stats = hub.finish();
        assert_eq!(
            stats.offered,
            stats.dispatched + stats.queue_drops + stats.pending
        );
    }

    #[test]
    fn request_subset_rejects_mutation_bodies_duplicate_headers_and_bad_cursors() {
        let authority = "127.0.0.1:8766";
        let parse = |line: &str, headers: &str| {
            request(
                format!("{line}\r\nHost: {authority}\r\n{headers}\r\n").as_bytes(),
                authority,
            )
        };
        assert_eq!(
            parse("GET /v1/samples?after=2&limit=64 HTTP/1.1", ""),
            Ok(Route::Samples {
                after: 2,
                limit: 64
            })
        );
        assert_eq!(parse("POST /v1/latest HTTP/1.1", ""), Err(405));
        for header in [
            "Host: localhost:8766\r\n",
            "Content-Length: 1\r\n",
            "Transfer-Encoding: chunked\r\n",
            " folded: x\r\n",
            "Expect: 100-continue\r\n",
        ] {
            assert_eq!(parse("GET /v1/latest HTTP/1.1", header), Err(400));
        }
        for target in [
            "/v1/samples?limit=0",
            "/v1/samples?limit=65",
            "/v1/samples?after=-1",
            "/v1/samples?after=0&after=1",
            "/v1/samples?foo=1",
        ] {
            assert_eq!(parse(&format!("GET {target} HTTP/1.1"), ""), Err(400));
        }
        assert_eq!(
            request(
                b"GET /v1/status HTTP/1.1\r\nHost: other.example\r\n\r\n",
                authority
            ),
            Err(400)
        );
        assert_eq!(parse("GET /op HTTP/1.1", ""), Err(404));
    }

    #[test]
    fn freshness_requires_active_current_valid_and_recent_data() {
        let record = Record {
            event_index: 4,
            elapsed_us: 10,
            cycle_index: 4,
            received: true,
            valid: true,
            expected_wkc: 1,
            actual_wkc: Some(1),
            al: Some((4, 0)),
            issue: None,
            counts: Counts::default(),
            data: [0; MAX_PAYLOAD],
        };
        assert!(is_fresh(true, 4, Some(&record), 100, 1));
        assert!(!is_fresh(false, 4, Some(&record), 100, 1));
        assert!(!is_fresh(true, 5, Some(&record), 100, 1));
        assert!(!is_fresh(true, 4, Some(&record), 1011, 1));
        assert!(!is_fresh(true, 4, None, 0, 1));
    }

    #[test]
    fn response_bound_and_wide_typed_values_do_not_use_json_floats() {
        let mut output = Limited(Vec::new());
        assert!(output.write(&vec![0; MAX_RESPONSE + 1]).is_err());
        assert!(output.0.is_empty());
        let mut metadata = metadata();
        metadata.tx_bytes = 8;
        metadata.fields[0].width = 64;
        let record = Record {
            event_index: 1,
            elapsed_us: 0,
            cycle_index: 1,
            received: true,
            valid: true,
            expected_wkc: 1,
            actual_wkc: Some(1),
            al: Some((4, 0)),
            issue: None,
            counts: Counts::default(),
            data: [255; MAX_PAYLOAD],
        };
        let value = serde_json::to_value(sample(&record, &metadata, 1)).unwrap();
        assert_eq!(value["values"]["Input"], "18446744073709551615");
    }

    #[test]
    fn incomplete_client_cannot_block_offer_or_shutdown() {
        let mut hub = hub();
        let mut socket = TcpStream::connect(hub.address.strip_prefix("http://").unwrap()).unwrap();
        socket.write_all(b"GET /v1/status HTTP/1.1\r\n").unwrap();
        wait_for(|| hub.stats().requests > 0);
        for _ in 0..100 {
            offer(&mut hub, true);
        }
        assert_eq!(hub.stats().offered, 100);
        let start = Instant::now();
        let stats = hub.finish();
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(
            stats.offered,
            stats.dispatched + stats.queue_drops + stats.pending
        );
    }

    #[test]
    fn config_is_bounded_and_legacy_profiles_omit_disabled_http() {
        for config in [
            Config {
                queue_capacity: 0,
                ..Config::default()
            },
            Config {
                history_capacity: 4097,
                ..Config::default()
            },
            Config {
                freshness_ms: 0,
                ..Config::default()
            },
        ] {
            assert!(config.validate().is_err());
        }
        let value = serde_json::to_value(Profile::default()).unwrap();
        assert!(value.get("http").is_none());
        let disabled: Profile = serde_json::from_value(value).unwrap();
        assert!(disabled.http.is_none());
    }
}

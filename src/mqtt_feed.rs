//! Publish-only MQTT 3.1.1, QoS 0, clean sessions, non-retained, IPv4 loopback only.
//! No socket, JSON, allocation or consumer wait occurs in `Hub::offer`.
use crate::{
    input_feed::{self, Metadata, Observation, Record, is_fresh, json, sample},
    model::Profile,
    run::Report,
};
use anyhow::{Context, Result, bail, ensure};
use crossbeam_queue::ArrayQueue;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{
            AtomicBool, AtomicU64,
            Ordering::{Acquire, Relaxed, Release},
        },
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub port: u16,
    pub topic: String,
    pub queue_capacity: usize,
    pub period_ms: u64,
    pub freshness_ms: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            port: 1883,
            topic: "ethercat/workbench/input".into(),
            queue_capacity: 4096,
            period_ms: 20,
            freshness_ms: 100,
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.port != 0, "MQTT broker port must be 1..65535");
        ensure!(
            (1..=512).contains(&self.topic.len())
                && self
                    .topic
                    .bytes()
                    .all(|c| (33..=126).contains(&c) && c != b'+' && c != b'#')
                && !self.topic.starts_with('$'),
            "MQTT topic must be 1..512 printable ASCII bytes, without whitespace, wildcards or a leading $"
        );
        ensure!(
            (1..=8192).contains(&self.queue_capacity),
            "MQTT queue capacity must be 1..8192"
        );
        ensure!(
            (1..=60000).contains(&self.period_ms),
            "MQTT period must be 1..60000 ms"
        );
        ensure!(
            (1..=60000).contains(&self.freshness_ms),
            "MQTT freshness must be 1..60000 ms"
        );
        Ok(())
    }
}

struct Shared {
    queue: ArrayQueue<Record>,
    active: AtomicBool,
    done: AtomicBool,
    connected: AtomicBool,
    worker_failed: AtomicBool,
    offered: AtomicU64,
    drained: AtomicU64,
    dropped: AtomicU64,
    coalesced: AtomicU64,
    attempted_events: AtomicU64,
    unsent_events: AtomicU64,
    connect_attempts: AtomicU64,
    connections: AtomicU64,
    connect_errors: AtomicU64,
    publish_attempts: AtomicU64,
    write_completions: AtomicU64,
    publish_errors: AtomicU64,
    errors: AtomicU64,
    shutdown_written: AtomicBool,
    disconnect_written: AtomicBool,
    last_error: Mutex<Option<String>>,
}
impl Shared {
    fn new(capacity: usize) -> Self {
        Self {
            queue: ArrayQueue::new(capacity),
            active: true.into(),
            done: false.into(),
            connected: false.into(),
            worker_failed: false.into(),
            offered: 0.into(),
            drained: 0.into(),
            dropped: 0.into(),
            coalesced: 0.into(),
            attempted_events: 0.into(),
            unsent_events: 0.into(),
            connect_attempts: 0.into(),
            connections: 0.into(),
            connect_errors: 0.into(),
            publish_attempts: 0.into(),
            write_completions: 0.into(),
            publish_errors: 0.into(),
            errors: 0.into(),
            shutdown_written: false.into(),
            disconnect_written: false.into(),
            last_error: Mutex::new(None),
        }
    }
    fn error(&self, error: anyhow::Error) {
        self.errors.fetch_add(1, Relaxed);
        if let Ok(mut last) = self.last_error.lock() {
            *last = Some(format!("{error:#}").chars().take(512).collect());
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Stats {
    pub address: String,
    pub topic: String,
    pub client_id: String,
    pub stream_id: String,
    pub stream_start_utc: String,
    pub active: bool,
    pub connected: bool,
    pub offered: u64,
    pub drained: u64,
    pub queue_drops: u64,
    pub queue_pending: u64,
    pub coalesced: u64,
    pub attempted_events: u64,
    pub unsent_events: u64,
    pub connect_attempts: u64,
    pub connections: u64,
    pub connect_errors: u64,
    pub publish_attempts: u64,
    pub write_completions: u64,
    pub publish_errors: u64,
    pub errors: u64,
    pub shutdown_written: bool,
    pub disconnect_written: bool,
    pub last_error: Option<String>,
    pub worker_failed: bool,
    pub worker_error: Option<String>,
}

pub(crate) struct Hub {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<Result<()>>>,
    start: Instant,
    config: Config,
    id: String,
    utc: String,
    client_id: String,
    offered: u64,
}
impl Hub {
    pub(crate) fn start(config: &Config, profile: &Profile, report: &Report) -> Result<Self> {
        config.validate()?;
        let (start, utc, id) = input_feed::anchor();
        // 23 ASCII alphanumeric bytes accepted by MQTT 3.1.1 servers. Derive from
        // UTC/process/run identity; reconnect retains this ID with a clean session.
        let client_id = format!("ecw{}", &hex::encode(Sha256::digest(id.as_bytes()))[..20]);
        let shared = Arc::new(Shared::new(config.queue_capacity));
        let runtime = Runtime {
            config: config.clone(),
            metadata: Metadata::new(profile, report),
            start,
            id: id.clone(),
            utc: utc.clone(),
            client_id: client_id.clone(),
            generation: report.connection_generation,
        };
        let worker_shared = shared.clone();
        let worker = thread::Builder::new()
            .name("mqtt-input-feed".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    runtime.serve(&worker_shared)
                }))
                .unwrap_or_else(|_| Err(anyhow::anyhow!("MQTT worker panicked")));
                worker_shared.active.store(false, Release);
                worker_shared.connected.store(false, Release);
                worker_shared.worker_failed.store(result.is_err(), Release);
                result
            })
            .context("start MQTT input worker")?;
        Ok(Self {
            shared,
            worker: Some(worker),
            start,
            config: config.clone(),
            id,
            utc,
            client_id,
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
        snapshot(
            &self.shared,
            &self.config,
            &self.id,
            &self.utc,
            &self.client_id,
        )
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
            Err(_) => Some("MQTT worker panicked".into()),
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
fn snapshot(s: &Shared, c: &Config, id: &str, utc: &str, client_id: &str) -> Stats {
    Stats {
        address: format!("127.0.0.1:{}", c.port),
        topic: c.topic.clone(),
        client_id: client_id.into(),
        stream_id: id.into(),
        stream_start_utc: utc.into(),
        active: s.active.load(Acquire),
        connected: s.connected.load(Acquire),
        offered: s.offered.load(Acquire),
        drained: s.drained.load(Relaxed),
        queue_drops: s.dropped.load(Relaxed),
        queue_pending: s.queue.len() as u64,
        coalesced: s.coalesced.load(Relaxed),
        attempted_events: s.attempted_events.load(Relaxed),
        unsent_events: s.unsent_events.load(Relaxed),
        connect_attempts: s.connect_attempts.load(Relaxed),
        connections: s.connections.load(Relaxed),
        connect_errors: s.connect_errors.load(Relaxed),
        publish_attempts: s.publish_attempts.load(Relaxed),
        write_completions: s.write_completions.load(Relaxed),
        publish_errors: s.publish_errors.load(Relaxed),
        errors: s.errors.load(Relaxed),
        shutdown_written: s.shutdown_written.load(Relaxed),
        disconnect_written: s.disconnect_written.load(Relaxed),
        last_error: s.last_error.try_lock().ok().and_then(|e| e.clone()),
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
    fn drain(&mut self, shared: &Shared) {
        for _ in 0..shared.queue.capacity() {
            let Some(record) = shared.queue.pop() else {
                break;
            };
            if self.pending {
                shared.coalesced.fetch_add(1, Relaxed);
            }
            if record.valid {
                self.last_valid = Some(record);
            }
            self.latest = Some(record);
            self.pending = true;
            shared.unsent_events.store(1, Relaxed);
            shared.drained.fetch_add(1, Relaxed);
        }
    }
    fn attempt(&mut self, shared: &Shared) {
        if self.pending {
            shared.attempted_events.fetch_add(1, Relaxed);
            self.pending = false;
            shared.unsent_events.store(0, Relaxed);
        }
    }
}
struct Runtime {
    config: Config,
    metadata: Metadata,
    start: Instant,
    id: String,
    utc: String,
    client_id: String,
    generation: u64,
}
impl Runtime {
    fn payload(&self, state: &Latest, shared: &Shared, finishing: bool) -> Result<Vec<u8>> {
        let now = self.start.elapsed().as_micros() as u64;
        let active = shared.active.load(Acquire) && !finishing;
        #[derive(Serialize)]
        struct Envelope<'a> {
            schema: u32,
            kind: &'static str,
            stream_id: &'a str,
            stream_start_utc: &'a str,
            connection_generation: u64,
            broker_attempt: u64,
            publication_index: u64,
            response_elapsed_us: u64,
            active: bool,
            fresh: bool,
            latest: Option<input_feed::Sample<'a>>,
            last_valid: Option<input_feed::Sample<'a>>,
            metadata: &'a Metadata,
            feed: Stats,
        }
        json(&Envelope {
            schema: 1,
            kind: "input",
            stream_id: &self.id,
            stream_start_utc: &self.utc,
            connection_generation: self.generation,
            broker_attempt: shared.connect_attempts.load(Relaxed),
            publication_index: shared.publish_attempts.load(Relaxed),
            response_elapsed_us: now,
            active,
            fresh: is_fresh(
                active,
                shared.offered.load(Acquire),
                state.latest.as_ref(),
                now,
                self.config.freshness_ms,
            ),
            latest: state
                .latest
                .as_ref()
                .map(|r| sample(r, &self.metadata, now)),
            last_valid: state
                .last_valid
                .as_ref()
                .map(|r| sample(r, &self.metadata, now)),
            metadata: &self.metadata,
            feed: snapshot(shared, &self.config, &self.id, &self.utc, &self.client_id),
        })
    }
    fn publish(
        &self,
        connection: &mut Connection,
        state: &mut Latest,
        shared: &Shared,
        finishing: bool,
    ) -> Result<()> {
        state.attempt(shared);
        shared.publish_attempts.fetch_add(1, Relaxed);
        let result = (|| {
            let payload = self.payload(state, shared, finishing)?;
            let packet = publish_packet(&self.config.topic, &payload)?;
            write_all(
                &mut connection.socket,
                &packet,
                (!finishing).then_some(&shared.done),
            )?;
            connection.last_send = Instant::now();
            shared.write_completions.fetch_add(1, Relaxed);
            Ok(())
        })();
        if result.is_err() {
            shared.publish_errors.fetch_add(1, Relaxed);
        }
        result
    }
    fn serve(self, shared: &Shared) -> Result<()> {
        let mut state = Latest::default();
        let mut connection: Option<Connection> = None;
        let mut retry_at = Instant::now();
        let mut backoff = Duration::from_millis(100);
        let mut next_publish = Instant::now();
        loop {
            state.drain(shared);
            if shared.done.load(Acquire) {
                if let Some(mut c) = connection.take() {
                    match self.publish(&mut c, &mut state, shared, true) {
                        Ok(()) => {
                            shared.shutdown_written.store(true, Relaxed);
                            match write_all(&mut c.socket, &[0xe0, 0], None) {
                                Ok(()) => shared.disconnect_written.store(true, Relaxed),
                                Err(e) => shared.error(e.into()),
                            }
                        }
                        Err(e) => shared.error(e),
                    }
                }
                return Ok(());
            }
            if connection.is_none() && Instant::now() >= retry_at {
                shared.connect_attempts.fetch_add(1, Relaxed);
                match Connection::connect(&self, shared) {
                    Ok(c) => {
                        connection = Some(c);
                        shared.connected.store(true, Release);
                        shared.connections.fetch_add(1, Relaxed);
                        backoff = Duration::from_millis(100);
                        next_publish = Instant::now();
                    }
                    Err(e) => {
                        if shared.done.load(Acquire) {
                            continue;
                        }
                        shared.connect_errors.fetch_add(1, Relaxed);
                        shared.error(e);
                        retry_at = Instant::now() + backoff;
                        backoff = (backoff * 2).min(Duration::from_secs(5));
                    }
                }
            }
            if let Some(c) = connection.as_mut() {
                let result = (|| {
                    c.poll()?;
                    if Instant::now() >= next_publish {
                        self.publish(c, &mut state, shared, false)?;
                        next_publish =
                            Instant::now() + Duration::from_millis(self.config.period_ms);
                    }
                    c.keepalive(&shared.done)?;
                    Ok::<_, anyhow::Error>(())
                })();
                if let Err(error) = result {
                    connection = None;
                    shared.connected.store(false, Release);
                    if !shared.done.load(Acquire) {
                        shared.error(error);
                    }
                    retry_at = Instant::now() + backoff;
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}

fn utf8(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let len = u16::try_from(value.len()).context("MQTT string exceeds 65535 bytes")?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}
fn packet(kind: u8, body: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        body.len() <= input_feed::MAX_RESPONSE + 1024,
        "MQTT packet exceeds bound"
    );
    let mut packet = Vec::with_capacity(body.len() + 5);
    packet.push(kind);
    let mut remaining = body.len();
    loop {
        let digit = (remaining % 128) as u8;
        remaining /= 128;
        packet.push(digit | if remaining > 0 { 128 } else { 0 });
        if remaining == 0 {
            break;
        }
    }
    packet.extend_from_slice(body);
    Ok(packet)
}
fn publish_packet(topic: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let mut body = Vec::with_capacity(topic.len() + payload.len() + 2);
    utf8(&mut body, topic.as_bytes())?;
    body.extend_from_slice(payload);
    packet(0x30, &body)
}
fn connect_packet(client_id: &str, topic: &str, will: &[u8]) -> Result<Vec<u8>> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, 6, 0, 10];
    utf8(&mut body, client_id.as_bytes())?;
    utf8(&mut body, topic.as_bytes())?;
    utf8(&mut body, will)?;
    packet(0x10, &body)
}
fn write_all(socket: &mut TcpStream, bytes: &[u8], stop: Option<&AtomicBool>) -> io::Result<()> {
    let end = Instant::now() + Duration::from_millis(25);
    let mut written = 0;
    while written < bytes.len() {
        if Instant::now() >= end || stop.is_some_and(|s| s.load(Acquire)) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "MQTT write deadline/stop",
            ));
        }
        match socket.write(&bytes[written..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "MQTT peer closed")),
            Ok(n) => written += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1))
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
struct Connection {
    socket: TcpStream,
    last_send: Instant,
    ping: Option<Instant>,
    response: [u8; 2],
    received: usize,
}
impl Connection {
    fn connect(runtime: &Runtime, shared: &Shared) -> Result<Self> {
        let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, runtime.config.port));
        let mut socket = TcpStream::connect_timeout(&address, Duration::from_millis(100))
            .context("MQTT loopback connect")?;
        socket.set_nonblocking(true)?;
        socket.set_nodelay(true)?;
        let will = json(
            &serde_json::json!({"schema":1,"kind":"unavailable","stream_id":runtime.id,"connection_generation":runtime.generation,"broker_attempt":shared.connect_attempts.load(Relaxed),"active":false,"fresh":false,"reason":"publisher_connection_lost"}),
        )?;
        write_all(
            &mut socket,
            &connect_packet(&runtime.client_id, &runtime.config.topic, &will)?,
            Some(&shared.done),
        )?;
        let end = Instant::now() + Duration::from_millis(100);
        let mut response = [0; 4];
        let mut received = 0;
        while received < 4 {
            ensure!(
                !shared.done.load(Acquire) && Instant::now() < end,
                "MQTT CONNACK deadline/stop"
            );
            match socket.read(&mut response[received..]) {
                Ok(0) => bail!("MQTT broker closed before CONNACK"),
                Ok(n) => received += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        ensure!(
            response == [0x20, 2, 0, 0],
            "MQTT CONNACK rejected/malformed: {response:02X?}"
        );
        Ok(Self {
            socket,
            last_send: Instant::now(),
            ping: None,
            response: [0; 2],
            received: 0,
        })
    }
    fn poll(&mut self) -> Result<()> {
        match self.socket.read(&mut self.response[self.received..]) {
            Ok(0) => bail!("MQTT broker disconnected"),
            Ok(n) => {
                ensure!(
                    self.ping.is_some(),
                    "unexpected MQTT server packet (no subscriptions)"
                );
                self.received += n;
                if self.received == 2 {
                    ensure!(self.response == [0xd0, 0], "malformed MQTT PINGRESP");
                    self.received = 0;
                    self.ping = None;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e.into()),
        }
        ensure!(
            !self
                .ping
                .is_some_and(|at| at.elapsed() >= Duration::from_millis(100)),
            "MQTT PINGRESP deadline"
        );
        Ok(())
    }
    fn keepalive(&mut self, stop: &AtomicBool) -> Result<()> {
        if self.ping.is_none() && self.last_send.elapsed() >= Duration::from_secs(2) {
            write_all(&mut self.socket, &[0xc0, 0], Some(stop))?;
            self.last_send = Instant::now();
            self.ping = Some(self.last_send);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        health::InputIssue,
        input_feed::Counts,
        model::{Field, MAX_PAYLOAD},
    };
    use std::net::TcpListener;

    fn runtime(config: Config) -> Runtime {
        let profile = Profile {
            tx_bytes: 1,
            tx: vec![Field {
                name: "Byte".into(),
                width: 8,
                log: false,
                ..Default::default()
            }],
            staged_rx_hex: "AB".into(),
            ..Default::default()
        };
        let (start, utc, id) = input_feed::anchor();
        Runtime {
            config,
            metadata: Metadata::new(&profile, &Report::default()),
            start,
            id,
            utc,
            client_id: "ecw01234567890123456789".into(),
            generation: 7,
        }
    }
    fn offer(shared: &Shared, runtime: &Runtime, index: u64, valid: bool) {
        let now = Instant::now();
        let record = Record::new(
            index,
            runtime.start,
            Observation {
                cycle_index: index,
                received: valid.then_some(now),
                observed: now,
                valid,
                expected_wkc: 1,
                actual_wkc: valid.then_some(1),
                al: valid.then_some((4, 0)),
                issue: (!valid).then_some(InputIssue::Timeout),
                counts: Counts::default(),
                data: &[7; MAX_PAYLOAD],
            },
        );
        shared.offered.store(index, Release);
        if shared.queue.push(record).is_err() {
            shared.dropped.fetch_add(1, Relaxed);
        }
    }
    #[test]
    fn mqtt_wire_vectors_are_clean_session_qos_zero_non_retained_and_bounded() {
        assert_eq!(
            publish_packet("t", b"{}").unwrap(),
            [0x30, 5, 0, 1, b't', b'{', b'}']
        );
        assert_eq!(
            connect_packet("a", "t", b"{}").unwrap(),
            [
                0x10, 20, 0, 4, b'M', b'Q', b'T', b'T', 4, 6, 0, 10, 0, 1, b'a', 0, 1, b't', 0, 2,
                b'{', b'}'
            ]
        );
        let packet = packet(0x30, &[0; 321]).unwrap();
        assert_eq!(&packet[..3], &[0x30, 0xc1, 2]);
        assert!(packet.len() < input_feed::MAX_RESPONSE);
        assert!(super::packet(0x30, &vec![0; input_feed::MAX_RESPONSE + 1025]).is_err());
        assert!(utf8(&mut vec![], &vec![0; 65536]).is_err());
    }
    #[test]
    fn config_bounds_and_disabled_profile_hash_shape_are_explicit() {
        assert!(Config::default().validate().is_ok());
        for topic in [
            "",
            "x/#",
            "x/+",
            "$SYS/x",
            "space here",
            "nonascii-é",
            "x\0y",
        ] {
            assert!(
                Config {
                    topic: topic.into(),
                    ..Default::default()
                }
                .validate()
                .is_err()
            );
        }
        for config in [
            Config {
                port: 0,
                ..Default::default()
            },
            Config {
                period_ms: 0,
                ..Default::default()
            },
            Config {
                freshness_ms: 60001,
                ..Default::default()
            },
            Config {
                queue_capacity: 8193,
                ..Default::default()
            },
        ] {
            assert!(config.validate().is_err());
        }
        assert!(serde_json::from_str::<Config>(r#"{"broker":"remote"}"#).is_err());
        assert!(
            serde_json::to_value(Profile::default())
                .unwrap()
                .get("mqtt")
                .is_none()
        );
    }
    #[test]
    fn overflow_coalescing_and_attempts_balance_without_a_broker() {
        let r = runtime(Config::default());
        let shared = Shared::new(1);
        let mut latest = Latest::default();
        offer(&shared, &r, 1, true);
        offer(&shared, &r, 2, false);
        latest.drain(&shared);
        assert_eq!(shared.dropped.load(Relaxed), 1);
        let value: serde_json::Value =
            serde_json::from_slice(&r.payload(&latest, &shared, false).unwrap()).unwrap();
        assert!(!value["fresh"].as_bool().unwrap());
        offer(&shared, &r, 3, false);
        latest.drain(&shared);
        let value: serde_json::Value =
            serde_json::from_slice(&r.payload(&latest, &shared, false).unwrap()).unwrap();
        assert!(value["latest"]["payload_hex"].is_null() && value["latest"]["values"].is_null());
        assert_eq!(value["last_valid"]["values"]["Byte"], "7");
        assert!(value["metadata"].get("staged_rx_hex").is_none());
        assert_eq!(shared.coalesced.load(Relaxed), 1);
        latest.attempt(&shared);
        assert_eq!(
            shared.drained.load(Relaxed),
            shared.coalesced.load(Relaxed)
                + shared.attempted_events.load(Relaxed)
                + shared.unsent_events.load(Relaxed)
        );
        assert!(!r.payload(&latest, &shared, true).unwrap().is_empty());
        shared.active.store(false, Release);
        let value: serde_json::Value =
            serde_json::from_slice(&r.payload(&latest, &shared, false).unwrap()).unwrap();
        assert_eq!(value["active"], false);
        assert_eq!(value["fresh"], false);
    }
    fn fixture(reply: Option<[u8; 4]>) -> (Config, std::sync::mpsc::Receiver<()>, JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let config = Config {
            port: listener.local_addr().unwrap().port(),
            ..Default::default()
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(2);
            let mut socket = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < until);
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut bytes = [0; 1024];
            let n = socket.read(&mut bytes).unwrap();
            assert!(n > 0);
            if let Some(reply) = reply {
                socket.write_all(&reply).unwrap();
            }
            tx.send(()).unwrap();
            thread::sleep(Duration::from_millis(200));
        });
        (config, rx, worker)
    }
    #[test]
    fn malformed_connack_does_not_become_connected_or_fail_acquisition_worker() {
        let (config, ready, server) = fixture(Some([0x20, 2, 1, 0]));
        let hub = Hub::start(&config, &Profile::default(), &Report::default()).unwrap();
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        let until = Instant::now() + Duration::from_secs(1);
        while hub.stats().connect_errors == 0 {
            assert!(Instant::now() < until);
            thread::sleep(Duration::from_millis(1));
        }
        let stats = hub.finish();
        assert!(!stats.connected && !stats.worker_failed);
        assert_eq!(stats.connections, 0);
        assert!(stats.connect_errors > 0);
        assert!(stats.last_error.is_some());
        server.join().unwrap();
    }
    #[test]
    fn silent_broker_shutdown_is_bounded_and_offer_never_waits_on_handshake() {
        let (config, ready, server) = fixture(None);
        let mut hub = Hub::start(&config, &Profile::default(), &Report::default()).unwrap();
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        let start = Instant::now();
        for index in 0..100 {
            let now = Instant::now();
            hub.offer(Observation {
                cycle_index: index,
                received: None,
                observed: now,
                valid: false,
                expected_wkc: 1,
                actual_wkc: None,
                al: None,
                issue: Some(InputIssue::Timeout),
                counts: Counts::default(),
                data: &[0; MAX_PAYLOAD],
            });
        }
        let stats = hub.finish();
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(stats.offered, 100);
        assert_eq!(stats.drained, 100);
        assert_eq!(stats.coalesced, 99);
        assert_eq!(stats.unsent_events, 1);
        assert!(!stats.worker_failed);
        server.join().unwrap();
    }
}

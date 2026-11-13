//! Shared fixed input records and bounded JSON encoding, independent of each consumer.
use crate::{
    health::InputIssue,
    model::{Field, MAX_PAYLOAD, Profile},
    run::Report,
};
use anyhow::Result;
use serde::{Serialize, ser::SerializeMap};
use std::{
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::Instant,
};
pub(crate) const MAX_RESPONSE: usize = 2 * 1024 * 1024;
pub(crate) fn anchor() -> (Instant, String, String) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let now = chrono::Utc::now();
    (
        Instant::now(),
        now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        format!(
            "{}-{}-{}",
            now.timestamp_micros(),
            std::process::id(),
            NEXT.fetch_add(1, Relaxed)
        ),
    )
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
pub(crate) struct Record {
    pub(crate) event_index: u64,
    pub(crate) elapsed_us: u64,
    pub(crate) cycle_index: u64,
    pub(crate) received: bool,
    pub(crate) valid: bool,
    pub(crate) expected_wkc: u16,
    pub(crate) actual_wkc: Option<u16>,
    pub(crate) al: Option<(u16, u16)>,
    pub(crate) issue: Option<InputIssue>,
    pub(crate) counts: Counts,
    pub(crate) data: [u8; MAX_PAYLOAD],
}
#[derive(Clone, Copy)]
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

impl Record {
    pub(crate) fn new(event_index: u64, start: Instant, event: Observation<'_>) -> Self {
        Self {
            event_index,
            elapsed_us: event
                .received
                .unwrap_or(event.observed)
                .saturating_duration_since(start)
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
        }
    }
}
#[derive(Serialize)]
pub(crate) struct Metadata {
    pub(crate) app_version: String,
    pub(crate) backend: String,
    pub(crate) profile_sha256: Option<String>,
    pub(crate) requested_cycle_us: u64,
    pub(crate) expected_identity: Option<crate::model::Identity>,
    pub(crate) tx_bytes: usize,
    pub(crate) fields: Vec<Field>,
    pub(crate) device_setup_snapshot: Vec<crate::run::DeviceInfo>,
    pub(crate) pdo_verification: Option<Arc<crate::pdo::Verification>>,
    pub(crate) synchronization: Option<crate::sync::Synchronization>,
}

impl Metadata {
    pub(crate) fn new(profile: &Profile, report: &Report) -> Self {
        Self {
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
pub(crate) struct Sample<'a> {
    pub(crate) event_index: u64,
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
pub(crate) fn sample<'a>(record: &'a Record, metadata: &'a Metadata, now: u64) -> Sample<'a> {
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

pub(crate) fn is_fresh(
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

pub(crate) struct Limited(pub(crate) Vec<u8>);
impl Write for Limited {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_RESPONSE - self.0.len() {
            return Err(io::Error::other(
                "Input feed response exceeds 2 MiB; request fewer samples",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(crate) fn json(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut out = Limited(Vec::new());
    serde_json::to_writer(&mut out, value)?;
    Ok(out.0)
}

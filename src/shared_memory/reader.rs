//! Read-only inspection of the v1 byte contract. Saved bytes never establish current input.
use crate::{
    model::{Identity, MAX_PAYLOAD, Profile},
    shared_memory::{HEADER, SIZE},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};
#[cfg(windows)]
mod windows;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ready,
    NotReady,
    Busy,
    Abandoned,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Source {
    LiveSharedMemory { name: String },
    SavedFile { path: PathBuf },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    Alive,
    Exited,
    IdentityMismatch,
    Unavailable,
}
#[derive(Clone, Debug, Serialize)]
pub struct Observation {
    pub reader_qpc: Option<u64>,
    pub qpc_frequency: Option<u64>,
    pub process: ProcessState,
    pub error: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct Payload {
    pub payload_hex: String,
    pub values: Option<BTreeMap<String, String>>,
}
#[derive(Debug, Serialize)]
pub struct Historical {
    pub event_index: u64,
    pub cycle_index: u64,
    pub elapsed_us: u64,
    pub age_us_at_publication: u64,
    pub observed_age_us: Option<u64>,
    pub data: Payload,
}
#[derive(Debug, Serialize)]
pub struct Latest {
    pub event_index: u64,
    pub cycle_index: u64,
    pub elapsed_us: u64,
    pub age_us_at_publication: u64,
    pub observed_age_us: Option<u64>,
    pub valid_at_exchange: bool,
    pub received: bool,
    pub expected_wkc: u16,
    pub actual_wkc: Option<u16>,
    pub al_status: Option<u16>,
    pub al_code: Option<u16>,
    pub issue: u32,
    pub data: Option<Payload>,
}
#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub stream_id: String,
    pub backend: String,
    pub publisher_pid: u32,
    pub publisher_created_filetime: u64,
    pub utc_start_us: i64,
    pub generation: u64,
    pub publication_index: u64,
    pub publication_elapsed_us: u64,
    pub publication_qpc: u64,
    pub qpc_frequency: u64,
    pub active: bool,
    pub fresh_at_publication: bool,
    pub profile_sha256: Option<String>,
    pub tx_bytes: usize,
    pub expected_identity: Option<Identity>,
    pub observed_identity: Option<Identity>,
    pub station: u16,
    pub position: u16,
    pub requested_cycle_us: u32,
    pub freshness_ms: u32,
    pub period_ms: u32,
    pub latest: Option<Latest>,
    pub last_valid: Option<Historical>,
    pub offered: u64,
    pub drained: u64,
    pub queue_drops: u64,
    pub queue_pending: u64,
    pub coalesced: u64,
    pub written_events: u64,
    pub writes: u64,
    pub lock_misses: u64,
    pub abandoned_recoveries: u64,
    pub cycles: u64,
    pub valid_exchanges: u64,
    pub timeouts: u64,
    pub wkc_mismatches: u64,
    pub al_mismatches: u64,
    pub transport_errors: u64,
    pub missed_deadlines: u64,
    pub csv: Option<crate::http_feed::CsvCounts>,
}
#[derive(Debug, Serialize)]
pub struct Decoding {
    pub profile_sha256: String,
    pub tx_fields: Vec<crate::model::Field>,
}
#[derive(Debug, Serialize)]
pub struct Inspection {
    pub schema: u32,
    pub kind: &'static str,
    pub app_version: &'static str,
    pub source: Source,
    pub status: Status,
    pub raw_sha256: Option<String>,
    pub observation: Option<Observation>,
    pub publication_age_us: Option<u64>,
    pub clock_error: Option<String>,
    pub current_usable: bool,
    pub snapshot: Option<Snapshot>,
    pub decoding: Option<Decoding>,
}
pub struct Capture {
    pub inspection: Inspection,
    bytes: Option<Box<[u8; SIZE]>>,
}
impl Capture {
    pub fn save_raw(&self, path: &Path) -> Result<()> {
        ensure!(
            self.inspection.status == Status::Ready,
            "no ready coherent snapshot to save"
        );
        ensure!(
            path.extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("bin")),
            "snapshot output must end in .bin"
        );
        let mut file = File::create_new(path)
            .context("create new raw snapshot; existing paths are preserved")?;
        file.write_all(self.bytes.as_ref().context("no captured bytes")?.as_slice())?;
        file.sync_all().context("flush raw snapshot")
    }
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn bounded_file(path: &Path, max: u64) -> Result<Vec<u8>> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= max,
        "input must be a regular file no larger than {max} bytes"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(max + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= max, "input grew beyond {max} bytes");
    Ok(bytes)
}
/// Exact effective profile, optionally extracted from a versioned saved run context.
pub fn load_decoding_profile(
    profile: Option<&Path>,
    report: Option<&Path>,
) -> Result<Option<Profile>> {
    ensure!(
        profile.is_none() || report.is_none(),
        "choose --profile or --run-report, not both"
    );
    let Some(path) = profile.or(report) else {
        return Ok(None);
    };
    let bytes = bounded_file(path, 16 * 1024 * 1024)?;
    let profile = if report.is_some() {
        #[derive(Deserialize)]
        struct Saved {
            context: crate::benchmark::RunContext,
        }
        let ctx = serde_json::from_slice::<Saved>(&bytes)?.context;
        ensure!(
            ctx.schema == 1 && hash(&serde_json::to_vec(&ctx.profile)?) == ctx.profile_sha256,
            "saved run context/profile hash mismatch"
        );
        ctx.profile
    } else {
        serde_json::from_slice(&bytes)?
    };
    check_profile(&profile)?;
    Ok(Some(profile))
}
fn check_profile(profile: &Profile) -> Result<()> {
    profile.validate()?;
    ensure!(
        profile.tx.iter().map(|f| f.name.len()).sum::<usize>() <= 16384,
        "typed snapshot field names exceed 16 KiB"
    );
    Ok(())
}
pub fn inspect_file(path: &Path, profile: Option<&Profile>) -> Result<Capture> {
    let bytes = bounded_file(path, SIZE as u64)?;
    let bytes: Box<[u8; SIZE]> = bytes
        .into_boxed_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("snapshot must be exactly {SIZE} bytes"))?;
    build(
        Source::SavedFile { path: path.into() },
        Status::Ready,
        Some(bytes),
        None,
        profile,
    )
}
/// One zero-wait read. Opens existing objects only, closes all handles before returning.
pub fn read_once(name: &str, profile: Option<&Profile>) -> Result<Capture> {
    if let Some(profile) = profile {
        check_profile(profile)?;
    }
    #[cfg(windows)]
    {
        crate::shared_memory::Config {
            name: name.into(),
            ..Default::default()
        }
        .validate()?;
        let (status, bytes, observation) = windows::copy(name)?;
        build(
            Source::LiveSharedMemory { name: name.into() },
            status,
            bytes,
            observation,
            profile,
        )
    }
    #[cfg(not(windows))]
    {
        let _ = (name, profile);
        anyhow::bail!("live shared-memory reading requires Windows");
    }
}
fn build(
    source: Source,
    status: Status,
    bytes: Option<Box<[u8; SIZE]>>,
    observation: Option<Observation>,
    profile: Option<&Profile>,
) -> Result<Capture> {
    let raw_sha256 = bytes.as_ref().map(|b| hash(b.as_slice()));
    let mut snapshot = bytes
        .as_ref()
        .map(|b| parse(b.as_slice()))
        .transpose()?
        .flatten();
    let status = if status == Status::Ready && snapshot.is_none() {
        Status::NotReady
    } else {
        status
    };
    let mut decoding = None;
    if let (Some(snapshot), Some(profile)) = (&mut snapshot, profile) {
        check_profile(profile)?;
        let wanted = hash(&serde_json::to_vec(profile)?);
        ensure!(
            snapshot.profile_sha256.as_deref() == Some(wanted.as_str()),
            "snapshot profile hash mismatch or unavailable; use the exact effective profile (or --run-report)"
        );
        ensure!(
            snapshot.tx_bytes == profile.tx_bytes
                && snapshot.expected_identity == profile.expected_identity,
            "snapshot layout/expected identity disagrees with verified profile"
        );
        let decode = |payload: &mut Payload| -> Result<()> {
            let data = hex::decode(&payload.payload_hex)?;
            payload.values = Some(
                profile
                    .tx
                    .iter()
                    .map(|f| {
                        Ok((
                            f.name.clone(),
                            f.decode(&data)
                                .context("verified input field does not fit snapshot payload")?,
                        ))
                    })
                    .collect::<Result<_>>()?,
            );
            Ok(())
        };
        if let Some(data) = snapshot.latest.as_mut().and_then(|l| l.data.as_mut()) {
            decode(data)?;
        }
        if let Some(last) = &mut snapshot.last_valid {
            decode(&mut last.data)?;
        }
        decoding = Some(Decoding {
            profile_sha256: wanted,
            tx_fields: profile.tx.clone(),
        });
    }
    let mut publication_age_us = None;
    let mut clock_error = None;
    let mut current_usable = false;
    // File evidence is always historical, even if its original active/fresh bits remain true.
    let observation = if matches!(source, Source::LiveSharedMemory { .. }) {
        observation
    } else {
        None
    };
    if let (Some(s), Some(o)) = (&mut snapshot, &observation) {
        publication_age_us = o
            .reader_qpc
            .zip(o.qpc_frequency)
            .filter(|(q, f)| *f == s.qpc_frequency && *f > 0 && *q >= s.publication_qpc)
            .and_then(|(q, f)| {
                u64::try_from(u128::from(q - s.publication_qpc) * 1_000_000 / u128::from(f)).ok()
            });
        if publication_age_us.is_none() {
            clock_error=Some("QPC unavailable, frequency differs, counter regressed or age exceeds u64 microseconds".into());
        }
        if let Some(age) = publication_age_us {
            if let Some(latest) = &mut s.latest {
                latest.observed_age_us = latest.age_us_at_publication.checked_add(age);
            }
            if let Some(last) = &mut s.last_valid {
                last.observed_age_us = last.age_us_at_publication.checked_add(age);
            }
            current_usable = o.process == ProcessState::Alive
                && s.active
                && s.fresh_at_publication
                && s.latest.as_ref().is_some_and(|l| {
                    l.valid_at_exchange
                        && l.event_index == s.offered
                        && l.observed_age_us
                            .is_some_and(|a| a <= u64::from(s.freshness_ms) * 1000)
                });
        }
    }
    Ok(Capture {
        inspection: Inspection {
            schema: 1,
            kind: "shared_input_inspection",
            app_version: env!("CARGO_PKG_VERSION"),
            source,
            status,
            raw_sha256,
            observation,
            publication_age_us,
            clock_error,
            current_usable,
            snapshot,
            decoding,
        },
        bytes,
    })
}

fn parse(data: &[u8]) -> Result<Option<Snapshot>> {
    ensure!(data.len() == SIZE, "snapshot must be exactly {SIZE} bytes");
    if data.iter().all(|b| *b == 0) {
        return Ok(None);
    }
    let u16_at = |o| u16::from_le_bytes(data[o..o + 2].try_into().expect("bounded header"));
    let u32_at = |o| u32::from_le_bytes(data[o..o + 4].try_into().expect("bounded header"));
    let u64_at = |o| u64::from_le_bytes(data[o..o + 8].try_into().expect("bounded header"));
    ensure!(
        &data[..8] == b"ECWBIN01"
            && [u32_at(8), u32_at(12), u32_at(16), u32_at(20)]
                == [1, SIZE as u32, HEADER as u32, MAX_PAYLOAD as u32],
        "unsupported snapshot schema/layout"
    );
    let flags = u32_at(268);
    ensure!(flags & !0xfff == 0, "unknown snapshot flags");
    let bit = |b| flags & b != 0;
    let tx = u32_at(284) as usize;
    let len = u32_at(288) as usize;
    let last_len = u32_at(292) as usize;
    ensure!(
        (1..=MAX_PAYLOAD).contains(&tx)
            && len == if bit(4) { tx } else { 0 }
            && last_len == if bit(8) { tx } else { 0 },
        "inconsistent snapshot payload lengths"
    );
    ensure!(
        data[HEADER + len..HEADER + MAX_PAYLOAD]
            .iter()
            .all(|b| *b == 0)
            && data[HEADER + MAX_PAYLOAD + last_len..]
                .iter()
                .all(|b| *b == 0),
        "nonzero unused or invalid payload bytes"
    );
    ensure!(
        u64_at(40) > 0 && u64_at(256) > 0 && u32_at(264) > 0 && u64_at(336) > 0,
        "missing stream/process/clock identity"
    );
    ensure!(
        (250..=1_000_000).contains(&u32_at(320))
            && (1..=60000).contains(&u32_at(324))
            && (1..=60000).contains(&u32_at(328)),
        "invalid snapshot timing settings"
    );
    let string = |o| -> Result<String> {
        let bytes = &data[o..o + 64];
        let end = bytes
            .iter()
            .position(|b| *b == 0)
            .context("unterminated snapshot string")?;
        ensure!(
            end > 0 && bytes[end..].iter().all(|b| *b == 0),
            "empty or nonzero padded snapshot string"
        );
        let text = std::str::from_utf8(&bytes[..end])?;
        ensure!(
            !text.chars().any(char::is_control),
            "control character in snapshot text"
        );
        Ok(text.into())
    };
    let identity = |o, present| -> Result<Option<Identity>> {
        let value = Identity {
            vendor: u32_at(o),
            product: u32_at(o + 4),
            revision: u32_at(o + 8),
        };
        if present {
            Ok(Some(value))
        } else {
            ensure!(
                value.vendor == 0 && value.product == 0 && value.revision == 0,
                "nonzero absent identity"
            );
            Ok(None)
        }
    };
    let profile_sha256 = if bit(512) {
        Some(hex::encode(&data[408..440]))
    } else {
        ensure!(
            data[408..440].iter().all(|b| *b == 0),
            "nonzero absent profile hash"
        );
        None
    };
    let elapsed = u64_at(48);
    let payload = |o, n| Payload {
        payload_hex: hex::encode_upper(&data[o..o + n]),
        values: None,
    };
    let issue = u32_at(280);
    ensure!(issue <= 5, "unknown input issue");
    let latest = if bit(2) {
        ensure!(
            u64_at(64) > 0 && u64_at(64) <= u64_at(56) && u64_at(72) > 0 && u64_at(80) <= elapsed,
            "invalid latest indexes/timestamp"
        );
        ensure!(
            bit(32) == bit(16) && (bit(16) || !bit(64)),
            "readback present without current reply"
        );
        ensure!(bit(32) || u16_at(274) == 0, "nonzero absent WKC");
        ensure!(
            bit(64) || (u16_at(276) == 0 && u16_at(278) == 0),
            "nonzero absent AL"
        );
        let wkc_ok = u16_at(272) == u16_at(274);
        let al_ok = bit(64) && u16_at(276) & 31 == 4 && u16_at(278) == 0;
        let expected_issue = if !bit(16) {
            if issue == 5 { 5 } else { 1 }
        } else {
            match (wkc_ok, al_ok) {
                (true, true) => 0,
                (false, true) => 2,
                (true, false) => 3,
                (false, false) => 4,
            }
        };
        ensure!(
            issue == expected_issue && bit(4) == (bit(16) && wkc_ok && al_ok),
            "input issue/validity disagrees with WKC/AL/reply quality"
        );
        Some(Latest {
            event_index: u64_at(64),
            cycle_index: u64_at(72),
            elapsed_us: u64_at(80),
            age_us_at_publication: elapsed - u64_at(80),
            observed_age_us: None,
            valid_at_exchange: bit(4),
            received: bit(16),
            expected_wkc: u16_at(272),
            actual_wkc: bit(32).then(|| u16_at(274)),
            al_status: bit(64).then(|| u16_at(276)),
            al_code: bit(64).then(|| u16_at(278)),
            issue,
            data: bit(4).then(|| payload(HEADER, tx)),
        })
    } else {
        ensure!(
            flags & (4 | 8 | 16 | 32 | 64 | 256 | 2048) == 0
                && data[64..112].iter().all(|b| *b == 0)
                && data[168..248].iter().all(|b| *b == 0)
                && data[272..284].iter().all(|b| *b == 0),
            "latest absent but exchange data present"
        );
        None
    };
    let last_valid = if bit(8) {
        let l = latest.as_ref().context("historical input without latest")?;
        ensure!(
            u64_at(88) > 0
                && u64_at(88) <= l.event_index
                && u64_at(96) > 0
                && u64_at(96) <= l.cycle_index
                && u64_at(104) <= l.elapsed_us,
            "invalid historical indexes/timestamp"
        );
        if l.valid_at_exchange {
            ensure!(
                u64_at(88) == l.event_index
                    && u64_at(96) == l.cycle_index
                    && u64_at(104) == l.elapsed_us
                    && data[HEADER..HEADER + tx]
                        == data[HEADER + MAX_PAYLOAD..HEADER + MAX_PAYLOAD + tx],
                "latest valid input disagrees with last-valid image"
            );
        } else {
            ensure!(
                u64_at(88) < l.event_index,
                "invalid latest cannot also be last-valid"
            );
        }
        Some(Historical {
            event_index: u64_at(88),
            cycle_index: u64_at(96),
            elapsed_us: u64_at(104),
            age_us_at_publication: elapsed - u64_at(104),
            observed_age_us: None,
            data: payload(HEADER + MAX_PAYLOAD, tx),
        })
    } else {
        ensure!(
            !bit(4) && data[88..112].iter().all(|b| *b == 0),
            "missing or nonzero absent last-valid image"
        );
        None
    };
    ensure!(
        !bit(256)
            || (bit(1)
                && latest.as_ref().is_some_and(|l| l.valid_at_exchange
                    && l.event_index == u64_at(56)
                    && l.age_us_at_publication <= u64::from(u32_at(324)) * 1000)),
        "inconsistent fresh-at-publication flag"
    );
    let csv = if bit(2048) {
        Some(crate::http_feed::CsvCounts {
            selected: u64_at(224),
            written: u64_at(232),
            overruns: u64_at(240),
        })
    } else {
        ensure!(
            data[224..248].iter().all(|b| *b == 0),
            "nonzero absent CSV counters"
        );
        None
    };
    Ok(Some(Snapshot {
        stream_id: string(344)?,
        backend: string(440)?,
        publisher_pid: u32_at(264),
        publisher_created_filetime: u64_at(336),
        utc_start_us: u64_at(32) as i64,
        generation: u64_at(40),
        publication_index: u64_at(24),
        publication_elapsed_us: elapsed,
        publication_qpc: u64_at(248),
        qpc_frequency: u64_at(256),
        active: bit(1),
        fresh_at_publication: bit(256),
        profile_sha256,
        tx_bytes: tx,
        expected_identity: identity(296, bit(128))?,
        observed_identity: identity(308, bit(1024))?,
        station: u16_at(332),
        position: u16_at(334),
        requested_cycle_us: u32_at(320),
        freshness_ms: u32_at(324),
        period_ms: u32_at(328),
        latest,
        last_valid,
        offered: u64_at(56),
        drained: u64_at(120),
        queue_drops: u64_at(112),
        queue_pending: u64_at(152),
        coalesced: u64_at(128),
        written_events: u64_at(144),
        writes: u64_at(160),
        lock_misses: u64_at(136),
        abandoned_recoveries: u64_at(504),
        cycles: u64_at(168),
        valid_exchanges: u64_at(176),
        timeouts: u64_at(184),
        wkc_mismatches: u64_at(192),
        al_mismatches: u64_at(200),
        transport_errors: u64_at(208),
        missed_deadlines: u64_at(216),
        csv,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Field, Kind};
    fn put32(b: &mut [u8], o: usize, v: u32) {
        b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(b: &mut [u8], o: usize, v: u64) {
        b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn fixture() -> (Box<[u8; SIZE]>, Profile) {
        // Independent byte vector; deliberately does not call the publisher's encoder.
        let p = Profile {
            tx_bytes: 16,
            tx: vec![
                Field {
                    name: "Wide".into(),
                    width: 64,
                    log: false,
                    ..Default::default()
                },
                Field {
                    name: "Float".into(),
                    bit: 64,
                    width: 32,
                    kind: Kind::F32,
                    ..Default::default()
                },
                Field {
                    name: "Words".into(),
                    bit: 96,
                    width: 32,
                    big_endian: true,
                    swap_bytes_in_words: true,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let mut b = Box::new([0; SIZE]);
        b[..8].copy_from_slice(b"ECWBIN01");
        for (o, v) in [
            (8, 1),
            (12, 2560),
            (16, 512),
            (20, 1024),
            (264, 123),
            (268, 0x37f),
            (284, 16),
            (288, 16),
            (292, 16),
            (320, 1000),
            (324, 20),
            (328, 10),
        ] {
            put32(b.as_mut_slice(), o, v);
        }
        for (o, v) in [
            (24, 2),
            (32, 1700000000000000),
            (40, 1),
            (48, 1000),
            (56, 1),
            (64, 1),
            (72, 4),
            (80, 900),
            (88, 1),
            (96, 4),
            (104, 900),
            (120, 1),
            (144, 1),
            (160, 1),
            (168, 1),
            (176, 1),
            (248, 1000),
            (256, 1000000),
            (336, 130000000000000000),
        ] {
            put64(b.as_mut_slice(), o, v);
        }
        b[272..274].copy_from_slice(&1u16.to_le_bytes());
        b[274..276].copy_from_slice(&1u16.to_le_bytes());
        b[276..278].copy_from_slice(&4u16.to_le_bytes());
        b[344..355].copy_from_slice(b"independent");
        b[440..447].copy_from_slice(b"Fixture");
        b[408..440].copy_from_slice(&Sha256::digest(serde_json::to_vec(&p).unwrap()));
        let data = [
            255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 192, 127, 34, 17, 68, 51,
        ];
        b[512..528].copy_from_slice(&data);
        b[1536..1552].copy_from_slice(&data);
        (b, p)
    }
    fn source() -> Source {
        Source::LiveSharedMemory {
            name: "fixture".into(),
        }
    }
    fn observed(qpc: u64, process: ProcessState) -> Option<Observation> {
        Some(Observation {
            reader_qpc: Some(qpc),
            qpc_frequency: Some(1000000),
            process,
            error: None,
        })
    }
    #[test]
    fn verified_profile_decodes_all_fields_as_exact_strings_and_keeps_offline_historical() {
        let (b, p) = fixture();
        p.validate().unwrap();
        let report = build(
            source(),
            Status::Ready,
            Some(b.clone()),
            observed(1100, ProcessState::Alive),
            Some(&p),
        )
        .unwrap()
        .inspection;
        assert!(report.current_usable);
        let s = report.snapshot.unwrap();
        let values = s.latest.unwrap().data.unwrap().values.unwrap();
        assert_eq!(values["Wide"], "18446744073709551615");
        assert_eq!(values["Float"], "NaN");
        assert_eq!(values["Words"], "287454020");
        let file = build(
            Source::SavedFile {
                path: "fixture.bin".into(),
            },
            Status::Ready,
            Some(b),
            observed(1100, ProcessState::Alive),
            Some(&p),
        )
        .unwrap()
        .inspection;
        assert!(
            !file.current_usable && file.observation.is_none() && file.publication_age_us.is_none()
        );
        assert!(
            file.snapshot
                .unwrap()
                .latest
                .unwrap()
                .observed_age_us
                .is_none()
        );
    }
    #[test]
    fn freshness_requires_process_creation_liveness_clock_and_sample_age() {
        let (b, _) = fixture();
        for process in [
            ProcessState::Exited,
            ProcessState::IdentityMismatch,
            ProcessState::Unavailable,
        ] {
            assert!(
                !build(
                    source(),
                    Status::Ready,
                    Some(b.clone()),
                    observed(1100, process),
                    None
                )
                .unwrap()
                .inspection
                .current_usable
            );
        }
        for qpc in [999, 21001] {
            assert!(
                !build(
                    source(),
                    Status::Ready,
                    Some(b.clone()),
                    observed(qpc, ProcessState::Alive),
                    None
                )
                .unwrap()
                .inspection
                .current_usable
            );
        }
        let mut observation = observed(1100, ProcessState::Alive).unwrap();
        observation.qpc_frequency = Some(7);
        let report = build(
            source(),
            Status::Ready,
            Some(b.clone()),
            Some(observation),
            None,
        )
        .unwrap()
        .inspection;
        assert!(!report.current_usable && report.clock_error.is_some());
        let mut b = b;
        put64(b.as_mut_slice(), 248, 0);
        put64(b.as_mut_slice(), 256, 1);
        let report = build(
            source(),
            Status::Ready,
            Some(b),
            Some(Observation {
                reader_qpc: Some(u64::MAX),
                qpc_frequency: Some(1),
                process: ProcessState::Alive,
                error: None,
            }),
            None,
        )
        .unwrap()
        .inspection;
        assert!(
            !report.current_usable
                && report.publication_age_us.is_none()
                && report.clock_error.is_some()
        );
    }
    #[test]
    fn invalid_attempt_has_no_current_values_and_last_good_remains_explicitly_historical() {
        let (mut b, p) = fixture();
        put32(b.as_mut_slice(), 268, 1 | 2 | 8 | 512);
        put32(b.as_mut_slice(), 280, 1);
        put32(b.as_mut_slice(), 288, 0);
        put64(b.as_mut_slice(), 56, 2);
        put64(b.as_mut_slice(), 64, 2);
        put64(b.as_mut_slice(), 72, 5);
        put64(b.as_mut_slice(), 80, 950);
        b[274..280].fill(0);
        b[512..1536].fill(0);
        let report = build(
            source(),
            Status::Ready,
            Some(b),
            observed(1100, ProcessState::Alive),
            Some(&p),
        )
        .unwrap()
        .inspection;
        assert!(!report.current_usable);
        let s = report.snapshot.unwrap();
        let latest = s.latest.unwrap();
        assert!(
            !latest.valid_at_exchange
                && latest.data.is_none()
                && latest.actual_wkc.is_none()
                && latest.al_status.is_none()
        );
        assert_eq!(
            s.last_valid.unwrap().data.values.unwrap()["Wide"],
            "18446744073709551615"
        );
    }
    #[test]
    fn malformed_lengths_flags_padding_quality_time_and_history_are_rejected() {
        let (b, _) = fixture();
        for n in 0..SIZE {
            assert!(parse(&b[..n]).is_err());
        }
        let mut oversized = b.to_vec();
        oversized.push(0);
        assert!(parse(&oversized).is_err());
        for (o, value) in [
            (8, 2),
            (12, 2559),
            (16, 513),
            (20, 1023),
            (268, 0x137f),
            (284, 1025),
            (288, 15),
            (292, 0),
            (280, 6),
            (320, 0),
            (324, 0),
            (328, 60001),
        ] {
            let mut bad = b.clone();
            put32(bad.as_mut_slice(), o, value);
            assert!(parse(bad.as_slice()).is_err(), "offset {o}");
        }
        for (o, value) in [
            (40, 0),
            (80, 1001),
            (88, 2),
            (96, 5),
            (104, 1001),
            (256, 0),
            (336, 0),
        ] {
            let mut bad = b.clone();
            put64(bad.as_mut_slice(), o, value);
            assert!(parse(bad.as_slice()).is_err(), "offset {o}");
        }
        for (o, value) in [
            (0, b'x'),
            (356, b'x'),
            (440, 255),
            (528, 1),
            (1552, 1),
            (274, 0),
            (278, 1),
        ] {
            let mut bad = b.clone();
            bad[o] = value;
            assert!(parse(bad.as_slice()).is_err(), "offset {o}");
        }
    }
    #[test]
    fn profile_changes_and_header_layout_disagreement_cannot_produce_typed_values() {
        let (b, mut p) = fixture();
        p.tx[0].name = "Changed".into();
        assert!(build(source(), Status::Ready, Some(b.clone()), None, Some(&p)).is_err());
        let (_, p) = fixture();
        let mut bad = b;
        put32(bad.as_mut_slice(), 268, 0x37f | 128);
        assert!(parse(bad.as_slice()).is_ok());
        assert!(build(source(), Status::Ready, Some(bad), None, Some(&p)).is_err());
        let empty = build(
            source(),
            Status::Ready,
            Some(Box::new([0; SIZE])),
            None,
            None,
        )
        .unwrap();
        assert_eq!(empty.inspection.status, Status::NotReady);
        assert!(empty.inspection.snapshot.is_none());
        assert!(empty.save_raw(Path::new("must_not_write.bin")).is_err());
        for status in [Status::Busy, Status::Abandoned] {
            let capture = build(source(), status, None, None, None).unwrap();
            assert!(
                capture.inspection.snapshot.is_none()
                    && capture.inspection.raw_sha256.is_none()
                    && !capture.inspection.current_usable
            );
        }
    }
}

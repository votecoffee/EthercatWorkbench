//! Bounded offline inspection of classic PCAP. Never opens a driver or replays traffic.
use crate::{
    model::Profile,
    wire::{Frame, input_datagrams, input_reply},
};
use anyhow::{Context, Result, bail, ensure};
use hdrhistogram::Histogram;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path, sync::atomic::AtomicBool};

const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PACKETS: u64 = 1_000_000;
const MAX_SNAPLEN: u32 = 262_144;

#[derive(Debug, Default, Serialize)]
pub struct Counts {
    pub packets: u64,
    pub snapshot_truncated: u64,
    pub ethercat: u64,
    pub requests: u64,
    pub replies: u64,
    pub valid_safeop_replies: u64,
    pub wkc_mismatches: u64,
    pub al_mismatches: u64,
    pub unmatched_ethercat: u64,
    pub other_packets: u64,
    pub vlan_packets: u64,
    pub timestamp_regressions: u64,
}

#[derive(Debug, Serialize)]
pub struct Spacing {
    pub count: u64,
    pub p50_ns: Option<u64>,
    pub p95_ns: Option<u64>,
    pub p99_ns: Option<u64>,
    pub longest_gap_ns: Option<u64>,
}

struct Gaps {
    previous: Option<u64>,
    histogram: Histogram<u64>,
    longest: u64,
}

impl Gaps {
    fn new() -> Result<Self> {
        Ok(Self {
            previous: None,
            histogram: Histogram::new(3)?,
            longest: 0,
        })
    }

    fn tick(&mut self, timestamp: u64) -> Result<()> {
        if let Some(previous) = self.previous
            && let Some(gap) = timestamp.checked_sub(previous)
        {
            self.histogram.record(gap)?;
            self.longest = self.longest.max(gap);
        }
        self.previous = Some(timestamp);
        Ok(())
    }

    fn finish(self) -> Spacing {
        let count = self.histogram.len();
        let percentile =
            |q| (count != 0).then(|| self.histogram.value_at_quantile(q).min(self.longest));
        Spacing {
            count,
            p50_ns: percentile(0.50),
            p95_ns: percentile(0.95),
            p99_ns: percentile(0.99),
            longest_gap_ns: (count != 0).then_some(self.longest),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Value {
    pub field: String,
    pub source: crate::model::Source,
    pub value: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Preview {
    pub packet_index: u64,
    pub timestamp_unix_ns: u64,
    pub sequence: u8,
    pub input_wkc: u16,
    pub al_wkc: u16,
    pub al_status: u16,
    pub al_code: u16,
    pub valid_safeop: bool,
    pub payload_hex: String,
    pub values: Vec<Value>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub app_version: String,
    pub file: String,
    pub file_bytes: u64,
    pub file_sha256: String,
    pub profile: Profile,
    pub profile_sha256: String,
    pub station_address: u16,
    pub expected_input_wkc: u16,
    pub timestamp_resolution: String,
    pub capture_first_utc: Option<String>,
    pub first_timestamp_unix_ns: Option<u64>,
    pub last_timestamp_unix_ns: Option<u64>,
    pub counts: Counts,
    pub request_spacing: Option<Spacing>,
    pub reply_spacing: Option<Spacing>,
    pub valid_reply_spacing: Option<Spacing>,
    pub preview_limit: usize,
    pub preview: Vec<Preview>,
    pub notes: Vec<String>,
}

pub fn inspect(
    path: &Path,
    profile: &Profile,
    station: u16,
    preview_limit: usize,
) -> Result<Report> {
    inspect_with_stop(path, profile, station, preview_limit, None)
}

pub fn inspect_cancelable(
    path: &Path,
    profile: &Profile,
    station: u16,
    preview_limit: usize,
    stop: &AtomicBool,
) -> Result<Report> {
    inspect_with_stop(path, profile, station, preview_limit, Some(stop))
}

fn read_bytes(mut reader: impl Read, stop: Option<&AtomicBool>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 65_536];
    loop {
        crate::review::check_cancel(stop)?;
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        ensure!(
            bytes.len() + count <= MAX_BYTES as usize,
            "PCAP exceeds 64 MiB"
        );
        bytes.extend_from_slice(&buffer[..count]);
    }
    crate::review::check_cancel(stop)?;
    Ok(bytes)
}

fn inspect_with_stop(
    path: &Path,
    profile: &Profile,
    station: u16,
    preview_limit: usize,
    stop: Option<&AtomicBool>,
) -> Result<Report> {
    crate::review::check_cancel(stop)?;
    validate_settings(profile, station, preview_limit)?;
    let file = File::open(path).with_context(|| format!("open PCAP {}", path.display()))?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.len() <= MAX_BYTES,
        "PCAP must be a regular file of at most 64 MiB"
    );
    let bytes = read_bytes(&file, stop)?;
    let after = file.metadata()?;
    ensure!(
        bytes.len() as u64 == before.len()
            && before.len() == after.len()
            && before.modified()? == after.modified()?,
        "PCAP changed while reading"
    );
    let mut report = parse_with_stop(&bytes, profile, station, preview_limit, stop)?;
    report.file = path.display().to_string();
    crate::review::check_cancel(stop)?;
    Ok(report)
}

pub(crate) fn validate_settings(
    profile: &Profile,
    station: u16,
    preview_limit: usize,
) -> Result<()> {
    profile.validate()?;
    ensure!(
        profile.tx_bytes > 0,
        "PCAP inspection requires a nonempty TxPDO image"
    );
    ensure!(
        (1..=0xfffe).contains(&station),
        "station address must be 1..65534"
    );
    ensure!(preview_limit <= 64, "PCAP preview limit must be 0..64");
    ensure!(
        profile.tx.iter().map(|f| f.name.len()).sum::<usize>() <= 16_384,
        "PCAP preview field names exceed 16 KiB"
    );
    Ok(())
}

fn parse_with_stop(
    bytes: &[u8],
    profile: &Profile,
    station: u16,
    preview_limit: usize,
    stop: Option<&AtomicBool>,
) -> Result<Report> {
    crate::review::check_cancel(stop)?;
    validate_settings(profile, station, preview_limit)?;
    ensure!(
        bytes.len() >= 24 && bytes.len() as u64 <= MAX_BYTES,
        "PCAP header truncated or file exceeds 64 MiB"
    );
    let (little, nano) = match &bytes[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        [0x0a, 0x0d, 0x0d, 0x0a] => {
            bail!("PCAPNG is unsupported; export classic Ethernet PCAP 2.4")
        }
        _ => bail!("unsupported PCAP magic"),
    };
    let word = |at| {
        let raw = [bytes[at], bytes[at + 1]];
        if little {
            u16::from_le_bytes(raw)
        } else {
            u16::from_be_bytes(raw)
        }
    };
    let number = |data: &[u8], at| {
        let raw = [data[at], data[at + 1], data[at + 2], data[at + 3]];
        if little {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        }
    };
    ensure!(
        word(4) == 2 && word(6) == 4,
        "only PCAP version 2.4 is supported"
    );
    let snaplen = number(bytes, 16);
    ensure!(
        (1..=MAX_SNAPLEN).contains(&snaplen),
        "PCAP snaplen must be 1..262144"
    );
    ensure!(
        number(bytes, 20) == 1,
        "only Ethernet link type 1 without additional FCS flags is supported"
    );

    let mut counts = Counts::default();
    let mut requests = Gaps::new()?;
    let mut replies = Gaps::new()?;
    let mut valid_replies = Gaps::new()?;
    let mut preview = Vec::new();
    let mut first = None;
    let mut previous = None;
    let mut offset = 24;
    while offset < bytes.len() {
        crate::review::check_cancel(stop)?;
        ensure!(
            counts.packets < MAX_PACKETS,
            "PCAP exceeds one million packets"
        );
        ensure!(bytes.len() - offset >= 16, "truncated PCAP packet header");
        let header = &bytes[offset..offset + 16];
        let seconds = number(header, 0) as u64;
        let fraction = number(header, 4) as u64;
        let resolution = if nano { 1_000_000_000 } else { 1_000_000 };
        ensure!(
            fraction < resolution,
            "PCAP timestamp fraction out of range"
        );
        let timestamp = seconds * 1_000_000_000 + fraction * if nano { 1 } else { 1000 };
        let captured = number(header, 8);
        let original = number(header, 12);
        ensure!(
            captured <= snaplen && captured <= original,
            "invalid PCAP captured/original packet lengths"
        );
        offset += 16;
        ensure!(
            captured as usize <= bytes.len() - offset,
            "truncated PCAP packet data"
        );
        let packet = &bytes[offset..offset + captured as usize];
        offset += captured as usize;
        counts.packets += 1;
        counts.timestamp_regressions += u64::from(previous.is_some_and(|at| timestamp < at));
        first.get_or_insert(timestamp);
        previous = Some(timestamp);
        let truncated = captured < original;
        counts.snapshot_truncated += u64::from(truncated);
        let ether_type = packet.get(12..14);
        if ether_type != Some(&[0x88, 0xa4][..]) {
            counts.other_packets += 1;
            counts.vlan_packets +=
                u64::from(matches!(ether_type, Some([0x81, 0x00] | [0x88, 0xa8])));
            continue;
        }
        counts.ethercat += 1;
        if truncated || packet.len() < 18 {
            counts.unmatched_ethercat += 1;
            continue;
        }
        let sequence = packet[17];
        let frame = Frame::new(sequence, input_datagrams(station, profile.tx_bytes));
        if packet.starts_with(frame.bytes()) {
            counts.requests += 1;
            requests.tick(timestamp)?;
        } else if let Some(parts) = frame.reply(packet) {
            let input = input_reply(parts);
            let wkc_ok = input.wkc == 1;
            let al_ok = input
                .status
                .is_some_and(|(state, code)| state & 0x1f == 4 && code == 0);
            let valid = wkc_ok && al_ok;
            counts.replies += 1;
            counts.wkc_mismatches += u64::from(!wkc_ok);
            counts.al_mismatches += u64::from(!al_ok);
            replies.tick(timestamp)?;
            if valid {
                counts.valid_safeop_replies += 1;
                valid_replies.tick(timestamp)?;
            }
            if preview.len() < preview_limit {
                let payload = &input.data[..profile.tx_bytes];
                preview.push(Preview {
                    packet_index: counts.packets,
                    timestamp_unix_ns: timestamp,
                    sequence,
                    input_wkc: input.wkc,
                    al_wkc: parts[1].1,
                    al_status: u16::from_le_bytes([parts[1].0[0], parts[1].0[1]]),
                    al_code: u16::from_le_bytes([parts[1].0[4], parts[1].0[5]]),
                    valid_safeop: valid,
                    payload_hex: hex::encode_upper(payload),
                    values: profile
                        .tx
                        .iter()
                        .map(|field| Value {
                            field: field.name.clone(),
                            source: field.source.clone(),
                            value: field.decode(payload),
                        })
                        .collect(),
                });
            }
        } else {
            counts.unmatched_ethercat += 1;
        }
    }
    let monotonic = counts.timestamp_regressions == 0;
    let mut notes = vec![
        "Offline file evidence only. Capture clock, placement, direction and dropped packets are unknown; recorded timestamps are not the application monotonic receive clock or qualified wire timing.".into(),
        "Only the Workbench untagged input-only LRD at logical address 0 plus FPRD AL-status signature is recognized. Station address and profile are user-supplied expectations; device identity and PDO meaning are not verified.".into(),
        "Requests and replies are counted independently, without pairing, deduplication, timeout inference, cycle indexes or deadline estimates. Duplicate frames are retained. Percentiles use a three-significant-digit histogram; longest gap is exact.".into(),
    ];
    if !monotonic {
        notes.push("Capture timestamps regress; all spacing summaries are unavailable.".into());
    }
    if counts.snapshot_truncated > 0 {
        notes.push("Snapshot-truncated packets were counted but never decoded.".into());
    }
    if counts.vlan_packets > 0 {
        notes.push(
            "VLAN-tagged packets were counted as other traffic; VLAN decoding is unsupported."
                .into(),
        );
    }
    if counts.replies == 0 {
        notes.push("No returned frames matched the selected station, image length and Workbench signature.".into());
    }
    if counts.replies > preview.len() as u64 {
        notes.push("Payload preview is limited; all recognized frames contributed to counts and available spacing summaries.".into());
    }
    let mut hash = Sha256::new();
    for chunk in bytes.chunks(65_536) {
        crate::review::check_cancel(stop)?;
        hash.update(chunk);
    }
    let profile_sha256 = crate::benchmark::hash(&serde_json::to_vec(profile)?);
    crate::review::check_cancel(stop)?;
    Ok(Report {
        schema: 1,
        app_version: env!("CARGO_PKG_VERSION").into(),
        file: String::new(),
        file_bytes: bytes.len() as u64,
        file_sha256: hex::encode(hash.finalize()),
        profile: profile.clone(),
        profile_sha256,
        station_address: station,
        expected_input_wkc: 1,
        timestamp_resolution: if nano { "nanoseconds" } else { "microseconds" }.into(),
        capture_first_utc: first
            .and_then(|at| {
                chrono::DateTime::from_timestamp(
                    (at / 1_000_000_000) as i64,
                    (at % 1_000_000_000) as u32,
                )
            })
            .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)),
        first_timestamp_unix_ns: first,
        last_timestamp_unix_ns: previous,
        counts,
        request_spacing: monotonic.then(|| requests.finish()),
        reply_spacing: monotonic.then(|| replies.finish()),
        valid_reply_spacing: monotonic.then(|| valid_replies.finish()),
        preview_limit,
        preview,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(
        bytes: &[u8],
        profile: &Profile,
        station: u16,
        preview_limit: usize,
    ) -> Result<Report> {
        parse_with_stop(bytes, profile, station, preview_limit, None)
    }

    #[test]
    fn cancellation_stops_chunked_reads_and_prevents_parsing_or_file_access() {
        use std::sync::atomic::Ordering::Relaxed;
        struct Reader<'a> {
            stop: &'a AtomicBool,
            reads: usize,
        }
        impl Read for Reader<'_> {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                self.reads += 1;
                assert_eq!(self.reads, 1, "cancellation must prevent the next read");
                bytes.fill(0);
                self.stop.store(true, Relaxed);
                Ok(bytes.len())
            }
        }
        let stop = AtomicBool::new(false);
        assert!(
            read_bytes(
                Reader {
                    stop: &stop,
                    reads: 0
                },
                Some(&stop)
            )
            .unwrap_err()
            .to_string()
            .contains("cancelled")
        );
        assert!(
            parse_with_stop(&[], &profile(), 0x1000, 16, Some(&stop))
                .unwrap_err()
                .to_string()
                .contains("cancelled")
        );
        assert!(
            inspect_cancelable(Path::new("missing.pcap"), &profile(), 0x1000, 16, &stop)
                .unwrap_err()
                .to_string()
                .contains("cancelled")
        );
    }

    fn profile() -> Profile {
        serde_json::from_str(include_str!("../samples/synthetic.json")).unwrap()
    }

    fn capture(little: bool, nano: bool, packets: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let u32bytes = |n: u32| {
            if little {
                n.to_le_bytes()
            } else {
                n.to_be_bytes()
            }
        };
        let u16bytes = |n: u16| {
            if little {
                n.to_le_bytes()
            } else {
                n.to_be_bytes()
            }
        };
        let mut bytes = Vec::new();
        bytes.extend(u32bytes(if nano { 0xa1b23c4d } else { 0xa1b2c3d4 }));
        bytes.extend(u16bytes(2));
        bytes.extend(u16bytes(4));
        for n in [0, 0, 65535, 1] {
            bytes.extend(u32bytes(n));
        }
        for (fraction, packet) in packets {
            for n in [
                1_700_000_000,
                *fraction,
                packet.len() as u32,
                packet.len() as u32,
            ] {
                bytes.extend(u32bytes(n));
            }
            bytes.extend(packet);
        }
        bytes
    }

    fn reply(seq: u8, wkc: u16, state: u8, al_wkc: u16) -> Vec<u8> {
        let mut packet = Frame::new(seq, input_datagrams(0x1000, 8)).bytes().to_vec();
        packet[6..12].copy_from_slice(&crate::wire::CUSTOM_REPLY);
        packet[26..34].copy_from_slice(&[42, 0, 1, 0, 0, 0, 40, 65]);
        packet[34..36].copy_from_slice(&wkc.to_le_bytes());
        packet[46] = state;
        packet[52..54].copy_from_slice(&al_wkc.to_le_bytes());
        packet
    }

    #[test]
    fn endian_and_precision_variants_keep_values_quality_and_independent_counts() {
        for little in [false, true] {
            for nano in [false, true] {
                let unit = if nano { 1000 } else { 1 };
                let request = Frame::new(8, input_datagrams(0x1000, 8)).bytes().to_vec();
                let packets = vec![
                    (0, request.clone()),
                    (100 * unit, reply(8, 1, 4, 1)),
                    (1000 * unit, request),
                    (1100 * unit, reply(8, 2, 4, 1)),
                    (2100 * unit, reply(9, 1, 0x14, 1)),
                    (3100 * unit, reply(10, 1, 4, 0)),
                    (4100 * unit, reply(11, 1, 4, 1)),
                ];
                let report =
                    parse(&capture(little, nano, &packets), &profile(), 0x1000, 64).unwrap();
                assert_eq!(report.counts.requests, 2);
                assert_eq!(report.counts.replies, 5);
                assert_eq!(report.counts.valid_safeop_replies, 2);
                assert_eq!(report.counts.wkc_mismatches, 1);
                assert_eq!(report.counts.al_mismatches, 2);
                assert_eq!(
                    report.reply_spacing.unwrap().longest_gap_ns,
                    Some(1_000_000)
                );
                assert_eq!(
                    report.valid_reply_spacing.unwrap().longest_gap_ns,
                    Some(4_000_000)
                );
                assert_eq!(report.preview[0].values[0].value.as_deref(), Some("42"));
                assert_eq!(report.preview[0].values[1].value.as_deref(), Some("true"));
                assert_eq!(report.preview[0].values[2].value.as_deref(), Some("10.5"));
                assert!(!report.preview[2].valid_safeop);
            }
        }
    }

    #[test]
    fn regressions_suppress_spacing_and_duplicates_remain_visible() {
        let bytes = capture(
            true,
            true,
            &[(100, reply(1, 1, 4, 1)), (100, reply(1, 1, 4, 1))],
        );
        let report = parse(&bytes, &profile(), 0x1000, 1).unwrap();
        assert_eq!(report.counts.replies, 2);
        assert_eq!(report.preview.len(), 1);
        assert_eq!(report.reply_spacing.unwrap().p99_ns, Some(0));
        let bytes = capture(
            true,
            true,
            &[(100, reply(1, 1, 4, 1)), (90, reply(2, 1, 4, 1))],
        );
        let report = parse(&bytes, &profile(), 0x1000, 0).unwrap();
        assert_eq!(report.counts.timestamp_regressions, 1);
        assert!(
            report.request_spacing.is_none()
                && report.reply_spacing.is_none()
                && report.valid_reply_spacing.is_none()
        );
    }

    #[test]
    fn truncated_vlan_and_wrong_signature_never_decode() {
        let mut vlan = reply(1, 1, 4, 1);
        vlan[12..14].copy_from_slice(&[0x81, 0]);
        let mut wrong = reply(2, 1, 4, 1);
        wrong[38] = 1;
        let mut bytes = capture(
            true,
            false,
            &[(0, reply(1, 1, 4, 1)), (1, vlan), (2, wrong)],
        );
        bytes[36..40].copy_from_slice(&100u32.to_le_bytes()); // original > captured
        let report = parse(&bytes, &profile(), 0x1000, 64).unwrap();
        assert_eq!(report.counts.snapshot_truncated, 1);
        assert_eq!(report.counts.vlan_packets, 1);
        assert_eq!(report.counts.unmatched_ethercat, 2);
        assert!(report.preview.is_empty());
        assert_eq!(
            parse(
                &capture(true, false, &[(0, reply(1, 1, 4, 1))]),
                &profile(),
                0x1001,
                64
            )
            .unwrap()
            .counts
            .replies,
            0
        );
    }

    #[test]
    fn rejects_structural_errors_and_unsupported_formats() {
        let bytes = capture(true, false, &[(0, reply(1, 1, 4, 1))]);
        for end in [0, 4, 23, 25, 39, bytes.len() - 1] {
            assert!(parse(&bytes[..end], &profile(), 0x1000, 0).is_err());
        }
        for (offset, value) in [
            (0, 0x0a0d0d0au32),
            (16, 0),
            (20, 101),
            (20, 0x24000001),
            (28, 1_000_000),
            (32, 65536),
            (36, 1),
        ] {
            let mut bad = bytes.clone();
            bad[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(
                parse(&bad, &profile(), 0x1000, 0).is_err(),
                "offset {offset}, value {value}"
            );
        }
        assert!(parse(&bytes, &profile(), 0, 0).is_err());
        assert!(parse(&bytes, &profile(), 0x1000, 65).is_err());
        let empty = parse(&capture(true, true, &[]), &profile(), 0x1000, 0).unwrap();
        assert!(empty.first_timestamp_unix_ns.is_none());
        assert_eq!(empty.counts.packets, 0);
    }
}

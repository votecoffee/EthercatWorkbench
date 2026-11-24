//! Extract register bytes from an explicitly addressed saved logical payload.
use super::{
    Sample, copy_bits,
    fmmu::{Check, Contributions, Table},
};
use crate::{
    input_group::{AlRead, MAX_DATAGRAMS, decode_frame_hex, preflight::topology, read_json},
    model::{MAX_PAYLOAD, payload_hex},
    wire::{Frame, MAX_FRAME_BYTES, input_datagrams},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{iter::once, ops::Range, path::Path};

const MAX_FILE_BYTES: u64 = 16 * 1024;
const LOGICAL_ADDRESS_END: u64 = 1 << 32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedWindow {
    schema: u32,
    station_address: u16,
    logical_start: u32,
    payload_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedReply {
    schema: u32,
    station_address: u16,
    index: u8,
    logical_start: u32,
    byte_count: usize,
    expected_wkc: Option<u16>,
    reply_hex: String,
}

#[derive(Serialize)]
struct ReplyEvidence {
    frame_sha256: String,
    index: u8,
    expected_wkc: Option<u16>,
    actual_wkc: u16,
    wkc_matches: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    station_al: Option<AlRead>,
    #[serde(skip_serializing_if = "Option::is_none")]
    topology: Option<TopologyEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contributors: Option<Contributions>,
}

#[derive(Serialize)]
struct TopologyEvidence {
    observation: topology::Reading,
    conflicting_alias_positions: Vec<usize>,
    valid: bool,
}

impl TopologyEvidence {
    fn new(observation: topology::Reading, station: u16) -> Self {
        let conflicting_alias_positions = observation.conflicting_alias_positions(station);
        let valid = observation.valid && conflicting_alias_positions.is_empty();
        Self {
            observation,
            conflicting_alias_positions,
            valid,
        }
    }
}

impl ReplyEvidence {
    fn unavailable_reason(&self) -> Option<String> {
        let Some(expected) = self.expected_wkc else {
            return Some(
                "FMMU station evidence is incomplete or invalid for LRD contribution review".into(),
            );
        };
        if expected == 0 {
            return Some("no active FMMU read mappings intersect the LRD window".into());
        }
        if let Some(declared) = self
            .contributors
            .as_ref()
            .and_then(|contributors| contributors.declared_expected_wkc)
            && declared != expected
        {
            return Some(format!(
                "declared LRD Working Counter {declared} differs from the FMMU expectation {expected}"
            ));
        }
        if !self.wkc_matches {
            return Some(format!(
                "LRD Working Counter mismatch (expected {expected}, received {})",
                self.actual_wkc
            ));
        }
        if let Some(al) = &self.station_al
            && !al.clean_safeop
        {
            return Some(match &al.status {
                Some(status) => format!(
                    "AL read did not report clean SAFEOP (state {}, status {:#06x}, code {:#06x})",
                    status.state, status.raw, status.code
                ),
                None => format!(
                    "AL Working Counter mismatch (expected {}, received {})",
                    al.expected_wkc, al.actual_wkc
                ),
            });
        }
        if let Some(topology) = &self.topology
            && !topology.valid
        {
            return Some(if !topology.observation.valid {
                "same-frame topology did not confirm the FMMU station count and order".into()
            } else {
                format!(
                    "selected station address also appears as a configured alias at positions {:?}",
                    topology.conflicting_alias_positions
                )
            });
        }
        None
    }
}

#[derive(Serialize)]
pub(super) struct Evidence {
    file_name: String,
    sha256: String,
    source: &'static str,
    station_address: u16,
    logical_start: u32,
    byte_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    lrd_reply: Option<ReplyEvidence>,
}

impl Evidence {
    fn new(
        path: &Path,
        bytes: &[u8],
        station_address: u16,
        logical_start: u32,
        byte_count: usize,
        lrd_reply: Option<ReplyEvidence>,
    ) -> Result<Self> {
        let source = if lrd_reply.is_some() {
            "saved_lrd_reply"
        } else {
            "supplied_logical_bytes"
        };
        Ok(Self {
            file_name: path
                .file_name()
                .context("logical payload evidence has no file name")?
                .to_string_lossy()
                .into_owned(),
            sha256: hex::encode(Sha256::digest(bytes)),
            source,
            station_address,
            logical_start,
            byte_count,
            lrd_reply,
        })
    }
}

pub(super) struct Window {
    pub(super) evidence: Evidence,
    data: Vec<u8>,
}

impl Window {
    pub(super) fn load(path: &Path, station: u16) -> Result<Self> {
        let (saved, bytes) = read_json::<SavedWindow>(path, MAX_FILE_BYTES)?;
        ensure!(
            saved.schema == 1,
            "unsupported logical payload schema {}",
            saved.schema
        );
        ensure!(
            saved.station_address == station,
            "logical payload station {:#06x} differs from selected FMMU station {station:#06x}",
            saved.station_address,
        );
        let data = payload_hex(&saved.payload_hex).context("decode saved logical payload")?;
        validate_window(saved.logical_start, data.len())?;
        Ok(Self {
            evidence: Evidence::new(
                path,
                &bytes,
                saved.station_address,
                saved.logical_start,
                data.len(),
                None,
            )?,
            data,
        })
    }

    pub(super) fn load_reply(path: &Path, table: &Table) -> Result<Self> {
        let station = table.evidence.station_address;
        let stations = &table.stations;
        let (saved, bytes) = read_json::<SavedReply>(path, MAX_FILE_BYTES)?;
        ensure!(
            matches!(saved.schema, 1..=4),
            "unsupported saved LRD reply schema {}",
            saved.schema
        );
        ensure!(
            saved.station_address == station,
            "LRD reply station {:#06x} differs from selected FMMU station {station:#06x}",
            saved.station_address,
        );
        ensure!(
            saved.schema == 4 || saved.expected_wkc.is_some(),
            "expected LRD Working Counter is required for schema 1 through 3"
        );
        ensure!(
            saved.expected_wkc != Some(0),
            "expected LRD Working Counter must be nonzero"
        );
        validate_window(saved.logical_start, saved.byte_count)?;
        let reply = decode_frame_hex(&saved.reply_hex).context("decode saved LRD reply frame")?;
        let expects_al = saved.schema >= 2;
        let expects_topology = saved.schema >= 3;
        let mut used = if expects_al { 2 } else { 1 };
        let inputs = input_datagrams(station, saved.byte_count);
        let mut parts = [inputs[0]; MAX_DATAGRAMS];
        parts[..2].copy_from_slice(&inputs);
        parts[0].address = saved.logical_start.to_le_bytes();
        if expects_topology {
            topology::fill_probe(&mut parts[2..], stations.len());
            used += 1 + stations.len();
        }
        let encoded_len = Frame::<MAX_DATAGRAMS>::encoded_len(&parts[..used]);
        ensure!(
            encoded_len <= MAX_FRAME_BYTES,
            "expected LRD frame exceeds {MAX_FRAME_BYTES} bytes"
        );
        let frame = Frame::with_count(saved.index, parts, used);
        let observed = frame.reply(&reply).context(match saved.schema {
            1 => "saved frame does not match the expected Workbench LRD reply",
            2 => "saved frame does not match the expected Workbench LRD and AL reply",
            _ => "saved frame does not match the expected Workbench LRD, AL and topology reply",
        })?;
        ensure!(
            reply.len() == encoded_len || reply.len() == frame.bytes().len(),
            "saved LRD reply has trailing bytes beyond the expected Ethernet frame",
        );
        let (payload, actual_wkc) = observed[0];
        let station_al =
            expects_al.then(|| AlRead::from_datagram(station, observed[1].0, observed[1].1));
        let topology = if expects_topology {
            let observation = topology::decode_reading(
                &reply[frame.datagram_offset(2)..],
                &observed[2..used],
                stations,
            )?;
            Some(TopologyEvidence::new(observation, station))
        } else {
            None
        };
        let contributors = (saved.schema == 4).then(|| {
            table.contributions(saved.logical_start, saved.byte_count, saved.expected_wkc)
        });
        let expected_wkc = match &contributors {
            Some(contributors) => contributors.derived_expected_wkc,
            None => saved.expected_wkc,
        };
        let evidence = ReplyEvidence {
            frame_sha256: hex::encode(Sha256::digest(&reply)),
            index: saved.index,
            expected_wkc,
            actual_wkc,
            wkc_matches: expected_wkc == Some(actual_wkc),
            station_al,
            topology,
            contributors,
        };
        let usable = evidence.unavailable_reason().is_none();
        Ok(Self {
            evidence: Evidence::new(
                path,
                &bytes,
                saved.station_address,
                saved.logical_start,
                saved.byte_count,
                Some(evidence),
            )?,
            data: if usable { payload.to_vec() } else { Vec::new() },
        })
    }

    pub(super) fn sample(&self, check: &Check, requested: Range<usize>) -> Sample {
        if let Some(reason) = self
            .evidence
            .lrd_reply
            .as_ref()
            .and_then(ReplyEvidence::unavailable_reason)
        {
            return Sample::Unavailable { reason };
        }
        let data = match check {
            Check::Matched {
                logical_start,
                byte_count,
                ..
            } => self.extract(
                once((0, u64::from(*logical_start) * 8, *byte_count * 8)),
                requested,
            ),
            Check::MatchedSplit { segments, .. } => self.extract(
                segments.iter().map(|segment| {
                    (
                        segment.projection_byte_offset * 8,
                        u64::from(segment.logical_start) * 8,
                        segment.byte_count * 8,
                    )
                }),
                requested,
            ),
            Check::MatchedBits { segments, .. } => self.extract(
                segments.iter().map(|segment| {
                    (
                        segment.projection_bit_offset,
                        segment.logical_start_bit,
                        segment.bit_count,
                    )
                }),
                requested,
            ),
            Check::Unmapped { reason }
            | Check::Conflict { reason }
            | Check::Unavailable { reason } => {
                return Sample::Unavailable {
                    reason: format!("FMMU placement unavailable ({reason})"),
                };
            }
        };

        match data {
            Ok(bytes) => Sample::Available {
                raw_hex: hex::encode_upper(bytes),
            },
            Err(error) => Sample::Unavailable {
                reason: error.to_string(),
            },
        }
    }

    fn extract(
        &self,
        segments: impl IntoIterator<Item = (usize, u64, usize)>,
        requested: Range<usize>,
    ) -> Result<Vec<u8>> {
        let mut data = vec![0; requested.len().div_ceil(8)];
        let mut next = requested.start;
        let window_start = u64::from(self.evidence.logical_start) * 8;
        let window_end = window_start + self.data.len() as u64 * 8;
        for (offset, logical_start, bit_count) in segments {
            let start = offset.max(requested.start);
            let end = (offset + bit_count).min(requested.end);
            if start >= end {
                continue;
            }
            ensure!(
                start == next,
                "FMMU placement did not cover the requested bytes"
            );
            let logical_start = logical_start + (start - offset) as u64;
            let logical = logical_start..logical_start + (end - start) as u64;
            ensure!(
                logical.start >= window_start && logical.end <= window_end,
                "logical bytes {:#010x}..{:#010x} are outside the supplied payload",
                logical.start / 8,
                logical.end.div_ceil(8),
            );
            if let Some(station) = self
                .evidence
                .lrd_reply
                .as_ref()
                .and_then(|reply| reply.contributors.as_ref())
                .and_then(|contributors| {
                    contributors.other_reader(self.evidence.station_address, &logical)
                })
            {
                anyhow::bail!(
                    "station {station:#06x} also has an active read mapping in the requested logical range"
                );
            }
            copy_bits(
                &self.data,
                (logical.start - window_start) as usize,
                &mut data,
                start - requested.start,
                end - start,
            );
            next = end;
        }
        ensure!(
            next == requested.end,
            "FMMU placement did not cover the requested bytes"
        );
        Ok(data)
    }
}

fn validate_window(logical_start: u32, byte_count: usize) -> Result<()> {
    ensure!(
        byte_count != 0,
        "logical payload must contain at least one byte"
    );
    ensure!(
        byte_count <= MAX_PAYLOAD,
        "payload exceeds {MAX_PAYLOAD} bytes"
    );
    ensure!(
        u64::from(logical_start) + byte_count as u64 <= LOGICAL_ADDRESS_END,
        "logical payload extends beyond the 32-bit logical address space",
    );
    Ok(())
}

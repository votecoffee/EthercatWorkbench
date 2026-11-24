//! Extract register bytes from an explicitly addressed saved logical payload.
use super::{Sample, fmmu::Check};
use crate::{
    input_group::{AlRead, decode_frame_hex, read_json},
    model::{MAX_PAYLOAD, payload_hex},
    wire::{Frame, input_datagrams},
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
    expected_wkc: u16,
    reply_hex: String,
}

#[derive(Serialize)]
struct ReplyEvidence {
    frame_sha256: String,
    index: u8,
    expected_wkc: u16,
    actual_wkc: u16,
    wkc_matches: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    station_al: Option<AlRead>,
}

impl ReplyEvidence {
    fn unavailable_reason(&self) -> Option<String> {
        if !self.wkc_matches {
            return Some(format!(
                "LRD Working Counter mismatch (expected {}, received {})",
                self.expected_wkc, self.actual_wkc
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

    pub(super) fn load_reply(path: &Path, station: u16) -> Result<Self> {
        let (saved, bytes) = read_json::<SavedReply>(path, MAX_FILE_BYTES)?;
        ensure!(
            matches!(saved.schema, 1 | 2),
            "unsupported saved LRD reply schema {}",
            saved.schema
        );
        ensure!(
            saved.station_address == station,
            "LRD reply station {:#06x} differs from selected FMMU station {station:#06x}",
            saved.station_address,
        );
        ensure!(
            saved.expected_wkc != 0,
            "expected LRD Working Counter must be nonzero"
        );
        validate_window(saved.logical_start, saved.byte_count)?;
        let reply = decode_frame_hex(&saved.reply_hex).context("decode saved LRD reply frame")?;
        let expects_al = saved.schema == 2;
        let used = if expects_al { 2 } else { 1 };
        let mut parts = input_datagrams(station, saved.byte_count);
        parts[0].address = saved.logical_start.to_le_bytes();
        let frame = Frame::with_count(saved.index, parts, used);
        let [(payload, actual_wkc), (al_bytes, al_wkc)] =
            frame.reply(&reply).context(if expects_al {
                "saved frame does not match the expected Workbench LRD and AL reply"
            } else {
                "saved frame does not match the expected Workbench LRD reply"
            })?;
        ensure!(
            reply.len() == Frame::<2>::encoded_len(&parts[..used])
                || reply.len() == frame.bytes().len(),
            "saved LRD reply has trailing bytes beyond the expected Ethernet frame",
        );
        let station_al = expects_al.then(|| AlRead::from_datagram(station, al_bytes, al_wkc));
        let wkc_matches = actual_wkc == saved.expected_wkc;
        let usable = wkc_matches && station_al.as_ref().is_none_or(|al| al.clean_safeop);
        Ok(Self {
            evidence: Evidence::new(
                path,
                &bytes,
                saved.station_address,
                saved.logical_start,
                saved.byte_count,
                Some(ReplyEvidence {
                    frame_sha256: hex::encode(Sha256::digest(&reply)),
                    index: saved.index,
                    expected_wkc: saved.expected_wkc,
                    actual_wkc,
                    wkc_matches,
                    station_al,
                }),
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
            } => self.extract(once((0, *logical_start, *byte_count)), requested),
            Check::MatchedSplit { segments, .. } => self.extract(
                segments.iter().map(|segment| {
                    (
                        segment.projection_byte_offset,
                        segment.logical_start,
                        segment.byte_count,
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
        segments: impl IntoIterator<Item = (usize, u32, usize)>,
        requested: Range<usize>,
    ) -> Result<Vec<u8>> {
        let mut data = Vec::with_capacity(requested.len());
        let window_start = u64::from(self.evidence.logical_start);
        let window_end = window_start + self.data.len() as u64;
        for (offset, logical_start, byte_count) in segments {
            let start = offset.max(requested.start);
            let end = (offset + byte_count).min(requested.end);
            if start >= end {
                continue;
            }
            let logical_start = u64::from(logical_start) + (start - offset) as u64;
            let logical_end = logical_start + (end - start) as u64;
            ensure!(
                logical_start >= window_start && logical_end <= window_end,
                "logical bytes {logical_start:#010x}..{logical_end:#010x} are outside the supplied payload",
            );
            data.extend_from_slice(
                &self.data[(logical_start - window_start) as usize
                    ..(logical_end - window_start) as usize],
            );
        }
        ensure!(
            data.len() == requested.len(),
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

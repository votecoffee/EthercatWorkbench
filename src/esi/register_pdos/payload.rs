//! Extract register bytes from an explicitly addressed saved logical payload.
use super::{Sample, fmmu::Check};
use crate::{input_group::read_json, model::payload_hex};
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

#[derive(Serialize)]
pub(super) struct Evidence {
    file_name: String,
    sha256: String,
    source: &'static str,
    station_address: u16,
    logical_start: u32,
    byte_count: usize,
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
        ensure!(
            !data.is_empty(),
            "logical payload must contain at least one byte"
        );
        ensure!(
            u64::from(saved.logical_start) + data.len() as u64 <= LOGICAL_ADDRESS_END,
            "logical payload extends beyond the 32-bit logical address space",
        );
        Ok(Self {
            evidence: Evidence {
                file_name: path
                    .file_name()
                    .context("logical payload has no file name")?
                    .to_string_lossy()
                    .into_owned(),
                sha256: hex::encode(Sha256::digest(&bytes)),
                source: "supplied_logical_bytes",
                station_address: saved.station_address,
                logical_start: saved.logical_start,
                byte_count: data.len(),
            },
            data,
        })
    }

    pub(super) fn sample(&self, check: &Check, requested: Range<usize>) -> Sample {
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

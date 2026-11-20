//! Offline planning and decoding for a byte-aligned, input-only logical read.
pub mod audit;
pub mod bundle;
pub mod clock_rehearsal;
pub(crate) mod fmmu;
mod pdo_readback;
pub mod preflight;
pub mod replay;
pub(crate) mod sync_manager;

use crate::{
    esc::{AlStatus, al_status, clean_safeop},
    model::{Identity, MAX_PAYLOAD, Profile, Source},
    wire::{Datagram, FPRD, Frame, LRD, MAX_FRAME_BYTES, al_readback},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    path::{Component, Path, PathBuf},
};

const MAX_DEVICES: usize = 16;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_PROFILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_FRAME_FILE_BYTES: u64 = 16 * 1024;
const MAX_DATAGRAMS: usize = MAX_DEVICES + 1;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    devices: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    position: usize,
    profile: PathBuf,
    identity: Identity,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FrameSample {
    schema: u32,
    index: u8,
    stations: Vec<u16>,
    reply_hex: String,
}

struct Binding {
    entry: Entry,
    profile: Profile,
    profile_file: PathBuf,
    profile_sha256: String,
    offset: Option<usize>,
}

pub struct InputGroup {
    bindings: Vec<Binding>,
    manifest_sha256: String,
    input_bytes: usize,
    expected_wkc: u16,
}

pub(crate) struct MappingReview {
    fmmu: fmmu::Review,
    sync_managers: Option<sync_manager::Review>,
    pdo: Option<pdo_readback::Review>,
    topology: Option<preflight::topology::Check>,
}

impl MappingReview {
    fn compare_stations(&mut self, stations: &[u16]) {
        self.fmmu.compare_stations(stations);
    }

    fn valid(&self) -> bool {
        self.fmmu.valid
            && self.sync_managers.as_ref().is_none_or(|sync| sync.valid)
            && self.pdo.as_ref().is_none_or(|pdo| pdo.valid)
            && self.topology.as_ref().is_none_or(|topology| topology.valid)
    }

    fn attach(self, inspection: &mut Inspection<'_>) {
        inspection.fmmu = Some(self.fmmu);
        inspection.sync_managers = self.sync_managers;
        inspection.pdo = self.pdo;
        inspection.topology = self.topology;
    }
}

#[derive(Serialize)]
pub struct Inspection<'a> {
    schema: u32,
    source: &'static str,
    logical_start: u32,
    pub(crate) input_bytes: usize,
    pub(crate) expected_wkc: u16,
    actual_wkc: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) frame: Option<FrameCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fmmu: Option<fmmu::Review>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sync_managers: Option<sync_manager::Review>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pdo: Option<pdo_readback::Review>,
    #[serde(skip_serializing_if = "Option::is_none")]
    topology: Option<preflight::topology::Check>,
    pub(crate) devices: Vec<Device<'a>>,
}

#[derive(Serialize)]
pub(crate) struct FrameCheck {
    index: u8,
    reply_sha256: String,
    pub(crate) lrd_wkc_matches: bool,
    pub(crate) valid: bool,
}

#[derive(Serialize)]
pub(crate) struct Device<'a> {
    position: usize,
    identity: &'a Identity,
    profile: &'a Path,
    profile_sha256: &'a str,
    name: &'a str,
    pub(crate) offset: Option<usize>,
    pub(crate) tx_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) al: Option<AlRead>,
    pub(crate) input: Option<DecodedInput<'a>>,
}

#[derive(Debug, Serialize)]
pub struct AlRead {
    pub station_address: u16,
    expected_wkc: u16,
    pub actual_wkc: u16,
    pub clean_safeop: bool,
    pub status: Option<AlStatus>,
}

#[derive(Serialize)]
pub(crate) struct DecodedInput<'a> {
    pub(crate) raw_hex: String,
    fields: Vec<FieldValue<'a>>,
}

#[derive(Serialize)]
struct FieldValue<'a> {
    field: &'a str,
    bit: usize,
    width: usize,
    source: &'a Source,
    value: Option<String>,
}

impl InputGroup {
    pub fn load(path: &Path) -> Result<Self> {
        Self::load_profiles(path, None)
    }

    fn load_profiles(path: &Path, bundled: Option<&[PathBuf]>) -> Result<Self> {
        let path = std::path::absolute(path).context("resolve input group path")?;
        let parent = path.parent().context("input group needs a file name")?;
        let (manifest, bytes) = read_json::<Manifest>(&path, MAX_MANIFEST_BYTES)?;
        let manifest_sha256 = hex::encode(Sha256::digest(&bytes));
        ensure!(
            manifest.schema == 1,
            "unsupported input group schema {}",
            manifest.schema
        );
        ensure!(
            (1..=MAX_DEVICES).contains(&manifest.devices.len()),
            "input group requires 1–{MAX_DEVICES} device positions"
        );
        ensure!(
            bundled.is_none_or(|profiles| profiles.len() == manifest.devices.len()),
            "bundled profile count differs from the manifest"
        );
        let mut bindings = Vec::with_capacity(manifest.devices.len());
        let mut input_bytes = 0;
        let mut expected_wkc = 0;
        for (position, entry) in manifest.devices.into_iter().enumerate() {
            ensure!(
                entry.position == position,
                "expected position {position} in bus order, got {}",
                entry.position
            );
            ensure!(
                !entry.profile.as_os_str().is_empty()
                    && (entry.profile.is_absolute()
                        || (!entry.profile.has_root()
                            && !matches!(
                                entry.profile.components().next(),
                                Some(Component::Prefix(_))
                            ))),
                "position {position} needs an absolute or group-relative profile path"
            );
            let profile_file = bundled.map_or_else(
                || parent.join(&entry.profile),
                |profiles| profiles[position].clone(),
            );
            let (profile, bytes) = read_json::<Profile>(&profile_file, MAX_PROFILE_BYTES)
                .with_context(|| format!("load profile for position {position}"))?;
            profile
                .validate()
                .with_context(|| format!("validate profile for position {position}"))?;
            ensure!(
                profile.expected_identity.as_ref() == Some(&entry.identity),
                "position {position} profile must carry the exact group identity {}",
                entry.identity
            );
            let offset = (profile.tx_bytes != 0).then_some(input_bytes);
            input_bytes += profile.tx_bytes;
            ensure!(
                input_bytes <= MAX_PAYLOAD,
                "group input exceeds {MAX_PAYLOAD} bytes at position {position}"
            );
            expected_wkc += u16::from(offset.is_some());
            bindings.push(Binding {
                entry,
                profile,
                profile_file,
                profile_sha256: hex::encode(Sha256::digest(&bytes)),
                offset,
            });
        }
        ensure!(
            input_bytes != 0,
            "input group needs at least one nonempty TxPDO image"
        );
        Ok(Self {
            bindings,
            manifest_sha256,
            input_bytes,
            expected_wkc,
        })
    }

    pub fn inspect(&self, sample: Option<(&[u8], u16)>) -> Result<Inspection<'_>> {
        if let Some((payload, wkc)) = sample {
            ensure!(
                payload.len() == self.input_bytes,
                "expected {} group input bytes, got {}",
                self.input_bytes,
                payload.len()
            );
            ensure!(
                wkc == self.expected_wkc,
                "group LRD Working Counter {wkc}, expected {}; payload decoding withheld",
                self.expected_wkc
            );
        }
        Ok(self.inspection(
            sample.map(|(payload, _)| payload),
            sample.map(|(_, wkc)| wkc),
        ))
    }

    pub fn inspect_frame_file(&self, path: &Path) -> Result<Inspection<'_>> {
        self.inspect_saved_frame(path, None)
    }

    pub fn inspect_fmmu_file(&self, path: &Path, frame: Option<&Path>) -> Result<Inspection<'_>> {
        self.inspect_mapping_files(path, None, frame)
    }

    pub fn inspect_mapping_files(
        &self,
        fmmu: &Path,
        sync_managers: Option<&Path>,
        frame: Option<&Path>,
    ) -> Result<Inspection<'_>> {
        self.inspect_input_evidence(fmmu, sync_managers, None, frame)
    }

    pub fn inspect_pdo_file(
        &self,
        fmmu: &Path,
        sync_managers: &Path,
        pdo: &Path,
        frame: Option<&Path>,
    ) -> Result<Inspection<'_>> {
        self.inspect_input_evidence(fmmu, Some(sync_managers), Some(pdo), frame)
    }

    fn inspect_input_evidence(
        &self,
        fmmu: &Path,
        sync_managers: Option<&Path>,
        pdo: Option<&Path>,
        frame: Option<&Path>,
    ) -> Result<Inspection<'_>> {
        let mapping = self.load_mapping_evidence(fmmu, sync_managers, pdo)?;
        if let Some(frame) = frame {
            return self.inspect_saved_frame(frame, Some(mapping));
        }
        let mut inspection = self.inspection(None, None);
        mapping.attach(&mut inspection);
        Ok(inspection)
    }

    fn load_mapping_evidence(
        &self,
        fmmu: &Path,
        sync_managers: Option<&Path>,
        pdo: Option<&Path>,
    ) -> Result<MappingReview> {
        let fmmu = fmmu::review(fmmu, &self.bindings)?;
        let sync_managers = sync_managers
            .map(|path| sync_manager::review(path, &fmmu))
            .transpose()?;
        let pdo = pdo
            .map(|path| {
                pdo_readback::review(
                    path,
                    &self.bindings,
                    &fmmu,
                    sync_managers
                        .as_ref()
                        .context("TxPDO review needs SyncManager evidence")?,
                )
            })
            .transpose()?;
        Ok(MappingReview {
            fmmu,
            sync_managers,
            pdo,
            topology: None,
        })
    }

    fn inspect_saved_frame(
        &self,
        path: &Path,
        mapping: Option<MappingReview>,
    ) -> Result<Inspection<'_>> {
        let (sample, _) = read_json::<FrameSample>(path, MAX_FRAME_FILE_BYTES)?;
        ensure!(
            sample.schema == 1,
            "unsupported group frame schema {}",
            sample.schema
        );
        let reply = decode_frame_hex(&sample.reply_hex)?;
        self.inspect_reply(sample.index, &sample.stations, &reply, mapping)
    }

    pub(crate) fn expected_frame(
        &self,
        index: u8,
        stations: &[u16],
    ) -> Result<Frame<MAX_DATAGRAMS>> {
        validate_stations(stations, self.bindings.len())?;
        let mut parts = [Datagram::register(LRD, 0, 0, self.input_bytes); MAX_DATAGRAMS];
        for (position, &station) in stations.iter().enumerate() {
            parts[position + 1] = Datagram::register(FPRD, station, 0x0130, 6);
        }
        Ok(Frame::with_count(index, parts, 1 + stations.len()))
    }

    pub(crate) fn inspect_reply(
        &self,
        index: u8,
        stations: &[u16],
        reply: &[u8],
        mut mapping: Option<MappingReview>,
    ) -> Result<Inspection<'_>> {
        ensure!(
            reply.len() <= MAX_FRAME_BYTES,
            "frame exceeds {MAX_FRAME_BYTES} bytes"
        );
        let frame = self.expected_frame(index, stations)?;
        let parts = frame
            .reply(reply)
            .context("frame does not match the expected grouped LRD and ordered AL reads")?;
        let (payload, wkc) = parts[0];
        let al_reads = decode_al_reads(stations, &parts[1..]);
        let lrd_wkc_matches = wkc == self.expected_wkc;
        let valid = lrd_wkc_matches && al_reads.iter().all(|al| al.clean_safeop);
        if let Some(review) = &mut mapping {
            review.compare_stations(stations);
        }
        let usable = valid && mapping.as_ref().is_none_or(MappingReview::valid);
        let mut inspection = self.inspection(usable.then_some(payload), Some(wkc));
        inspection.frame = Some(FrameCheck {
            index,
            reply_sha256: hex::encode(Sha256::digest(reply)),
            lrd_wkc_matches,
            valid,
        });
        if let Some(review) = mapping {
            review.attach(&mut inspection);
        }
        for (device, al) in inspection.devices.iter_mut().zip(al_reads) {
            device.al = Some(al);
        }
        Ok(inspection)
    }

    fn inspection(&self, payload: Option<&[u8]>, actual_wkc: Option<u16>) -> Inspection<'_> {
        let devices = self
            .bindings
            .iter()
            .map(|binding| {
                let profile = &binding.profile;
                let input = payload.zip(binding.offset).map(|(payload, offset)| {
                    let bytes = &payload[offset..offset + profile.tx_bytes];
                    DecodedInput {
                        raw_hex: hex::encode(bytes),
                        fields: profile
                            .tx
                            .iter()
                            .map(|field| FieldValue {
                                field: &field.name,
                                bit: field.bit,
                                width: field.width,
                                source: &field.source,
                                value: field.decode(bytes),
                            })
                            .collect(),
                    }
                });
                Device {
                    position: binding.entry.position,
                    identity: &binding.entry.identity,
                    profile: &binding.entry.profile,
                    profile_sha256: &binding.profile_sha256,
                    name: &profile.name,
                    offset: binding.offset,
                    tx_bytes: profile.tx_bytes,
                    al: None,
                    input,
                }
            })
            .collect();
        Inspection {
            schema: 1,
            source: "offline_profiles",
            logical_start: 0,
            input_bytes: self.input_bytes,
            expected_wkc: self.expected_wkc,
            actual_wkc,
            frame: None,
            fmmu: None,
            sync_managers: None,
            pdo: None,
            topology: None,
            devices,
        }
    }
}

fn decode_frame_hex(text: &str) -> Result<Vec<u8>> {
    let hex: String = text
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .take(MAX_FRAME_BYTES * 2 + 1)
        .collect();
    ensure!(
        hex.len() <= MAX_FRAME_BYTES * 2,
        "frame exceeds {MAX_FRAME_BYTES} bytes"
    );
    hex::decode(hex).context("group frame reply must contain hex byte pairs")
}

fn decode_al_reads(stations: &[u16], parts: &[(&[u8], u16)]) -> Vec<AlRead> {
    stations
        .iter()
        .zip(parts)
        .map(|(&station, &(bytes, status_wkc))| {
            let raw = al_readback(bytes, status_wkc);
            AlRead {
                station_address: station,
                expected_wkc: 1,
                actual_wkc: status_wkc,
                clean_safeop: raw.is_some_and(|(status, code)| clean_safeop(status, code)),
                status: raw.map(|(status, code)| al_status(status, code)),
            }
        })
        .collect()
}

fn validate_stations(stations: &[u16], expected: usize) -> Result<()> {
    ensure!(
        stations.len() == expected,
        "expected one station address per position ({expected}), got {}",
        stations.len()
    );
    for (position, &station) in stations.iter().enumerate() {
        ensure!(
            station != 0,
            "station address at position {position} must be nonzero"
        );
        ensure!(
            !stations[..position].contains(&station),
            "duplicate station address {station:#06x}"
        );
    }
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &Path, max_bytes: u64) -> Result<(T, Vec<u8>)> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("open {}", path.display()))?
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= max_bytes,
        "{} exceeds {max_bytes} bytes",
        path.display()
    );
    let value = serde_json::from_slice(bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes))
        .with_context(|| format!("parse {}", path.display()))?;
    Ok((value, bytes))
}

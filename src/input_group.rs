//! Offline planning and decoding for a byte-aligned, input-only logical read.
use crate::model::{Identity, MAX_PAYLOAD, Profile, Source};
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

struct Binding {
    entry: Entry,
    profile: Profile,
    profile_sha256: String,
    offset: Option<usize>,
}

pub struct InputGroup {
    bindings: Vec<Binding>,
    input_bytes: usize,
    expected_wkc: u16,
}

#[derive(Serialize)]
pub struct Inspection<'a> {
    schema: u32,
    source: &'static str,
    logical_start: u32,
    pub(crate) input_bytes: usize,
    pub(crate) expected_wkc: u16,
    actual_wkc: Option<u16>,
    pub(crate) devices: Vec<Device<'a>>,
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
    pub(crate) input: Option<DecodedInput<'a>>,
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
        let path = std::path::absolute(path).context("resolve input group path")?;
        let parent = path.parent().context("input group needs a file name")?;
        let (manifest, _) = read_json::<Manifest>(&path, MAX_MANIFEST_BYTES)?;
        ensure!(
            manifest.schema == 1,
            "unsupported input group schema {}",
            manifest.schema
        );
        ensure!(
            (1..=MAX_DEVICES).contains(&manifest.devices.len()),
            "input group requires 1–{MAX_DEVICES} device positions"
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
            let (profile, bytes) =
                read_json::<Profile>(&parent.join(&entry.profile), MAX_PROFILE_BYTES)
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
        let devices = self
            .bindings
            .iter()
            .map(|binding| {
                let profile = &binding.profile;
                let input = sample.zip(binding.offset).map(|((payload, _), offset)| {
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
                    input,
                }
            })
            .collect();
        Ok(Inspection {
            schema: 1,
            source: "offline_profiles",
            logical_start: 0,
            input_bytes: self.input_bytes,
            expected_wkc: self.expected_wkc,
            actual_wkc: sample.map(|(_, wkc)| wkc),
            devices,
        })
    }
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

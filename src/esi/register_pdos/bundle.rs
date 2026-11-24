//! Preserve and recheck the original evidence for an offline register decoder.
use super::{LayoutSource, LogicalSource, audit::SavedProfile, preview_with_layout};
use crate::{
    comparison_bundle::{copy_checked, json_bytes, require_entry, write_new},
    input_group::read_json,
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

const COMPLETION: &str = "bundle.json";
const PROFILE: &str = "profile.json";
const ESI: &str = "device.esi.xml";
const FMMU: &str = "fmmu.json";
const REPLY: &str = "lrd-reply.json";
const LAYOUT: &str = "register-layout.json";
const MAX_RECEIPT_BYTES: u64 = 16 * 1024;

pub struct Sources<'a> {
    pub profile: &'a Path,
    pub esi: &'a Path,
    pub fmmu: &'a Path,
    pub lrd_reply: &'a Path,
    pub register_layout: Option<&'a Path>,
    pub device_index: Option<usize>,
}

impl<'a> Sources<'a> {
    fn paths(&self) -> impl Iterator<Item = &'a Path> {
        [
            Some(self.profile),
            Some(self.esi),
            Some(self.fmmu),
            Some(self.lrd_reply),
            self.register_layout,
        ]
        .into_iter()
        .flatten()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Stamp {
    bytes: u64,
    sha256: String,
}

impl Stamp {
    fn observed(file: &Path, sha256: &str) -> Result<Self> {
        Ok(Self {
            bytes: fs::metadata(file)
                .with_context(|| format!("inspect {}", file.display()))?
                .len(),
            sha256: sha256.into(),
        })
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    schema: u32,
    scope: String,
    device_index: Option<usize>,
    profile: Stamp,
    esi: Stamp,
    fmmu: Stamp,
    lrd_reply: Stamp,
    register_layout: Option<Stamp>,
}

impl Receipt {
    fn entries(&self) -> impl Iterator<Item = (&'static str, &Stamp)> {
        [
            (PROFILE, Some(&self.profile)),
            (ESI, Some(&self.esi)),
            (FMMU, Some(&self.fmmu)),
            (REPLY, Some(&self.lrd_reply)),
            (LAYOUT, self.register_layout.as_ref()),
        ]
        .into_iter()
        .filter_map(|(name, stamp)| stamp.map(|stamp| (name, stamp)))
    }
}

#[derive(Serialize)]
pub struct VerifiedBundle {
    directory: PathBuf,
    receipt_sha256: String,
    receipt: Receipt,
    verification: super::DecoderVerification,
}

pub fn create(sources: Sources<'_>, output: &Path) -> Result<Receipt> {
    let root = std::path::absolute(output).context("resolve register decoder bundle directory")?;
    match fs::symlink_metadata(&root) {
        Ok(_) => bail!("bundle destination already exists: {}", root.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect bundle destination"),
    }
    let (receipt, _) = check_sources(&sources)?;
    fs::create_dir(&root)
        .with_context(|| format!("create new bundle directory {}", root.display()))?;
    (|| -> Result<()> {
        let stop = AtomicBool::new(false);
        for (source, (name, stamp)) in sources.paths().zip(receipt.entries()) {
            copy_checked(source, &root.join(name), stamp.bytes, &stamp.sha256, &stop)
                .with_context(|| format!("archive {name}"))?;
        }
        write_new(&root.join(COMPLETION), &json_bytes(&receipt)?)
    })()
    .with_context(|| {
        format!(
            "register decoder bundle did not complete in {}",
            root.display()
        )
    })?;
    Ok(receipt)
}

pub fn verify(directory: &Path) -> Result<VerifiedBundle> {
    let directory =
        std::path::absolute(directory).context("resolve register decoder bundle directory")?;
    require_entry(&directory, true)?;
    let manifest = directory.join(COMPLETION);
    require_entry(&manifest, false)?;
    let (receipt, bytes): (Receipt, _) = read_json(&manifest, MAX_RECEIPT_BYTES)?;
    ensure!(
        receipt.schema == 1 && receipt.scope == "saved_register_decoder_bundle",
        "expected a schema 1 register decoder bundle"
    );
    for (name, stamp) in receipt.entries() {
        let file = directory.join(name);
        require_entry(&file, false)?;
        ensure!(
            fs::metadata(file)?.len() == stamp.bytes,
            "bundle size differs for {name}"
        );
    }
    let layout = directory.join(LAYOUT);
    let sources = Sources {
        profile: &directory.join(PROFILE),
        esi: &directory.join(ESI),
        fmmu: &directory.join(FMMU),
        lrd_reply: &directory.join(REPLY),
        register_layout: receipt.register_layout.as_ref().map(|_| layout.as_path()),
        device_index: receipt.device_index,
    };
    let (observed, verification) = check_sources(&sources)?;
    ensure!(
        receipt == observed,
        "bundle SHA-256 or file length differs from reconstructed evidence"
    );
    Ok(VerifiedBundle {
        directory,
        receipt_sha256: hex::encode(Sha256::digest(bytes)),
        receipt,
        verification,
    })
}

fn check_sources(sources: &Sources<'_>) -> Result<(Receipt, super::DecoderVerification)> {
    for file in sources.paths() {
        require_entry(file, false)?;
    }
    let saved = SavedProfile::load(sources.profile)?;
    let provenance = saved
        .profile
        .register_decoder
        .as_ref()
        .context("profile has no register decoder provenance")?;
    let starts: Vec<_> = provenance
        .pdo_index
        .zip(provenance.manual_start_bit)
        .into_iter()
        .chain(
            provenance
                .pdos
                .iter()
                .filter_map(|pdo| pdo.manual_start_bit.map(|bit| (pdo.pdo_index, bit))),
        )
        .collect();
    let layout = match sources.register_layout {
        Some(path) => {
            ensure!(
                starts.is_empty(),
                "register decoder uses manual start bits; supply its ESI without a layout file"
            );
            LayoutSource::File(path)
        }
        None => LayoutSource::StartBits(&starts),
    };
    let review = preview_with_layout(
        sources.esi,
        sources.device_index,
        saved.profile.expected_identity.as_ref(),
        None,
        Some((sources.fmmu, provenance.station_address)),
        Some(LogicalSource::LrdReply(sources.lrd_reply)),
        layout,
    )?;
    let verification = review.verify_loaded_profile(&saved)?;
    verification
        .require_verified()
        .context("verify register decoder evidence")?;
    let register_layout = sources
        .register_layout
        .map(|file| {
            let source = review
                .manual_register_layout
                .as_ref()
                .context("layout provenance is unavailable")?;
            Stamp::observed(file, &source.sha256)
        })
        .transpose()?;
    let receipt = Receipt {
        schema: 1,
        scope: "saved_register_decoder_bundle".into(),
        device_index: sources.device_index,
        profile: Stamp::observed(sources.profile, &saved.sha256)?,
        esi: Stamp::observed(sources.esi, &review.esi_sha256)?,
        fmmu: Stamp::observed(
            sources.fmmu,
            &review
                .fmmu
                .as_ref()
                .context("FMMU evidence is unavailable")?
                .sha256,
        )?,
        lrd_reply: Stamp::observed(
            sources.lrd_reply,
            &review
                .logical_payload
                .as_ref()
                .context("reply evidence is unavailable")?
                .sha256,
        )?,
        register_layout,
    };
    Ok((receipt, verification))
}

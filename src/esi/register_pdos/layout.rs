//! Explicit register bit placements bound to an exact ESI selection.
use crate::{input_group::read_json, model::Identity, pdo_catalog::Definition};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, path::Path};

const MAX_LAYOUT_BYTES: u64 = 64 * 1024;

#[derive(Serialize)]
pub(super) struct Evidence {
    file_name: String,
    pub(super) sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    schema: u32,
    identity: Identity,
    esi_sha256: String,
    pdos: Vec<Pdo>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pdo {
    pdo_index: u16,
    entry_start_bits: Vec<Option<u8>>,
}

type EntryStarts = HashMap<u16, Vec<Option<u8>>>;

pub(super) fn load(
    path: &Path,
    identity: &Identity,
    esi_sha256: &str,
    pdos: &[&Definition],
) -> Result<(Evidence, EntryStarts)> {
    let (saved, bytes): (Saved, _) =
        read_json(path, MAX_LAYOUT_BYTES).context("read manual register layout")?;
    ensure!(
        saved.schema == 1,
        "unsupported manual register layout schema"
    );
    ensure!(
        &saved.identity == identity,
        "manual register layout identity differs from selected ESI device"
    );
    ensure!(
        saved.esi_sha256.eq_ignore_ascii_case(esi_sha256),
        "manual register layout ESI SHA-256 differs from selected ESI"
    );
    ensure!(
        !saved.pdos.is_empty(),
        "manual register layout needs at least one PDO"
    );
    let mut entries = HashMap::new();
    for pdo in saved.pdos {
        let index = pdo.pdo_index;
        let mut candidates = pdos.iter().filter(|pdo| pdo.index == index);
        let definition = candidates.next().with_context(|| format!("manual register layout PDO {index:#06x} is absent from the virtual TxPDOs with entries"))?;
        ensure!(
            candidates.next().is_none(),
            "manual register layout PDO {index:#06x} is ambiguous"
        );
        ensure!(
            pdo.entry_start_bits.len() == definition.entries.len(),
            "manual register layout PDO {index:#06x} needs one start bit per ESI entry"
        );
        ensure!(
            pdo.entry_start_bits.iter().flatten().all(|&bit| bit < 8),
            "manual register layout PDO {index:#06x} entry start bits must be 0 through 7"
        );
        for (position, (bit, entry)) in pdo
            .entry_start_bits
            .iter()
            .zip(&definition.entries)
            .enumerate()
        {
            if bit.is_none() {
                ensure!(
                    entry.index == 0 && entry.subindex == 0,
                    "manual register layout PDO {index:#06x} entry {} needs zero Index and SubIndex for null padding",
                    position + 1,
                );
            } else {
                ensure!(
                    entry.index != 0,
                    "manual register layout PDO {index:#06x} entry {} needs null for zero Index padding",
                    position + 1,
                );
            }
        }
        ensure!(
            pdo.entry_start_bits.iter().any(Option::is_some),
            "manual register layout PDO {index:#06x} needs at least one register entry"
        );
        ensure!(
            entries.insert(index, pdo.entry_start_bits).is_none(),
            "duplicate manual register layout PDO {index:#06x}"
        );
    }
    Ok((
        Evidence {
            file_name: path
                .file_name()
                .context("manual register layout has no file name")?
                .to_string_lossy()
                .into_owned(),
            sha256: hex::encode(Sha256::digest(bytes)),
        },
        entries,
    ))
}

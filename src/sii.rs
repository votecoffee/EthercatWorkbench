//! Decode SII PDO categories into the common bit layout representation.
use crate::pdo::{Layout, MappingSource, Pdo, SyncManager};
use anyhow::{Context, Result, ensure};

pub(crate) const MAX_CATEGORIES_BYTES: usize = 16 * 1024;

#[derive(Debug)]
pub(crate) struct SiiPdos {
    tx: Vec<(u8, Pdo)>,
    rx: Vec<(u8, Pdo)>,
}

impl SiiPdos {
    /// Input starts at the first category header (EEPROM byte address 0x80).
    pub fn parse(categories: &[u8]) -> Result<Self> {
        ensure!(
            categories.len() <= MAX_CATEGORIES_BYTES,
            "SII categories exceed 16 KiB"
        );
        let mut offset = 0;
        let mut result = Self {
            tx: Vec::new(),
            rx: Vec::new(),
        };
        let mut seen_tx = false;
        let mut seen_rx = false;
        loop {
            let header = categories
                .get(offset..offset + 4)
                .context("SII category end marker is missing or truncated")?;
            let category = word(header);
            if category == 0xffff {
                return Ok(result);
            }
            let len = usize::from(word(&header[2..])) * 2;
            offset += 4;
            let bytes = categories
                .get(offset..offset + len)
                .context("SII category payload is truncated")?;
            match category {
                50 => {
                    ensure!(!seen_tx, "duplicate SII TxPDO category");
                    seen_tx = true;
                    result.tx = pdos(bytes)?;
                }
                51 => {
                    ensure!(!seen_rx, "duplicate SII RxPDO category");
                    seen_rx = true;
                    result.rx = pdos(bytes)?;
                }
                _ => {}
            }
            offset += len;
        }
    }

    pub fn layout(&self, tx: bool, configured: &[(u8, usize)]) -> Layout {
        let pdos = if tx { &self.tx } else { &self.rx };
        Layout {
            mapping_source: MappingSource::Sii,
            sync_managers: configured
                .iter()
                .map(|(index, bytes)| SyncManager {
                    index: *index,
                    configured_bytes: Some(*bytes),
                    pdos: pdos
                        .iter()
                        .filter(|(sm, _)| sm == index)
                        .map(|(_, pdo)| pdo.clone())
                        .collect(),
                })
                .collect(),
        }
    }
}

fn pdos(mut bytes: &[u8]) -> Result<Vec<(u8, Pdo)>> {
    let mut pdos = Vec::new();
    let mut entry_count = 0;
    while !bytes.is_empty() {
        let header = bytes.get(..8).context("SII PDO header is truncated")?;
        let index = word(header);
        let count = usize::from(header[2]);
        let sm = header[3];
        ensure!(
            sm < 16 || sm == 0xff,
            "unsupported SII PDO SyncManager {sm}"
        );
        bytes = &bytes[8..];
        let raw_entries = bytes
            .get(..count * 8)
            .context("SII PDO entries are truncated")?;
        entry_count += count;
        ensure!(
            entry_count <= 1024 && pdos.len() < 64,
            "SII PDO count exceeds the bench limit"
        );
        let entries = raw_entries
            .as_chunks::<8>()
            .0
            .iter()
            .map(|entry| {
                (u32::from(word(entry)) << 16) | (u32::from(entry[2]) << 8) | u32::from(entry[5])
            })
            .collect();
        pdos.push((sm, Pdo { index, entries }));
        bytes = &bytes[count * 8..];
    }
    Ok(pdos)
}

fn word(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_padding_and_omits_unassigned_pdos() {
        let bytes = [
            50, 0, 20, 0, 0, 0x1a, 2, 1, 0, 0, 0, 0, 0, 0x60, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 7,
            0, 0, 1, 0x1a, 1, 0xff, 0, 0, 0, 0, 1, 0x60, 1, 0, 6, 16, 0, 0, 0xff, 0xff, 0, 0,
        ];
        let sii = SiiPdos::parse(&bytes).unwrap();
        let layout = sii.layout(true, &[(1, 1)]);
        let (entries, bytes) = layout.entries().unwrap();
        assert_eq!(bytes, 1);
        assert_eq!((entries[0].object_index, entries[0].width), (0x6000, 1));
        assert_eq!(
            (entries[1].object_index, entries[1].bit, entries[1].width),
            (0, 1, 7)
        );
        assert_eq!(layout.sync_managers[0].pdos.len(), 1);
    }

    #[test]
    fn rejects_truncated_and_duplicate_categories() {
        assert!(SiiPdos::parse(&[50, 0, 8, 0, 0]).is_err());
        assert!(SiiPdos::parse(&[50, 0, 0, 0, 50, 0, 0, 0, 0xff, 0xff, 0, 0]).is_err());
        assert!(
            SiiPdos::parse(&[50, 0, 4, 0, 0, 0x1a, 1, 1, 0, 0, 0, 0, 0xff, 0xff, 0, 0]).is_err()
        );
    }
}

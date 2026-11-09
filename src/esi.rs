use crate::model::{EsiSource, Field, Identity, Kind, Profile, Source};
use anyhow::{Context, Result, bail, ensure};
use roxmltree::{Document, Node};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug)]
pub struct Device {
    pub source: EsiSource,
    pub tx: Vec<Field>,
    pub rx: Vec<Field>,
    pub tx_bytes: usize,
    pub rx_bytes: usize,
    pub notes: Vec<String>,
}

impl Device {
    pub fn apply(&self, profile: &mut Profile) {
        profile.name.clone_from(&self.source.device);
        profile.expected_identity = Some(self.source.identity.clone());
        profile.esi = Some(self.source.clone());
        profile.tx.clone_from(&self.tx);
        profile.rx.clone_from(&self.rx);
        profile.tx_bytes = self.tx_bytes;
        profile.rx_bytes = self.rx_bytes;
        profile.staged_rx_hex.clear();
    }
}

pub fn load(path: &Path) -> Result<Vec<Device>> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let file = path
        .file_name()
        .context("ESI path has no file name")?
        .to_string_lossy();
    parse(&file, &bytes)
}

pub fn parse(file: &str, bytes: &[u8]) -> Result<Vec<Device>> {
    let text = xml_text(bytes)?;
    let doc = Document::parse(&text).context("parse ESI XML (DTD disabled)")?;
    let root = doc.root_element();
    ensure!(
        root.has_tag_name("EtherCATInfo") || root.tag_name().name() == "EtherCATInfo",
        "expected an EtherCATInfo document"
    );
    let vendor = number(
        child(child(root, "Vendor").context("ESI Vendor missing")?, "Id")
            .and_then(|n| n.text())
            .context("ESI Vendor Id missing")?,
    )?;
    let devices = child(
        child(root, "Descriptions").context("ESI Descriptions missing")?,
        "Devices",
    )
    .context("ESI Devices missing")?;
    let sha256 = hex::encode(Sha256::digest(bytes));
    let result = devices
        .children()
        .filter(|n| named(*n, "Device"))
        .map(|device| {
            let ty = child(device, "Type").context("ESI device Type missing")?;
            let product = number(
                ty.attribute("ProductCode")
                    .context("ESI ProductCode missing")?,
            )?;
            let revision = number(ty.attribute("RevisionNo").unwrap_or("0"))?;
            let label = label(device, "Name")
                .or_else(|| ty.text())
                .unwrap_or("Unnamed device")
                .to_owned();
            let mut notes = Vec::new();
            if ty.attribute("RevisionNo").is_none() {
                notes.push("RevisionNo is absent. Verify revision manually.".into());
            }
            let (tx, tx_bytes) = fields(device, "TxPdo", &mut notes)?;
            let (rx, rx_bytes) = fields(device, "RxPdo", &mut notes)?;
            if let Some(dc) = child(device, "Dc") {
                let modes: Vec<_> = dc
                    .children()
                    .filter(|n| named(*n, "OpMode"))
                    .filter_map(|mode| self::label(mode, "Name"))
                    .collect();
                if !modes.is_empty() {
                    notes.push(format!(
                        "ESI DC operating modes (descriptive): {}",
                        modes.join(", ")
                    ));
                }
            }
            Ok(Device {
                source: EsiSource {
                    file_name: file.to_owned(),
                    sha256: sha256.clone(),
                    device: label,
                    default_tx_bytes: Some(tx_bytes),
                    default_rx_bytes: Some(rx_bytes),
                    notes: notes.clone(),
                    identity: Identity {
                        vendor,
                        product,
                        revision,
                    },
                },
                tx,
                rx,
                tx_bytes,
                rx_bytes,
                notes,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(!result.is_empty(), "ESI has no devices");
    Ok(result)
}

fn xml_text(bytes: &[u8]) -> Result<String> {
    let utf16 = if bytes.starts_with(&[0xff, 0xfe]) {
        Some((true, &bytes[2..]))
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        Some((false, &bytes[2..]))
    } else if bytes.starts_with(&[b'<', 0]) {
        Some((true, bytes))
    } else if bytes.starts_with(&[0, b'<']) {
        Some((false, bytes))
    } else {
        None
    };
    if let Some((le, bytes)) = utf16 {
        ensure!(bytes.len().is_multiple_of(2), "truncated UTF-16 ESI");
        let code_units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| {
                if le {
                    u16::from_le_bytes([b[0], b[1]])
                } else {
                    u16::from_be_bytes([b[0], b[1]])
                }
            })
            .collect();
        return String::from_utf16(&code_units).context("decode UTF-16 ESI");
    }
    Ok(
        std::str::from_utf8(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes))
            .context("ESI must use UTF-8 or UTF-16")?
            .to_owned(),
    )
}

fn named(node: Node<'_, '_>, tag: &str) -> bool {
    node.is_element() && node.tag_name().name() == tag
}

fn child<'a, 'd>(node: Node<'a, 'd>, tag: &str) -> Option<Node<'a, 'd>> {
    node.children().find(|n| named(*n, tag))
}

fn label<'a>(node: Node<'a, '_>, tag: &str) -> Option<&'a str> {
    node.children()
        .filter(|n| named(*n, tag))
        .min_by_key(|n| match n.attribute("LcId") {
            Some("1033") => 0,
            None => 1,
            _ => 2,
        })
        .and_then(|n| n.text())
}

pub fn number(text: &str) -> Result<u32> {
    let text = text.trim();
    if let Some(hex) = text
        .strip_prefix("#x")
        .or_else(|| text.strip_prefix("#X"))
        .or_else(|| text.strip_prefix("0x"))
        .or_else(|| text.strip_prefix("0X"))
    {
        return u32::from_str_radix(hex, 16).with_context(|| format!("invalid integer {text:?}"));
    }
    text.parse()
        .with_context(|| format!("invalid integer {text:?}"))
}

fn fields(device: Node<'_, '_>, tag: &str, notes: &mut Vec<String>) -> Result<(Vec<Field>, usize)> {
    let mut assigned = Vec::new();
    for pdo in device.children().filter(|n| named(*n, tag)) {
        if let Some(sm) = pdo.attribute("Sm") {
            assigned.push((number(sm)?, pdo));
        } else {
            notes.push(format!("{tag} without a default SyncManager was omitted"));
        }
    }
    assigned.sort_by_key(|(sm, _)| *sm);
    let mut bit: usize = 0;
    let mut fields = Vec::new();
    for (_, pdo) in assigned {
        let index = u16::try_from(node_number(pdo, "Index")?)?;
        for entry in pdo.children().filter(|n| named(*n, "Entry")) {
            let width = usize::try_from(node_number(entry, "BitLen")?)?;
            let object = u16::try_from(node_number(entry, "Index")?)?;
            if object != 0 {
                let sub = child(entry, "SubIndex")
                    .and_then(|n| n.text())
                    .map(number)
                    .transpose()?
                    .unwrap_or(0);
                let base = label(entry, "Name").unwrap_or("Entry");
                let kind = match child(entry, "DataType")
                    .and_then(|n| n.text())
                    .unwrap_or("")
                    .trim()
                {
                    "BOOL" | "BIT" if width == 1 => Kind::Bool,
                    "SINT" | "INT" | "DINT" | "LINT" | "INT24" | "INT40" | "INT48" | "INT56" => {
                        Kind::Signed
                    }
                    "REAL" | "REAL32" if width == 32 && bit.is_multiple_of(8) => Kind::F32,
                    "LREAL" | "REAL64" if width == 64 && bit.is_multiple_of(8) => Kind::F64,
                    _ if width <= 64 => Kind::Unsigned,
                    _ if width.is_multiple_of(8) && bit.is_multiple_of(8) => Kind::Raw,
                    _ => bail!("unsupported PDO entry width/alignment at {object:#06x}:{sub}"),
                };
                let mut name = format!("{base} [{index:04X}/{object:04X}:{sub:02X}]");
                if fields.iter().any(|f: &Field| f.name == name) {
                    name.push_str(&format!(" @{bit}"));
                }
                fields.push(Field {
                    name,
                    bit,
                    width,
                    kind,
                    log: tag == "TxPdo",
                    source: Source::Esi,
                    pdo_index: Some(index),
                    object_index: Some(object),
                    subindex: Some(u8::try_from(sub)?),
                    ..Field::default()
                });
            }
            bit = bit.checked_add(width).context("PDO size overflow")?;
        }
    }
    Ok((fields, bit.div_ceil(8)))
}

fn node_number(node: Node<'_, '_>, name: &str) -> Result<u32> {
    number(
        child(node, name)
            .and_then(|n| n.text())
            .with_context(|| format!("missing {name}"))?,
    )
}

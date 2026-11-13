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
        profile.staged_esi_dc_mode = None;
        profile.sync_unit_cycle_ns = None;
    }
}

pub fn load(path: &Path) -> Result<Vec<Device>> {
    ensure!(
        std::fs::metadata(path)?.len() <= 16 * 1024 * 1024,
        "ESI exceeds 16 MiB"
    );
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let file = path
        .file_name()
        .context("ESI path has no file name")?
        .to_string_lossy();
    parse(&file, &bytes)
}

pub fn parse(file: &str, bytes: &[u8]) -> Result<Vec<Device>> {
    ensure!(bytes.len() <= 16 * 1024 * 1024, "ESI exceeds 16 MiB");
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
            let dc_modes = dc_modes(device)?;
            if !dc_modes.is_empty() {
                notes.push(format!(
                    "Imported {} ESI DC modes for offline review; none will be applied to hardware",
                    dc_modes.len()
                ));
            }
            Ok(Device {
                source: EsiSource {
                    file_name: file.to_owned(),
                    sha256: sha256.clone(),
                    device: label,
                    default_tx_bytes: Some(tx_bytes),
                    default_rx_bytes: Some(rx_bytes),
                    dc_modes,
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
    node.is_element()
        && node.tag_name().name() == tag
        && node.tag_name().namespace() == node.document().root_element().tag_name().namespace()
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
    let mut previous_sm = None;
    for (sm, pdo) in assigned {
        ensure!(sm < 16, "ESI SyncManager index exceeds the bench limit");
        if previous_sm.is_some_and(|previous| previous != sm) {
            bit = bit.div_ceil(8) * 8;
        }
        previous_sm = Some(sm);
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

fn unique_child<'a, 'd>(node: Node<'a, 'd>, tag: &str) -> Result<Option<Node<'a, 'd>>> {
    let mut children = node.children().filter(|n| named(*n, tag));
    let first = children.next();
    ensure!(children.next().is_none(), "duplicate ESI DC element {tag}");
    Ok(first)
}

fn dc_text(node: Node<'_, '_>) -> String {
    node.children()
        .filter(Node::is_text)
        .filter_map(|n| n.text())
        .collect()
}

fn timing(node: Node<'_, '_>, tag: &str) -> Result<Option<crate::sync_review::Timing>> {
    let Some(time) = unique_child(node, tag)? else {
        return Ok(None);
    };
    let integer = |text: &str| {
        text.trim()
            .parse::<i32>()
            .with_context(|| format!("invalid signed ESI DC integer in {tag}: {text:?}"))
    };
    let attr = |name| time.attribute(name).map(integer).transpose();
    let input = time
        .attribute("Input")
        .map(|v| match v.trim() {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            _ => bail!("invalid ESI DC Input boolean {v:?}"),
        })
        .transpose()?;
    let mut notes: Vec<_> = time
        .attributes()
        .filter(|a| {
            a.namespace().is_some()
                || !["Factor", "Input", "InputDelayTime", "OutputDelayTime"].contains(&a.name())
        })
        .map(|a| format!("Unsupported {tag} attribute {}={}", a.name(), a.value()))
        .collect();
    for child in time.children().filter(Node::is_element) {
        notes.push(format!(
            "Unsupported {tag} child {}",
            child.tag_name().name()
        ));
    }
    Ok(Some(crate::sync_review::Timing {
        value_ns: integer(&dc_text(time))?,
        factor: attr("Factor")?,
        input,
        input_delay_ns: attr("InputDelayTime")?,
        output_delay_ns: attr("OutputDelayTime")?,
        notes,
    }))
}

fn dc_modes(device: Node<'_, '_>) -> Result<Vec<crate::sync_review::DcMode>> {
    let mut modes = Vec::new();
    let mut add = |outer: Node<'_, '_>,
                   timing_node: Node<'_, '_>,
                   path: &str,
                   inherited: Vec<String>|
     -> Result<()> {
        ensure!(modes.len() < 64, "ESI has more than 64 DC modes");
        let mut notes = inherited;
        for node in [outer, timing_node] {
            {
                for child in node.children().filter(Node::is_element) {
                    let known = [
                        "Name",
                        "Desc",
                        "Dc",
                        "AssignActivate",
                        "CycleTimeSync0",
                        "ShiftTimeSync0",
                        "CycleTimeSync1",
                        "ShiftTimeSync1",
                    ];
                    if !known.iter().any(|name| named(child, name)) {
                        notes.push(format!("Unsupported DC mode child {}; mapping/vendor extensions require separate review", child.tag_name().name()));
                    }
                }
                notes.extend(
                    node.attributes().map(|a| {
                        format!("Descriptive DC mode attribute {}={}", a.name(), a.value())
                    }),
                );
            }
        }
        notes.sort();
        notes.dedup();
        let assign = unique_child(timing_node, "AssignActivate")?
            .context("ESI DC AssignActivate missing")?;
        ensure!(
            !assign.children().any(|n| n.is_element()),
            "ESI DC AssignActivate must contain only an integer"
        );
        notes.extend(assign.attributes().map(|a| {
            format!(
                "Descriptive AssignActivate attribute {}={}",
                a.name(),
                a.value()
            )
        }));
        let mode = crate::sync_review::DcMode {
            name: label(outer, "Name")
                .context("ESI DC mode Name missing")?
                .trim()
                .to_owned(),
            description: label(outer, "Desc").map(str::to_owned),
            xml_path: path.into(),
            assign_activate: u16::try_from(number(&dc_text(assign))?)
                .context("ESI DC AssignActivate exceeds 16 bits")?,
            cycle_sync0: timing(timing_node, "CycleTimeSync0")?,
            shift_sync0: timing(timing_node, "ShiftTimeSync0")?,
            cycle_sync1: timing(timing_node, "CycleTimeSync1")?,
            shift_sync1: timing(timing_node, "ShiftTimeSync1")?,
            notes,
        };
        mode.validate()?;
        modes.push(mode);
        Ok(())
    };
    for node in device.children().filter(Node::is_element) {
        if named(node, "Dc") {
            let mut notes: Vec<_> = node
                .attributes()
                .map(|a| format!("Descriptive Dc attribute {}={}", a.name(), a.value()))
                .collect();
            notes.extend(
                node.children()
                    .filter(Node::is_element)
                    .filter(|n| !named(*n, "OpMode"))
                    .map(|n| format!("Unsupported Dc child {}", n.tag_name().name())),
            );
            for mode in node.children().filter(|n| named(*n, "OpMode")) {
                add(mode, mode, "Device/Dc/OpMode", notes.clone())?;
            }
        } else if named(node, "OpMode")
            && let Some(dc) = unique_child(node, "Dc")?
        {
            add(node, dc, "Device/OpMode/Dc", Vec::new())?;
        }
    }
    Ok(modes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_both_dc_forms_and_preserves_signed_and_contextual_values() {
        let xml = include_bytes!("../samples/sync-modes.esi.xml");
        let devices = parse("sync.xml", xml).unwrap();
        let modes = &devices[0].source.dc_modes;
        assert_eq!(modes.len(), 4);
        assert_eq!(modes[1].assign_activate, 0x0300);
        assert_eq!(modes[1].shift_sync0.as_ref().unwrap().value_ns, -1250);
        assert_eq!(
            modes[1].shift_sync0.as_ref().unwrap().input_delay_ns,
            Some(250)
        );
        assert_eq!(modes[2].cycle_sync0.as_ref().unwrap().factor, Some(-2));
        assert_eq!(modes[3].xml_path, "Device/OpMode/Dc");
        assert!(modes[3].notes.iter().any(|n| n.contains("Sm")));
        let mut profile = Profile::default();
        devices[0].apply(&mut profile);
        profile.staged_esi_dc_mode = Some(2);
        profile.sync_unit_cycle_ns = Some(1_000_000);
        profile.validate().unwrap();
        let review = crate::sync_review::review(&profile, None).unwrap().unwrap();
        assert!(!review.applied);
        assert_eq!(review.cycle_sync0.value_ns, Some(500_000));
        assert_eq!(review.cycle_sync1.value_ns, Some(2_000_000));
        let saved: Profile =
            serde_json::from_str(&serde_json::to_string(&profile).unwrap()).unwrap();
        assert_eq!(saved.esi.unwrap().dc_modes, *modes);
        profile.expected_identity.as_mut().unwrap().revision += 1;
        assert!(profile.validate().is_err());
        devices[0].apply(&mut profile);
        assert_eq!(profile.staged_esi_dc_mode, None);
        assert_eq!(profile.sync_unit_cycle_ns, None);
    }

    #[test]
    fn filters_foreign_namespace_shadows_and_rejects_ambiguous_dc_numbers() {
        let xml = std::str::from_utf8(include_bytes!("../samples/sync-modes.esi.xml")).unwrap();
        let namespaced = xml
            .replace(
                "<EtherCATInfo Version=",
                "<EtherCATInfo xmlns=\"urn:bench\" xmlns:v=\"urn:vendor\" Version=",
            )
            .replace(
                "<AssignActivate>#x0300",
                "<v:AssignActivate>#xFFFF</v:AssignActivate><AssignActivate>#x0300",
            );
        let devices = parse("namespaced.xml", namespaced.as_bytes()).unwrap();
        assert_eq!(devices[0].source.dc_modes[1].assign_activate, 0x0300);
        assert_eq!(devices[0].tx_bytes, 8);
        for bad in [
            xml.replace("Factor=\"-2\"", "Factor=\"bad\""),
            xml.replace("#x0300", "#x10000"),
            xml.replace("Input=\"true\"", "Input=\"yes\""),
            xml.replace(
                "<AssignActivate>#x0300</AssignActivate>",
                "<AssignActivate>0</AssignActivate><AssignActivate>768</AssignActivate>",
            ),
        ] {
            assert!(parse("bad.xml", bad.as_bytes()).is_err());
        }
        let commented = xml.replace("#x0300", "#x03<!-- split text -->00");
        assert_eq!(
            parse("comments.xml", commented.as_bytes()).unwrap()[0]
                .source
                .dc_modes[1]
                .assign_activate,
            0x0300
        );
    }

    #[test]
    fn aligns_each_sync_manager_and_keeps_bits_contiguous_within_it() {
        let xml = br#"<EtherCATInfo><Vendor><Id>1</Id></Vendor><Descriptions><Devices>
          <Device><Type ProductCode="2" RevisionNo="3">Bits</Type>
            <TxPdo Sm="4"><Index>#x1a02</Index>
              <Entry><Index>#x6002</Index><BitLen>16</BitLen></Entry>
            </TxPdo>
            <TxPdo Sm="3"><Index>#x1a00</Index>
              <Entry><Index>#x6000</Index><BitLen>1</BitLen></Entry>
            </TxPdo>
            <TxPdo Sm="3"><Index>#x1a01</Index>
              <Entry><Index>#x6001</Index><BitLen>2</BitLen></Entry>
            </TxPdo>
          </Device></Devices></Descriptions></EtherCATInfo>"#;
        let devices = parse("bits.xml", xml).unwrap();
        assert_eq!(
            devices[0].tx.iter().map(|f| f.bit).collect::<Vec<_>>(),
            [0, 1, 8]
        );
        assert_eq!(devices[0].tx_bytes, 3);
    }
}

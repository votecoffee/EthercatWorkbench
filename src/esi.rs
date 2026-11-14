use crate::model::{EsiSource, Field, Identity, Profile};
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
    pub fn apply(&self, profile: &mut Profile) -> Result<()> {
        self.apply_selection(
            profile,
            crate::pdo_catalog::defaults(&self.source.pdo_catalog),
        )
    }

    pub fn apply_selection(
        &self,
        profile: &mut Profile,
        selection: crate::pdo_catalog::Selection,
    ) -> Result<()> {
        let mut candidate = profile.clone();
        candidate.name.clone_from(&self.source.device);
        candidate.expected_identity = Some(self.source.identity.clone());
        candidate.esi = Some(self.source.clone());
        candidate.staged_esi_dc_mode = None;
        candidate.sync_unit_cycle_ns = None;
        crate::pdo_catalog::apply(&mut candidate, selection)?;
        *profile = candidate;
        Ok(())
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

/// Parse an exact unsigned vendor/product/revision selector. Zero is a literal value.
pub fn identity_selector(text: &str) -> Result<Identity> {
    ensure!(text.len() <= 128, "ESI identity selector exceeds 128 bytes");
    let parts = text.split('/').collect::<Vec<_>>();
    ensure!(
        parts.len() == 3 && parts.iter().all(|part| !part.trim().is_empty()),
        "expected VENDOR/PRODUCT/REVISION with three unsigned 32-bit integers"
    );
    Ok(Identity {
        vendor: number(parts[0]).context("invalid ESI vendor selector")?,
        product: number(parts[1]).context("invalid ESI product selector")?,
        revision: number(parts[2]).context("invalid ESI revision selector")?,
    })
}

/// Select a unique exact identity, or explicitly choose an index with an optional identity guard.
pub fn select_device<'a>(
    devices: &'a [Device],
    index: Option<usize>,
    identity: Option<&Identity>,
) -> Result<&'a Device> {
    if let Some(index) = index {
        let device = devices
            .get(index)
            .context("ESI device index out of range")?;
        if let Some(expected) = identity {
            ensure!(
                &device.source.identity == expected,
                "ESI device index {index} has identity {}, expected {expected}",
                device.source.identity
            );
        }
        return Ok(device);
    }
    let identity = identity.context("select an ESI device with --device or --identity")?;
    let mut matching = devices
        .iter()
        .filter(|device| &device.source.identity == identity);
    let selected = matching
        .next()
        .with_context(|| format!("ESI identity {identity} was not found"))?;
    ensure!(
        matching.next().is_none(),
        "ESI identity {identity} matches multiple entries; inspect esi-list and use --device with --identity to choose one explicitly"
    );
    Ok(selected)
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
            let pdo_catalog = pdo_catalog(device)?;
            for pdo in pdo_catalog.iter().filter(|p| p.default_sm.is_none()) {
                notes.push(format!("{:?}Pdo without a default SyncManager was omitted from the default image and retained in the catalog", pdo.direction));
            }
            let default_layout = crate::pdo_catalog::build(&pdo_catalog, &crate::pdo_catalog::defaults(&pdo_catalog));
            let default_known = default_layout.is_ok();
            let (tx, tx_bytes, rx, rx_bytes) = match default_layout {
                Ok(built) => (built.tx, built.tx_bytes, built.rx, built.rx_bytes),
                Err(error) => {
                    notes.push(format!("Default PDO image needs an explicit selection: {error:#}"));
                    (Vec::new(), 0, Vec::new(), 0)
                }
            };
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
                    default_tx_bytes: default_known.then_some(tx_bytes),
                    default_rx_bytes: default_known.then_some(rx_bytes),
                    dc_modes,
                    pdo_catalog,
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

fn bool_attr(node: Node<'_, '_>, name: &str) -> Result<bool> {
    match node.attribute(name).map(str::trim) {
        None | Some("false" | "0") => Ok(false),
        Some("true" | "1") => Ok(true),
        Some(value) => bail!("invalid ESI {name} boolean {value:?}"),
    }
}

fn default_sm(node: Node<'_, '_>) -> Result<Option<u8>> {
    match node.attribute("Sm").map(str::trim) {
        None | Some("-1") => Ok(None),
        Some(value) => {
            let sm = u8::try_from(number(value)?)?;
            ensure!(sm < 16, "ESI default SyncManager exceeds 15");
            Ok(Some(sm))
        }
    }
}

fn pdo_catalog(device: Node<'_, '_>) -> Result<Vec<crate::pdo_catalog::Definition>> {
    use crate::pdo_catalog::{Definition, Direction, Entry, validate_catalog};
    let mut catalog = Vec::new();
    for node in device
        .children()
        .filter(|n| named(*n, "TxPdo") || named(*n, "RxPdo"))
    {
        ensure!(
            catalog.len() < 512,
            "ESI PDO catalog exceeds 512 candidates"
        );
        let mut notes = Vec::new();
        let mut unsupported = bool_attr(node, "OverwrittenByModule")?;
        for attr in node
            .attributes()
            .filter(|a| !["Sm", "Fixed", "Mandatory", "Virtual"].contains(&a.name()))
        {
            notes.push(format!(
                "Descriptive PDO attribute {}={}",
                attr.name(),
                attr.value()
            ));
        }
        let mut record_dependencies = |element: Node<'_, '_>| -> Result<()> {
            unsupported |=
                bool_attr(element, "DependOnSlot")? || bool_attr(element, "DependOnSlotGroup")?;
            for attr in element.attributes() {
                notes.push(format!(
                    "Descriptive {} attribute {}={}",
                    element.tag_name().name(),
                    attr.name(),
                    attr.value()
                ));
            }
            Ok(())
        };
        let index_node = unique_child(node, "Index")?.context("PDO Index missing")?;
        record_dependencies(index_node)?;
        let index = u16::try_from(number(&dc_text(index_node))?)?;
        let mut excludes = Vec::new();
        for excluded in node.children().filter(|n| named(*n, "Exclude")) {
            record_dependencies(excluded)?;
            excludes.push(u16::try_from(number(&dc_text(excluded))?)?);
        }
        let mut entries = Vec::new();
        for entry in node.children().filter(|n| named(*n, "Entry")) {
            ensure!(entries.len() < 255, "ESI PDO exceeds 255 entries");
            let object = unique_child(entry, "Index")?.context("PDO entry Index missing")?;
            record_dependencies(object)?;
            entries.push(Entry {
                index: u16::try_from(number(&dc_text(object))?)?,
                subindex: u8::try_from(
                    unique_child(entry, "SubIndex")?
                        .map(|n| number(&dc_text(n)))
                        .transpose()?
                        .unwrap_or(0),
                )?,
                width: usize::try_from(node_number(entry, "BitLen")?)?,
                name: label(entry, "Name").unwrap_or("Entry").into(),
                data_type: child(entry, "DataType")
                    .map(dc_text)
                    .unwrap_or_default()
                    .trim()
                    .into(),
                fixed: bool_attr(entry, "Fixed")?,
            });
        }
        for entry in node.children().filter(|n| named(*n, "Entry")) {
            for attr in entry.attributes().filter(|a| a.name() != "Fixed") {
                notes.push(format!(
                    "Entry attribute {}={} is descriptive only",
                    attr.name(),
                    attr.value()
                ));
            }
            for ty in entry.children().filter(|n| named(*n, "DataType")) {
                for attr in ty.attributes() {
                    notes.push(format!(
                        "DataType attribute {}={} is not applied to decoding",
                        attr.name(),
                        attr.value()
                    ));
                }
            }
        }
        for unknown in node.children().filter(Node::is_element).filter(|n| {
            !["Index", "Name", "Exclude", "Entry"]
                .iter()
                .any(|name| named(*n, name))
        }) {
            notes.push(format!(
                "Unsupported PDO child {}",
                unknown.tag_name().name()
            ));
        }
        catalog.push(Definition {
            direction: if named(node, "TxPdo") {
                Direction::Tx
            } else {
                Direction::Rx
            },
            index,
            name: label(node, "Name").unwrap_or("PDO").into(),
            default_sm: default_sm(node)?,
            fixed: bool_attr(node, "Fixed")?,
            mandatory: bool_attr(node, "Mandatory")?,
            virtual_pdo: bool_attr(node, "Virtual")?,
            excludes,
            entries,
            notes,
            unsupported,
        });
    }
    validate_catalog(&catalog)?;
    Ok(catalog)
}

fn node_number(node: Node<'_, '_>, name: &str) -> Result<u32> {
    number(&dc_text(
        unique_child(node, name)?.with_context(|| format!("missing {name}"))?,
    ))
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

fn mode_sync_managers(
    outer: Node<'_, '_>,
    timing_node: Node<'_, '_>,
) -> Result<Vec<crate::sync_review::ModeSyncManager>> {
    let mut result = Vec::new();
    for node in outer.children().filter(|n| named(*n, "Sm")) {
        ensure!(result.len() < 16, "ESI mode exceeds 16 SyncManagers");
        let index = u8::try_from(number(node.attribute("No").context("mode Sm No missing")?)?)
            .context("mode Sm No exceeds 8 bits")?;
        let mut notes: Vec<_> = node
            .attributes()
            .filter(|a| a.namespace().is_some() || a.name() != "No")
            .map(|a| format!("Unsupported Sm attribute {}={}", a.name(), a.value()))
            .collect();
        let sync_type = unique_child(node, "SyncType")?
            .map(|child| -> Result<u16> {
                notes.extend(
                    child.attributes().map(|a| {
                        format!("Unsupported SyncType attribute {}={}", a.name(), a.value())
                    }),
                );
                notes.extend(
                    child
                        .children()
                        .filter(Node::is_element)
                        .map(|c| format!("Unsupported SyncType child {}", c.tag_name().name())),
                );
                u16::try_from(number(&dc_text(child))?).context("mode Sm SyncType exceeds 16 bits")
            })
            .transpose()?;
        let mut pdo_indexes = Vec::new();
        for child in node.children().filter(Node::is_element) {
            if named(child, "Pdo") {
                if outer != timing_node {
                    notes.push(
                        "Pdo hints on Device/OpMode/Sm are outside the supported schema subset"
                            .into(),
                    );
                }
                ensure!(
                    pdo_indexes.len() < 512,
                    "ESI mode SyncManager exceeds 512 PDO hints"
                );
                notes.extend(
                    child.attributes().map(|a| {
                        format!("Unsupported mode Pdo attribute {}={}", a.name(), a.value())
                    }),
                );
                notes.extend(
                    child
                        .children()
                        .filter(Node::is_element)
                        .map(|c| format!("Unsupported mode Pdo child {}", c.tag_name().name())),
                );
                pdo_indexes.push(
                    u16::try_from(number(&dc_text(child))?)
                        .context("mode Pdo index exceeds 16 bits")?,
                );
            } else if !named(child, "SyncType") {
                notes.push(format!(
                    "Unsupported Sm child {}; device-specific interpretation required",
                    child.tag_name().name()
                ));
            }
        }
        result.push(crate::sync_review::ModeSyncManager {
            index,
            sync_type,
            pdo_indexes,
            notes,
        });
    }
    Ok(result)
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
                    if !(known.iter().any(|name| named(child, name))
                        || (node == outer && named(child, "Sm")))
                    {
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
            sync_managers: mode_sync_managers(outer, timing_node)?,
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
    fn exact_identity_selector_accepts_numeric_forms_and_rejects_partial_or_overflow() {
        let expected = Identity {
            vendor: 16,
            product: 32,
            revision: 0,
        };
        for text in ["16/32/0", "0x10/0X20/0", " #x10 / #X20 / 0 "] {
            assert_eq!(identity_selector(text).unwrap(), expected);
        }
        for text in [
            "",
            "1/2",
            "1/2/3/4",
            "1//3",
            "1/2/*",
            "1/2/-1",
            "1/2/4294967296",
            "0x100000000/2/3",
        ] {
            assert!(identity_selector(text).is_err(), "{text:?}");
        }
        assert!(identity_selector(&"0".repeat(129)).is_err());
    }

    #[test]
    fn exact_selection_distinguishes_revisions_and_guards_reordered_indexes() {
        let bytes = include_bytes!("../samples/mode-pdo-staging.esi.xml");
        let mut devices = parse("multi.xml", bytes).unwrap();
        let original = devices[0].source.identity.clone();
        let mut revision = parse("multi.xml", bytes).unwrap().remove(0);
        revision.source.identity.revision = 2;
        devices.push(revision);
        assert_eq!(
            select_device(&devices, None, Some(&original))
                .unwrap()
                .source
                .identity,
            original
        );
        let second = devices[1].source.identity.clone();
        assert!(std::ptr::eq(
            select_device(&devices, None, Some(&second)).unwrap(),
            &devices[1]
        ));
        assert!(select_device(&devices, Some(0), Some(&second)).is_err());
        devices.swap(0, 1);
        assert!(std::ptr::eq(
            select_device(&devices, None, Some(&original)).unwrap(),
            &devices[1]
        ));
        assert!(select_device(&devices, Some(0), Some(&original)).is_err());
        assert!(select_device(&devices, Some(1), Some(&original)).is_ok());
        assert!(select_device(&devices, Some(0), None).is_ok());
    }

    #[test]
    fn ambiguous_missing_and_absent_selectors_never_choose_a_default() {
        let bytes = include_bytes!("../samples/mode-pdo-staging.esi.xml");
        let mut devices = parse("duplicates.xml", bytes).unwrap();
        let identity = devices[0].source.identity.clone();
        devices.push(parse("duplicates.xml", bytes).unwrap().remove(0));
        assert!(
            select_device(&devices, None, Some(&identity))
                .unwrap_err()
                .to_string()
                .contains("matches multiple entries")
        );
        assert!(std::ptr::eq(
            select_device(&devices, Some(1), Some(&identity)).unwrap(),
            &devices[1]
        ));
        let mut missing = identity;
        missing.revision = 0; // Literal zero is not a wildcard for revisions 1 or later.
        assert!(select_device(&devices, None, Some(&missing)).is_err());
        assert!(select_device(&devices, None, None).is_err());
        assert!(select_device(&devices, Some(2), None).is_err());
        assert!(select_device(&[], None, Some(&missing)).is_err());
    }

    #[test]
    fn mode_sync_manager_hints_preserve_order_forms_and_unresolved_annotations() {
        let devices = parse(
            "modes.xml",
            include_bytes!("../samples/mode-sync-managers.esi.xml"),
        )
        .unwrap();
        let modes = &devices[0].source.dc_modes;
        assert_eq!(modes.len(), 3);
        assert_eq!(
            modes[0]
                .sync_managers
                .iter()
                .map(|s| s.index)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(modes[0].sync_managers[0].pdo_indexes, vec![0x1600]);
        assert_eq!(modes[0].sync_managers[1].pdo_indexes, vec![0x1a00]);
        assert_eq!(modes[1].xml_path, "Device/OpMode/Dc");
        assert_eq!(modes[1].sync_managers[0].sync_type, Some(2));
        assert!(
            modes[2].sync_managers[0]
                .notes
                .iter()
                .any(|n| n.contains("OSFac"))
        );
        assert!(
            modes[2].sync_managers[0]
                .notes
                .iter()
                .any(|n| n.contains("CycleTime"))
        );
        let mut profile = Profile::default();
        devices[0].apply(&mut profile).unwrap();
        profile.staged_esi_dc_mode = Some(0);
        let before = profile.clone();
        let review = crate::sync_review::review(&profile, None).unwrap().unwrap();
        assert_eq!(profile, before);
        assert!(
            review
                .sync_managers
                .iter()
                .all(|s| s.pdo_state == crate::sync_review::CheckState::Matched)
        );
        assert!(!review.applied);
        let saved: Profile =
            serde_json::from_slice(&serde_json::to_vec(&profile).unwrap()).unwrap();
        assert_eq!(saved, profile);
        let xml =
            std::str::from_utf8(include_bytes!("../samples/mode-sync-managers.esi.xml")).unwrap();
        let namespaced = xml
            .replace(
                "<EtherCATInfo Version=",
                "<EtherCATInfo xmlns=\"urn:authored:esi\" xmlns:x=\"urn:foreign\" Version=",
            )
            .replace(
                "<SyncType>0</SyncType>",
                "<x:SyncType>65535</x:SyncType><SyncType>0</SyncType>",
            );
        let foreign = parse("namespaced.xml", namespaced.as_bytes()).unwrap();
        assert_eq!(
            foreign[0].source.dc_modes[0].sync_managers[0].sync_type,
            Some(0)
        );
        assert!(
            !foreign[0].source.dc_modes[0].sync_managers[0]
                .notes
                .is_empty()
        );
    }

    #[test]
    fn mode_sync_manager_consumption_rejects_ambiguity_invalid_numbers_and_excessive_lists() {
        let parse_sm = |sm: &str| {
            parse("sm.xml",format!("<EtherCATInfo><Vendor><Id>1</Id></Vendor><Descriptions><Devices><Device><Type ProductCode='3' RevisionNo='1'>Test</Type><Name>Test</Name><Dc><OpMode><Name>Test</Name><AssignActivate>0</AssignActivate>{sm}</OpMode></Dc></Device></Devices></Descriptions></EtherCATInfo>").as_bytes())
        };
        for bad in [
            "<Sm><SyncType>0</SyncType></Sm>",
            "<Sm No='16'/>",
            "<Sm No='-1'/>",
            "<Sm No='3'><SyncType>65536</SyncType></Sm>",
            "<Sm No='3'><SyncType>0</SyncType><SyncType>1</SyncType></Sm>",
            "<Sm No='3'/><Sm No='3'/>",
            "<Sm No='3'><Pdo>0</Pdo></Sm>",
            "<Sm No='3'><Pdo>65536</Pdo></Sm>",
            "<Sm No='3'><Pdo>6656</Pdo><Pdo>6656</Pdo></Sm>",
        ] {
            assert!(parse_sm(bad).is_err(), "accepted {bad}");
        }
        let pdos = (1..=512)
            .map(|i| format!("<Pdo>{i}</Pdo>"))
            .collect::<String>();
        assert!(parse_sm(&format!("<Sm No='3'>{pdos}</Sm>")).is_ok());
        assert!(parse_sm(&format!("<Sm No='3'>{pdos}<Pdo>513</Pdo></Sm>")).is_err());
        let sms = (0..16)
            .map(|i| format!("<Sm No='{i}'/>"))
            .collect::<String>();
        assert!(parse_sm(&sms).is_ok());
        assert!(parse_sm(&format!("{sms}<Sm No='0'/>")).is_err());
    }

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
        assert_eq!(modes[3].sync_managers[0].index, 3);
        assert_eq!(modes[3].sync_managers[0].sync_type, Some(2));
        let mut profile = Profile::default();
        devices[0].apply(&mut profile).unwrap();
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
        devices[0].apply(&mut profile).unwrap();
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

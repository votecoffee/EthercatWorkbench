//! Container parsing only; packet bytes share the bounded input buffer.
use anyhow::{Result, bail, ensure};
use serde::Serialize;
use std::sync::atomic::AtomicBool;

pub(crate) const MAX_SNAPLEN: u32 = 262_144;
const MAX_INTERFACES: usize = 32;

#[derive(Clone, Debug, Serialize)]
pub struct InterfaceMetadata {
    pub interface_id: u32,
    pub link_type: u16,
    pub snaplen: u32,
    pub timestamp_resolution_exponent: u8,
    pub timestamp_offset_seconds: i64,
    pub packets: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PcapngMetadata {
    pub minor_version: u16,
    pub declared_section_bytes: Option<u64>,
    pub interface_id: u32,
    pub link_type: u16,
    pub snaplen: u32,
    pub timestamp_resolution_exponent: u8,
    pub timestamp_offset_seconds: i64,
    pub blocks: u64,
    pub skipped_blocks: u64,
    pub skipped_options: u64,
    pub selection_explicit: bool,
    pub total_packets: u64,
    pub skipped_packets: u64,
    pub interfaces: Vec<InterfaceMetadata>,
}

#[derive(Debug)]
pub(crate) struct Info {
    pub format: &'static str,
    pub nano: bool,
    pub pcapng: Option<PcapngMetadata>,
}

pub(crate) struct Packet<'a> {
    pub index: u64,
    pub timestamp: u64,
    pub original: u32,
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy)]
struct Order(bool);
impl Order {
    fn word(self, bytes: &[u8], at: usize) -> u16 {
        let value = [bytes[at], bytes[at + 1]];
        if self.0 {
            u16::from_le_bytes(value)
        } else {
            u16::from_be_bytes(value)
        }
    }
    fn number(self, bytes: &[u8], at: usize) -> u32 {
        let value = [bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]];
        if self.0 {
            u32::from_le_bytes(value)
        } else {
            u32::from_be_bytes(value)
        }
    }
    fn signed(self, bytes: &[u8], at: usize) -> i64 {
        let value: [u8; 8] = bytes[at..at + 8]
            .try_into()
            .expect("validated 8-byte field");
        if self.0 {
            i64::from_le_bytes(value)
        } else {
            i64::from_be_bytes(value)
        }
    }
}

#[cfg(test)]
pub(crate) fn packets<'a>(
    bytes: &'a [u8],
    stop: Option<&AtomicBool>,
    visit: impl FnMut(Packet<'a>) -> Result<()>,
) -> Result<Info> {
    selected_packets(bytes, stop, None, visit)
}

pub(crate) fn selected_packets<'a>(
    bytes: &'a [u8],
    stop: Option<&AtomicBool>,
    interface: Option<u32>,
    mut visit: impl FnMut(Packet<'a>) -> Result<()>,
) -> Result<Info> {
    ensure!(bytes.len() >= 24, "capture header truncated");
    if bytes[..4] == [0x0a, 0x0d, 0x0d, 0x0a] {
        return pcapng(bytes, stop, interface, visit);
    }
    ensure!(interface.is_none(), "interface selection requires PCAPNG");
    let (order, nano) = match &bytes[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (Order(true), false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (Order(false), false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (Order(true), true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Order(false), true),
        _ => bail!("unsupported PCAP/PCAPNG magic"),
    };
    ensure!(
        order.word(bytes, 4) == 2 && order.word(bytes, 6) == 4,
        "only PCAP version 2.4 is supported"
    );
    let snaplen = order.number(bytes, 16);
    ensure!(
        (1..=MAX_SNAPLEN).contains(&snaplen),
        "PCAP snaplen must be 1..262144"
    );
    ensure!(
        order.number(bytes, 20) == 1,
        "only Ethernet link type 1 without additional FCS flags is supported"
    );
    let mut offset = 24;
    let mut index = 0;
    while offset < bytes.len() {
        crate::review::check_cancel(stop)?;
        ensure!(index < 1_000_000, "capture exceeds one million packets");
        index += 1;
        ensure!(bytes.len() - offset >= 16, "truncated PCAP packet header");
        let header = &bytes[offset..offset + 16];
        let seconds = order.number(header, 0) as u64;
        let fraction = order.number(header, 4) as u64;
        ensure!(
            fraction < if nano { 1_000_000_000 } else { 1_000_000 },
            "PCAP timestamp fraction out of range"
        );
        let timestamp = seconds * 1_000_000_000 + fraction * if nano { 1 } else { 1000 };
        let captured = order.number(header, 8);
        let original = order.number(header, 12);
        ensure!(
            captured <= snaplen && captured <= original,
            "invalid PCAP captured/original packet lengths"
        );
        offset += 16;
        ensure!(
            captured as usize <= bytes.len() - offset,
            "truncated PCAP packet data"
        );
        visit(Packet {
            index,
            timestamp,
            original,
            bytes: &bytes[offset..offset + captured as usize],
        })?;
        offset += captured as usize;
    }
    Ok(Info {
        format: "pcap",
        nano,
        pcapng: None,
    })
}

fn block(bytes: &[u8], offset: usize, order: Order) -> Result<(u32, &[u8], usize)> {
    ensure!(bytes.len() - offset >= 12, "truncated PCAPNG block header");
    let length = order.number(bytes, offset + 4) as usize;
    ensure!(
        length >= 12 && length.is_multiple_of(4),
        "invalid PCAPNG block length/alignment"
    );
    ensure!(
        length <= bytes.len() - offset,
        "truncated PCAPNG block data"
    );
    let end = offset + length;
    ensure!(
        order.number(bytes, end - 4) as usize == length,
        "PCAPNG repeated block length differs"
    );
    Ok((
        order.number(bytes, offset),
        &bytes[offset + 8..end - 4],
        end,
    ))
}

fn options(
    bytes: &[u8],
    order: Order,
    stop: Option<&AtomicBool>,
    mut visit: impl FnMut(u16, &[u8]) -> Result<()>,
) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        crate::review::check_cancel(stop)?;
        ensure!(bytes.len() - offset >= 4, "truncated PCAPNG option header");
        let code = order.word(bytes, offset);
        let length = order.word(bytes, offset + 2) as usize;
        offset += 4;
        if code == 0 {
            ensure!(
                length == 0 && offset == bytes.len(),
                "invalid PCAPNG option terminator or trailing bytes"
            );
            return Ok(());
        }
        let padded = (length + 3) & !3;
        ensure!(
            padded <= bytes.len() - offset,
            "truncated PCAPNG option value/padding"
        );
        visit(code, &bytes[offset..offset + length])?;
        offset += padded;
    }
    Ok(())
}

fn unique(seen: &mut u8, mask: u8, value: &[u8], length: usize) -> Result<()> {
    ensure!(
        *seen & mask == 0 && value.len() == length,
        "duplicate or wrong-sized PCAPNG timing/FCS/flags option"
    );
    *seen |= mask;
    Ok(())
}

fn pcapng<'a>(
    bytes: &'a [u8],
    stop: Option<&AtomicBool>,
    selected: Option<u32>,
    mut visit: impl FnMut(Packet<'a>) -> Result<()>,
) -> Result<Info> {
    ensure!(
        selected.is_none_or(|id| id < MAX_INTERFACES as u32),
        "PCAPNG interface ID must be 0..31"
    );
    let order = match &bytes[8..12] {
        [0x4d, 0x3c, 0x2b, 0x1a] => Order(true),
        [0x1a, 0x2b, 0x3c, 0x4d] => Order(false),
        _ => bail!("invalid PCAPNG byte-order magic"),
    };
    let (_, section, mut offset) = block(bytes, 0, order)?;
    ensure!(section.len() >= 16, "truncated PCAPNG section header");
    let minor = order.word(section, 6);
    ensure!(
        order.word(section, 4) == 1 && matches!(minor, 0 | 2),
        "unsupported PCAPNG section version"
    );
    let declared = order.signed(section, 8);
    ensure!(
        declared == -1 || (declared >= 0 && declared as usize == bytes.len() - offset),
        "PCAPNG declared section length differs or is invalid"
    );
    let mut metadata = PcapngMetadata {
        minor_version: minor,
        declared_section_bytes: (declared >= 0).then_some(declared as u64),
        interface_id: selected.unwrap_or(0),
        link_type: 1,
        snaplen: 0,
        timestamp_resolution_exponent: 6,
        timestamp_offset_seconds: 0,
        blocks: 1,
        skipped_blocks: 0,
        skipped_options: 0,
        selection_explicit: selected.is_some(),
        total_packets: 0,
        skipped_packets: 0,
        interfaces: Vec::new(),
    };
    options(&section[16..], order, stop, |_, _| {
        metadata.skipped_options += 1;
        Ok(())
    })?;
    while offset < bytes.len() {
        crate::review::check_cancel(stop)?;
        ensure!(
            metadata.blocks < 1_000_000,
            "PCAPNG exceeds one million blocks"
        );
        ensure!(
            !bytes[offset..].starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]),
            "multiple PCAPNG sections are unsupported; select one section/interface"
        );
        let (kind, body, end) = block(bytes, offset, order)?;
        metadata.blocks += 1;
        match kind {
            1 => {
                ensure!(
                    metadata.interfaces.len() < MAX_INTERFACES,
                    "PCAPNG exceeds 32 interface descriptors"
                );
                ensure!(body.len() >= 8, "truncated PCAPNG interface descriptor");
                ensure!(
                    order.word(body, 2) == 0,
                    "PCAPNG interface reserved bits must be clear"
                );
                let mut interface = InterfaceMetadata {
                    interface_id: metadata.interfaces.len() as u32,
                    link_type: order.word(body, 0),
                    snaplen: order.number(body, 4),
                    timestamp_resolution_exponent: 6,
                    timestamp_offset_seconds: 0,
                    packets: 0,
                };
                ensure!(
                    (1..=MAX_SNAPLEN).contains(&interface.snaplen),
                    "PCAPNG snaplen must be 1..262144"
                );
                let mut seen = 0;
                options(&body[8..], order, stop, |code, value| {
                    match code {
                        9 => {
                            unique(&mut seen, 1, value, 1)?;
                            ensure!(
                                matches!(value[0], 6 | 9),
                                "PCAPNG supports decimal microsecond or nanosecond resolution only"
                            );
                            interface.timestamp_resolution_exponent = value[0];
                        }
                        14 => {
                            unique(&mut seen, 2, value, 8)?;
                            interface.timestamp_offset_seconds = order.signed(value, 0);
                        }
                        13 => {
                            unique(&mut seen, 4, value, 1)?;
                            ensure!(value[0] == 0, "declared PCAPNG FCS is unsupported");
                        }
                        _ => metadata.skipped_options += 1,
                    }
                    Ok(())
                })?;
                metadata.interfaces.push(interface);
            }
            6 => {
                ensure!(
                    !metadata.interfaces.is_empty() && body.len() >= 20,
                    "PCAPNG enhanced packet requires a prior interface and full header"
                );
                let id = order.number(body, 0);
                let interface = metadata.interfaces.get_mut(id as usize).ok_or_else(|| {
                    anyhow::anyhow!(
                        "PCAPNG packet references an interface without a prior descriptor"
                    )
                })?;
                let captured = order.number(body, 12) as usize;
                let original = order.number(body, 16);
                ensure!(
                    captured <= interface.snaplen as usize && captured <= original as usize,
                    "invalid PCAPNG captured/original lengths"
                );
                let padded = (captured + 3) & !3;
                ensure!(
                    padded <= body.len() - 20,
                    "truncated PCAPNG packet data/padding"
                );
                let mut seen = 0;
                options(&body[20 + padded..], order, stop, |code, value| {
                    if code == 2 {
                        unique(&mut seen, 1, value, 4)?;
                        let flags = order.number(value, 0);
                        ensure!(
                            flags & !0x1f == 0 && flags & 3 != 3 && (flags >> 2) <= 4,
                            "PCAPNG FCS/offload/error/reserved packet flags are unsupported"
                        );
                    }
                    metadata.skipped_options += 1;
                    Ok(())
                })?;
                let ticks = ((order.number(body, 4) as u64) << 32) | order.number(body, 8) as u64;
                let timestamp = ticks as i128
                    * if interface.timestamp_resolution_exponent == 6 {
                        1000
                    } else {
                        1
                    }
                    + interface.timestamp_offset_seconds as i128 * 1_000_000_000;
                ensure!(
                    (0..=i64::MAX as i128).contains(&timestamp),
                    "PCAPNG timestamp outside supported Unix nanosecond range"
                );
                ensure!(
                    metadata.total_packets < 1_000_000,
                    "capture exceeds one million packets"
                );
                metadata.total_packets += 1;
                interface.packets += 1;
                if id == metadata.interface_id {
                    visit(Packet {
                        index: metadata.total_packets,
                        timestamp: timestamp as u64,
                        original,
                        bytes: &body[20..20 + captured],
                    })?;
                } else {
                    metadata.skipped_packets += 1;
                }
            }
            0 | 2 | 3 => {
                bail!("invalid, obsolete or untimestamped PCAPNG packet block is unsupported")
            }
            _ => metadata.skipped_blocks += 1,
        }
        offset = end;
    }
    ensure!(
        !metadata.interfaces.is_empty(),
        "PCAPNG requires an interface descriptor"
    );
    if selected.is_none() && metadata.interfaces.len() != 1 {
        let choices = metadata
            .interfaces
            .iter()
            .map(|i| {
                format!(
                    "{} (link {}, {} packets)",
                    i.interface_id, i.link_type, i.packets
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "PCAPNG contains multiple interfaces: {choices}; select --interface ID (desktop: PCAPNG interface)"
        );
    }
    let interface = metadata
        .interfaces
        .get(metadata.interface_id as usize)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "selected PCAPNG interface {} is not present",
                metadata.interface_id
            )
        })?;
    ensure!(
        interface.link_type == 1,
        "selected PCAPNG interface must use Ethernet link type 1"
    );
    metadata.link_type = interface.link_type;
    metadata.snaplen = interface.snaplen;
    metadata.timestamp_resolution_exponent = interface.timestamp_resolution_exponent;
    metadata.timestamp_offset_seconds = interface.timestamp_offset_seconds;
    Ok(Info {
        format: "pcapng",
        nano: metadata.timestamp_resolution_exponent == 9,
        pcapng: Some(metadata),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(little: bool, value: u16) -> [u8; 2] {
        if little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        }
    }
    fn number(little: bool, value: u32) -> [u8; 4] {
        if little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        }
    }
    fn signed(little: bool, value: i64) -> [u8; 8] {
        if little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        }
    }
    fn block(little: bool, kind: u32, mut body: Vec<u8>) -> Vec<u8> {
        while !body.len().is_multiple_of(4) {
            body.push(0);
        }
        let length = body.len() as u32 + 12;
        let mut bytes = number(little, kind).to_vec();
        bytes.extend(number(little, length));
        bytes.extend(body);
        bytes.extend(number(little, length));
        bytes
    }
    fn option(little: bool, code: u16, value: &[u8]) -> Vec<u8> {
        let mut bytes = word(little, code).to_vec();
        bytes.extend(word(little, value.len() as u16));
        bytes.extend(value);
        while !bytes.len().is_multiple_of(4) {
            bytes.push(0);
        }
        bytes
    }
    fn section(little: bool) -> Vec<u8> {
        let mut body = number(little, 0x1a2b3c4d).to_vec();
        body.extend(word(little, 1));
        body.extend(word(little, 0));
        body.extend(signed(little, -1));
        block(little, 0x0a0d0d0a, body)
    }
    fn interface(little: bool, options: Vec<u8>) -> Vec<u8> {
        let mut body = word(little, 1).to_vec();
        body.extend(word(little, 0));
        body.extend(number(little, 65535));
        body.extend(options);
        block(little, 1, body)
    }
    fn packet(little: bool, ticks: u64, options: Vec<u8>) -> Vec<u8> {
        let mut body = Vec::new();
        for n in [0, (ticks >> 32) as u32, ticks as u32, 1, 1] {
            body.extend(number(little, n));
        }
        body.extend([42, 0x55, 0x55, 0x55]); // padding is not packet data and need not be zero
        body.extend(options);
        block(little, 6, body)
    }
    fn fixture(little: bool, options: Vec<u8>, ticks: u64) -> Vec<u8> {
        [
            section(little),
            interface(little, options),
            packet(little, ticks, Vec::new()),
        ]
        .concat()
    }
    fn inspect(bytes: &[u8]) -> Result<Info> {
        packets(bytes, None, |_| Ok(()))
    }

    #[test]
    fn pcapng_byte_orders_precisions_offsets_and_metadata_are_exact() {
        for little in [false, true] {
            for nano in [false, true] {
                for offset in [-2i64, 3] {
                    let mut opts = option(little, 9, &[if nano { 9 } else { 6 }]);
                    opts.extend(option(little, 14, &signed(little, offset)));
                    opts.extend(option(little, 2, b"Authored interface"));
                    let unit = if nano { 1_000_000_000u64 } else { 1_000_000 };
                    let fraction = if nano { 123_456_789 } else { 123_456 };
                    let mut bytes = fixture(little, opts, 1_700_000_000 * unit + fraction);
                    bytes.extend(block(little, 0x12345678, vec![1, 2, 3, 4]));
                    let mut observed = Vec::new();
                    let info = packets(&bytes, None, |packet| {
                        observed.push((packet.timestamp, packet.original, packet.bytes.to_vec()));
                        Ok(())
                    })
                    .unwrap();
                    assert_eq!(info.format, "pcapng");
                    assert_eq!(info.nano, nano);
                    let fraction_ns = fraction * if nano { 1 } else { 1000 };
                    assert_eq!(
                        observed,
                        vec![(
                            ((1_700_000_000i64 + offset) as u64) * 1_000_000_000 + fraction_ns,
                            1,
                            vec![42]
                        )]
                    );
                    let metadata = info.pcapng.unwrap();
                    assert_eq!(metadata.timestamp_offset_seconds, offset);
                    assert_eq!(metadata.skipped_options, 1);
                    assert_eq!(metadata.skipped_blocks, 1);
                    assert_eq!(metadata.blocks, 4);
                    let length = bytes.len() - 28;
                    bytes[16..24].copy_from_slice(&signed(little, length as i64));
                    bytes[14..16].copy_from_slice(&word(little, 2)); // equivalent legacy minor version
                    let info = inspect(&bytes).unwrap().pcapng.unwrap();
                    assert_eq!(info.declared_section_bytes, Some(length as u64));
                    assert_eq!(info.minor_version, 2);
                }
            }
        }
        let bytes = fixture(true, Vec::new(), 1);
        let mut time = 0;
        let info = packets(&bytes, None, |p| {
            time = p.timestamp;
            Ok(())
        })
        .unwrap();
        assert_eq!(time, 1000);
        assert!(!info.nano);
    }

    #[test]
    fn pcapng_rejects_truncation_repeated_lengths_and_invalid_section_or_packet_fields() {
        let bytes = fixture(true, Vec::new(), 1);
        assert_eq!(bytes.len(), 84);
        for end in 0..bytes.len() {
            if end != 48 {
                assert!(inspect(&bytes[..end]).is_err(), "prefix {end}");
            }
        }
        assert!(inspect(&bytes[..48]).is_ok()); // descriptor with no packets
        for (at, value) in [
            (4, 0u32),
            (4, 27),
            (8, 0),
            (12, 2),
            (16, 2),
            (36, 101),
            (40, 0),
            (52, u32::MAX),
            (56, 1),
            (68, 2),
            (72, 0),
            (80, 12),
        ] {
            let mut bad = bytes.clone();
            bad[at..at + 4].copy_from_slice(&value.to_le_bytes());
            assert!(inspect(&bad).is_err(), "offset {at}, value {value}");
        }
        assert!(inspect(&[bytes.clone(), section(false)].concat()).is_err());
        assert!(inspect(&[bytes.clone(), interface(true, Vec::new())].concat()).is_err());
        for kind in [0, 2, 3] {
            assert!(
                inspect(&[bytes[..48].to_vec(), block(true, kind, vec![0; 8])].concat()).is_err()
            );
        }
        assert!(
            inspect(
                &[
                    section(true),
                    packet(true, 1, Vec::new()),
                    interface(true, Vec::new())
                ]
                .concat()
            )
            .is_err()
        );
    }

    #[test]
    fn pcapng_validates_options_and_rejects_lossy_clocks_fcs_and_error_flags() {
        for opts in [
            option(true, 9, &[0]),
            option(true, 9, &[7]),
            option(true, 9, &[0x89]),
            option(true, 9, &[]),
            option(true, 14, &[0; 7]),
            option(true, 13, &[32]),
            [option(true, 9, &[6]), option(true, 9, &[9])].concat(),
            [option(true, 0, &[]), option(true, 1, b"after end")].concat(),
            vec![1, 0, 8, 0, 1, 2, 3, 4],
        ] {
            assert!(inspect(&fixture(true, opts, 1)).is_err());
        }
        for flags in [3u32, 0x1c, 0x20, 0x200, 0x01000000] {
            let bytes = [
                section(true),
                interface(true, Vec::new()),
                packet(true, 1, option(true, 2, &flags.to_le_bytes())),
            ]
            .concat();
            assert!(inspect(&bytes).is_err(), "flags {flags:#x}");
        }
        let bytes = [
            section(true),
            interface(true, option(true, 13, &[0])),
            packet(true, 1, option(true, 2, &2u32.to_le_bytes())),
        ]
        .concat();
        assert_eq!(inspect(&bytes).unwrap().pcapng.unwrap().skipped_options, 1);
    }

    #[test]
    fn pcapng_bounds_timestamp_arithmetic_without_rounding_or_overflow() {
        for offset in [i64::MIN, -2, i64::MAX] {
            assert!(inspect(&fixture(true, option(true, 14, &offset.to_le_bytes()), 0)).is_err());
        }
        assert!(inspect(&fixture(true, Vec::new(), u64::MAX)).is_err());
        assert!(inspect(&fixture(true, option(true, 9, &[9]), u64::MAX)).is_err());
        let bytes = fixture(true, option(true, 9, &[9]), i64::MAX as u64);
        let mut time = 0;
        packets(&bytes, None, |p| {
            time = p.timestamp;
            Ok(())
        })
        .unwrap();
        assert_eq!(time, i64::MAX as u64);
    }

    #[test]
    fn pcapng_observes_cancellation_between_packet_blocks() {
        use std::sync::atomic::Ordering::Relaxed;
        let mut bytes = fixture(true, Vec::new(), 1);
        bytes.extend(packet(true, 2, Vec::new()));
        let stop = AtomicBool::new(false);
        let mut count = 0;
        let error = packets(&bytes, Some(&stop), |_| {
            count += 1;
            stop.store(true, Relaxed);
            Ok(())
        })
        .unwrap_err();
        assert_eq!(count, 1);
        assert!(error.to_string().contains("cancelled"));
    }

    #[test]
    fn selection_keeps_interface_clocks_packet_indexes_and_counts_separate() {
        for little in [false, true] {
            let mut other = interface(little, Vec::new());
            other[8..10].copy_from_slice(&word(little, 101)); // An excluded non-Ethernet link.
            let selected = interface(
                little,
                [
                    option(little, 9, &[9]),
                    option(little, 14, &signed(little, -2)),
                ]
                .concat(),
            );
            let epb = |id: u32, ticks: u64| {
                let mut p = packet(little, ticks, Vec::new());
                p[8..12].copy_from_slice(&number(little, id));
                p
            };
            let bytes = [
                section(little),
                other,
                selected,
                epb(0, 10),
                epb(1, 3_000_000_001),
                epb(0, 1),
                epb(1, 3_000_001_001),
            ]
            .concat();
            assert!(
                inspect(&bytes)
                    .unwrap_err()
                    .to_string()
                    .contains("multiple interfaces")
            );
            let mut observed = Vec::new();
            let info = selected_packets(&bytes, None, Some(1), |p| {
                observed.push((p.index, p.timestamp, p.bytes.to_vec()));
                Ok(())
            })
            .unwrap();
            assert_eq!(
                observed,
                vec![(2, 1_000_000_001, vec![42]), (4, 1_000_001_001, vec![42])]
            );
            assert!(info.nano);
            let m = info.pcapng.unwrap();
            assert_eq!(
                (m.interface_id, m.total_packets, m.skipped_packets),
                (1, 4, 2)
            );
            assert!(m.selection_explicit);
            assert_eq!(
                m.interfaces.iter().map(|i| i.packets).collect::<Vec<_>>(),
                vec![2, 2]
            );
            assert!(
                selected_packets(&bytes, None, Some(0), |_| Ok(()))
                    .unwrap_err()
                    .to_string()
                    .contains("Ethernet")
            );
            assert!(
                selected_packets(&bytes, None, Some(2), |_| Ok(()))
                    .unwrap_err()
                    .to_string()
                    .contains("not present")
            );
            assert!(selected_packets(&bytes, None, Some(32), |_| Ok(())).is_err());
        }
    }

    #[test]
    fn selection_still_validates_excluded_records_and_bounds_interface_inventory() {
        let mut bytes = [
            section(true),
            interface(true, Vec::new()),
            interface(true, Vec::new()),
            packet(true, 1, Vec::new()),
        ]
        .concat();
        let record = bytes.len() - 36;
        bytes[record + 24..record + 28].copy_from_slice(&0u32.to_le_bytes()); // Original length smaller than captured on excluded ID 0.
        assert!(
            selected_packets(&bytes, None, Some(1), |_| Ok(()))
                .unwrap_err()
                .to_string()
                .contains("lengths")
        );
        let mut bytes = section(true);
        for _ in 0..32 {
            bytes.extend(interface(true, Vec::new()));
        }
        assert_eq!(
            selected_packets(&bytes, None, Some(31), |_| Ok(()))
                .unwrap()
                .pcapng
                .unwrap()
                .interfaces
                .len(),
            32
        );
        bytes.extend(interface(true, Vec::new()));
        assert!(
            selected_packets(&bytes, None, Some(31), |_| Ok(()))
                .unwrap_err()
                .to_string()
                .contains("32 interface")
        );
        let bytes = [
            section(true),
            interface(true, Vec::new()),
            packet(true, 1, Vec::new()),
            interface(true, Vec::new()),
        ]
        .concat();
        let stop = AtomicBool::new(true);
        assert!(
            selected_packets(&bytes, Some(&stop), Some(1), |_| Ok(()))
                .unwrap_err()
                .to_string()
                .contains("cancelled")
        );
    }
}

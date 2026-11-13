//! Typed RxPDO preparation in memory only. No bus or output publishing capability.
use crate::model::{Field, Identity, Kind, MAX_FIELDS, MAX_PAYLOAD, Profile, Source, payload_hex};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Assignment {
    pub field: usize,
    pub value: String,
}

impl Assignment {
    pub fn parse(text: &str) -> Result<Self> {
        let (field, value) = text
            .split_once('=')
            .context("assignment must be zero-based INDEX=VALUE")?;
        Ok(Self {
            field: field
                .trim()
                .parse()
                .context("field index must be a nonnegative integer")?,
            value: value.into(),
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Impact {
    pub field: usize,
    pub name: String,
    pub kind: Kind,
    pub bit: usize,
    pub width: usize,
    pub mapping_source: Source,
    pub selected: bool,
    pub bits_changed: bool,
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Review {
    pub schema: u32,
    pub app_version: String,
    pub scope: String,
    pub profile_name: String,
    pub profile_sha256: String,
    pub expected_identity: Option<Identity>,
    pub rx_bytes: usize,
    pub value_source: String,
    pub initialized_from_zero: bool,
    pub before_hex: String,
    pub after_hex: String,
    pub changed_bits: u32,
    pub assignments: Vec<Assignment>,
    pub impacts: Vec<Impact>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Plan {
    review: Review,
    candidate: Vec<u8>,
}

fn profile_hash(profile: &Profile) -> Result<String> {
    Ok(crate::benchmark::hash(&serde_json::to_vec(profile)?))
}

impl Plan {
    pub fn review(&self) -> &Review {
        &self.review
    }

    /// Only changes the saved offline bytes. A stale preview cannot be applied.
    pub fn apply(&self, profile: &mut Profile) -> Result<()> {
        ensure!(
            profile_hash(profile)? == self.review.profile_sha256,
            "profile changed since preview; build a new typed staging preview"
        );
        let mut candidate = profile.clone();
        candidate.staged_rx_hex = hex::encode_upper(&self.candidate);
        candidate.validate()?;
        profile.staged_rx_hex = candidate.staged_rx_hex;
        Ok(())
    }
}

pub fn prepare(
    profile: &Profile,
    assignments: &[Assignment],
    initialize_zero: bool,
) -> Result<Plan> {
    profile.validate()?;
    ensure!(
        profile.rx_bytes > 0,
        "configure a nonempty RxPDO image before staging"
    );
    ensure!(
        (1..=MAX_FIELDS).contains(&assignments.len()),
        "select 1–128 typed RxPDO assignments"
    );
    let blank = profile.staged_rx_hex.trim().is_empty();
    ensure!(
        !initialize_zero || blank,
        "zero initialization requires an empty staged image; existing bytes are preserved"
    );
    ensure!(
        !blank || initialize_zero,
        "no staged RxPDO image; explicitly initialize the offline image from zero first"
    );
    let before = if blank {
        vec![0; profile.rx_bytes]
    } else {
        payload_hex(&profile.staged_rx_hex)?
    };
    let mut candidate = before.clone();
    let mut assigned = vec![0u8; candidate.len()];
    let mut selected = HashSet::new();
    for assignment in assignments {
        ensure!(
            selected.insert(assignment.field),
            "duplicate assignment for RxPDO field {}",
            assignment.field
        );
        let field = profile
            .rx
            .get(assignment.field)
            .context("RxPDO field index out of range")?;
        let encoded = encode(field, &assignment.value)
            .with_context(|| format!("RxPDO field {} ({})", assignment.field, field.name))?;
        for offset in 0..field.width {
            let bit = field.bit + offset;
            let mask = 1u8 << (bit % 8);
            let value = ((encoded[offset / 8] >> (offset % 8)) & 1) != 0;
            ensure!(
                assigned[bit / 8] & mask == 0 || (candidate[bit / 8] & mask != 0) == value,
                "RxPDO field {} ({}) conflicts with an earlier assignment at bit {bit}",
                assignment.field,
                field.name
            );
            if value {
                candidate[bit / 8] |= mask;
            } else {
                candidate[bit / 8] &= !mask;
            }
            assigned[bit / 8] |= mask;
        }
    }
    let changed_bits = before
        .iter()
        .zip(&candidate)
        .map(|(a, b)| (a ^ b).count_ones())
        .sum();
    let impacts = profile
        .rx
        .iter()
        .enumerate()
        .filter_map(|(index, field)| {
            let bits_changed = field.changed(&before, &candidate);
            (selected.contains(&index) || bits_changed).then(|| Impact {
                field: index,
                name: field.name.clone(),
                kind: field.kind,
                bit: field.bit,
                width: field.width,
                mapping_source: field.source.clone(),
                selected: selected.contains(&index),
                bits_changed,
                before: field.decode(&before),
                after: field.decode(&candidate),
            })
        })
        .collect();
    Ok(Plan { candidate: candidate.clone(), review: Review {
        schema: 1, app_version: env!("CARGO_PKG_VERSION").into(), scope: "offline_rxpdo_only".into(),
        profile_name: profile.name.clone(), profile_sha256: profile_hash(profile)?,
        expected_identity: profile.expected_identity.clone(), rx_bytes: profile.rx_bytes,
        value_source: "manual_offline".into(), initialized_from_zero: blank,
        before_hex: hex::encode_upper(before), after_hex: hex::encode_upper(candidate), changed_bits,
        assignments: assignments.to_vec(), impacts,
        notes: vec!["Values were entered manually for an offline image. Mapping provenance describes field definitions, not the source or suitability of output values.".into(),
            "Only selected bits are replaced; padding and other bytes are preserved. Changed overlapping views are listed. Conflicting simultaneous assignments are rejected.".into(),
            "This preview grants no bus permission. Applying or saving it changes profile bytes only; OP, live outputs and configuration writes require separate approval and implementation.".into()],
    } })
}

fn encode(field: &Field, text: &str) -> Result<Vec<u8>> {
    ensure!(
        text.len() <= MAX_PAYLOAD * 3,
        "typed value exceeds 3072 bytes"
    );
    let text = text.trim();
    ensure!(!text.is_empty(), "enter a typed value");
    if field.kind == Kind::Raw {
        let bytes = payload_hex(text)?;
        ensure!(
            bytes.len() == field.width / 8,
            "raw value must contain exactly {} bytes",
            field.width / 8
        );
        return Ok(bytes);
    }
    let bits = match field.kind {
        Kind::Unsigned => {
            ensure!(
                !text.starts_with(['+', '-']),
                "unsigned value cannot have a sign"
            );
            let value = if let Some(digits) =
                text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"))
            {
                u64::from_str_radix(digits, 16).context("invalid hexadecimal unsigned integer")?
            } else {
                text.parse::<u64>()
                    .context("invalid decimal unsigned integer")?
            };
            ensure!(
                field.width == 64 || value < (1u64 << field.width),
                "unsigned value exceeds {} bits",
                field.width
            );
            value
        }
        Kind::Signed => {
            let value = text
                .parse::<i64>()
                .context("signed value must be a decimal i64")?;
            let limit = 1i128 << (field.width - 1);
            ensure!(
                (-(limit)..limit).contains(&(value as i128)),
                "signed value exceeds {} bits",
                field.width
            );
            (value as u64)
                & if field.width == 64 {
                    u64::MAX
                } else {
                    (1u64 << field.width) - 1
                }
        }
        Kind::Bool => {
            if text.eq_ignore_ascii_case("true") || text == "1" {
                1
            } else if text.eq_ignore_ascii_case("false") || text == "0" {
                0
            } else {
                bail!("boolean value must be true, false, 1 or 0");
            }
        }
        Kind::F32 => {
            let value = text.parse::<f32>().context("invalid f32 value")?;
            ensure!(value.is_finite(), "typed floating values must be finite");
            value.to_bits() as u64
        }
        Kind::F64 => {
            let value = text.parse::<f64>().context("invalid f64 value")?;
            ensure!(value.is_finite(), "typed floating values must be finite");
            value.to_bits()
        }
        Kind::Raw => unreachable!(),
    };
    let mut bytes = bits.to_le_bytes()[..field.width.div_ceil(8)].to_vec();
    // Reverse the decoder's transforms, in inverse order.
    if field.big_endian {
        bytes.reverse();
    }
    if field.reverse_words {
        let size = bytes.len();
        for word in 0..size / 4 {
            let other = size / 2 - 1 - word;
            bytes.swap(2 * word, 2 * other);
            bytes.swap(2 * word + 1, 2 * other + 1);
        }
    }
    if field.swap_bytes_in_words {
        for word in bytes.as_chunks_mut::<2>().0 {
            word.swap(0, 1);
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(field: Field, bytes: usize) -> Profile {
        Profile {
            rx_bytes: bytes,
            rx: vec![field],
            staged_rx_hex: "A5".repeat(bytes),
            ..Profile::default()
        }
    }
    fn set(field: usize, value: &str) -> Assignment {
        Assignment {
            field,
            value: value.into(),
        }
    }

    #[test]
    fn preserves_padding_and_reports_aliases_while_rejecting_conflicting_bits() {
        let mut profile = Profile {
            rx_bytes: 3,
            staged_rx_hex: "AA 55 CC".into(),
            rx: vec![
                Field {
                    name: "Odd width".into(),
                    bit: 3,
                    width: 5,
                    ..Field::default()
                },
                Field {
                    name: "Byte view".into(),
                    width: 8,
                    kind: Kind::Raw,
                    ..Field::default()
                },
                Field {
                    name: "High bit".into(),
                    bit: 7,
                    width: 1,
                    kind: Kind::Bool,
                    ..Field::default()
                },
            ],
            ..Profile::default()
        };
        let before = profile.clone();
        let plan = prepare(&profile, &[set(0, "7"), set(2, "false")], false).unwrap();
        assert_eq!(plan.review().after_hex, "3A55CC");
        assert_eq!(plan.review().changed_bits, 2);
        assert_eq!(profile, before);
        let alias = &plan.review().impacts[1];
        assert_eq!(alias.field, 1);
        assert!(!alias.selected && alias.bits_changed);
        assert_eq!(alias.before.as_deref(), Some("AA"));
        assert_eq!(alias.after.as_deref(), Some("3A"));
        let error = prepare(&profile, &[set(0, "7"), set(2, "true")], false).unwrap_err();
        assert!(error.to_string().contains("conflicts") && error.to_string().contains("bit 7"));
        assert_eq!(profile, before);
        plan.apply(&mut profile).unwrap();
        let mut expected = before;
        expected.staged_rx_hex = "3A55CC".into();
        assert_eq!(profile, expected);
    }

    #[test]
    fn all_numeric_transform_combinations_have_independent_byte_vectors() {
        let expected = [
            "44332211", "11223344", "33441122", "22114433", "22114433", "33441122", "11223344",
            "44332211",
        ];
        for (flags, expected) in expected.iter().enumerate() {
            let field = Field {
                width: 32,
                big_endian: flags & 1 != 0,
                swap_bytes_in_words: flags & 2 != 0,
                reverse_words: flags & 4 != 0,
                ..Field::default()
            };
            let profile = profile(field, 4);
            let plan = prepare(&profile, &[set(0, "0x11223344")], false).unwrap();
            assert_eq!(plan.review().after_hex, *expected);
            assert_eq!(plan.review().impacts[0].after.as_deref(), Some("287454020"));
        }
    }

    #[test]
    fn integer_width_boundaries_and_twos_complement_are_checked() {
        for (kind, width, value, expected) in [
            (
                Kind::Unsigned,
                64,
                "18446744073709551615",
                "FFFFFFFFFFFFFFFF",
            ),
            (Kind::Signed, 64, "-9223372036854775808", "0000000000000080"),
            (Kind::Signed, 8, "-128", "80"),
            (Kind::Signed, 8, "127", "7F"),
        ] {
            let profile = profile(
                Field {
                    width,
                    kind,
                    ..Field::default()
                },
                width / 8,
            );
            let plan = prepare(&profile, &[set(0, value)], false).unwrap();
            assert_eq!(plan.review().after_hex, expected);
        }
        for (kind, width, values) in [
            (
                Kind::Unsigned,
                3,
                vec!["8", "-1", "+1", "0x8", "18446744073709551616"],
            ),
            (
                Kind::Signed,
                3,
                vec!["4", "-5", "0xFF", "9223372036854775808"],
            ),
        ] {
            let profile = profile(
                Field {
                    width,
                    kind,
                    ..Field::default()
                },
                1,
            );
            for value in values {
                assert!(
                    prepare(&profile, &[set(0, value)], false).is_err(),
                    "{kind:?}: {value}"
                );
            }
        }
    }

    #[test]
    fn floats_boolean_and_raw_bytes_encode_without_changing_other_bits() {
        for (kind, width, value, expected) in [
            (Kind::F32, 32, "1.5", "0000C03F"),
            (Kind::F32, 32, "-0", "00000080"),
            (Kind::F64, 64, "1.5", "000000000000F83F"),
            (Kind::Raw, 24, "DE AD 00", "DEAD00"),
        ] {
            let profile = profile(
                Field {
                    width,
                    kind,
                    ..Field::default()
                },
                width / 8,
            );
            assert_eq!(
                prepare(&profile, &[set(0, value)], false)
                    .unwrap()
                    .review()
                    .after_hex,
                expected
            );
        }
        let profile = profile(
            Field {
                bit: 1,
                width: 1,
                kind: Kind::Bool,
                ..Field::default()
            },
            1,
        );
        assert_eq!(
            prepare(&profile, &[set(0, "TRUE")], false)
                .unwrap()
                .review()
                .after_hex,
            "A7"
        );
        assert_eq!(
            prepare(&profile, &[set(0, "0")], false)
                .unwrap()
                .review()
                .after_hex,
            "A5"
        );
        assert!(prepare(&profile, &[set(0, "2")], false).is_err());
        for kind in [Kind::F32, Kind::F64] {
            let width = if kind == Kind::F32 { 32 } else { 64 };
            let profile = self::profile(
                Field {
                    width,
                    kind,
                    ..Field::default()
                },
                width / 8,
            );
            for value in ["NaN", "inf", "-inf", "1e9999"] {
                assert!(prepare(&profile, &[set(0, value)], false).is_err());
            }
        }
        let raw = self::profile(
            Field {
                width: 16,
                kind: Kind::Raw,
                ..Field::default()
            },
            2,
        );
        for value in ["FF", "00 11 22", "0x1234", "GG"] {
            assert!(prepare(&raw, &[set(0, value)], false).is_err());
        }
    }

    #[test]
    fn zero_initialization_is_explicit_and_existing_images_are_preserved() {
        let mut profile = profile(
            Field {
                width: 8,
                ..Field::default()
            },
            2,
        );
        assert!(prepare(&profile, &[set(0, "1")], true).is_err());
        profile.staged_rx_hex.clear();
        assert!(prepare(&profile, &[set(0, "1")], false).is_err());
        let plan = prepare(&profile, &[set(0, "1")], true).unwrap();
        assert!(plan.review().initialized_from_zero);
        assert_eq!(plan.review().before_hex, "0000");
        assert_eq!(plan.review().after_hex, "0100");
        plan.apply(&mut profile).unwrap();
        assert_eq!(profile.staged_rx_hex, "0100");
        assert!(prepare(&profile, &[set(0, "2")], true).is_err());
        let unchanged = prepare(&profile, &[set(0, "1")], false).unwrap();
        assert_eq!(unchanged.review().changed_bits, 0);
        assert!(!unchanged.review().impacts[0].bits_changed);
    }

    #[test]
    fn stale_profiles_and_invalid_assignment_sets_never_apply() {
        let profile = profile(
            Field {
                width: 8,
                ..Field::default()
            },
            2,
        );
        let plan = prepare(&profile, &[set(0, "1")], false).unwrap();
        for change in 0..3 {
            let mut changed = profile.clone();
            match change {
                0 => changed.name = "Other profile".into(),
                1 => changed.rx[0].bit = 8,
                _ => changed.staged_rx_hex = "FFFF".into(),
            }
            let before = changed.clone();
            assert!(plan.apply(&mut changed).is_err());
            assert_eq!(changed, before);
        }
        for assignments in [
            vec![],
            vec![set(1, "1")],
            vec![set(0, "1"), set(0, "1")],
            vec![set(0, "")],
            vec![set(0, &"0".repeat(3073))],
        ] {
            assert!(prepare(&profile, &assignments, false).is_err());
        }
        assert!(Assignment::parse("-1=1").is_err());
        assert!(Assignment::parse("no equals").is_err());
        assert_eq!(Assignment::parse(" 0 =-2").unwrap(), set(0, "-2"));
    }
}

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, path::Path};

pub const MAX_PAYLOAD: usize = 1024;
pub const MAX_FIELDS: usize = 128;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub vendor: u32,
    pub product: u32,
    pub revision: u32,
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:#010x} / {:#010x} / {:#010x}",
            self.vendor, self.product, self.revision
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsiSource {
    pub file_name: String,
    pub sha256: String,
    pub device: String,
    pub identity: Identity,
    #[serde(default)]
    pub default_tx_bytes: Option<usize>,
    #[serde(default)]
    pub default_rx_bytes: Option<usize>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    #[default]
    Manual,
    Esi,
    Override,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    #[default]
    Unsigned,
    Signed,
    Bool,
    F32,
    F64,
    Raw,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Field {
    pub name: String,
    pub bit: usize,
    pub width: usize,
    pub kind: Kind,
    pub big_endian: bool,
    pub swap_bytes_in_words: bool,
    pub reverse_words: bool,
    pub log: bool,
    pub source: Source,
    pub pdo_index: Option<u16>,
    pub object_index: Option<u16>,
    pub subindex: Option<u8>,
}

impl Default for Field {
    fn default() -> Self {
        Self {
            name: "Value".into(),
            bit: 0,
            width: 16,
            kind: Kind::Unsigned,
            big_endian: false,
            swap_bytes_in_words: false,
            reverse_words: false,
            log: true,
            source: Source::Manual,
            pdo_index: None,
            object_index: None,
            subindex: None,
        }
    }
}

impl Field {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.name.trim().is_empty() && !self.name.contains(['\r', '\n']),
            "field name must be a nonempty single line"
        );
        let width_ok = match self.kind {
            Kind::Bool => self.width == 1,
            Kind::F32 => self.width == 32 && self.bit.is_multiple_of(8),
            Kind::F64 => self.width == 64 && self.bit.is_multiple_of(8),
            Kind::Raw => {
                self.width > 0 && self.width.is_multiple_of(8) && self.bit.is_multiple_of(8)
            }
            _ => (1..=64).contains(&self.width),
        };
        ensure!(
            width_ok,
            "{}: invalid width or alignment for {:?}",
            self.name,
            self.kind
        );
        ensure!(
            !(self.big_endian || self.swap_bytes_in_words || self.reverse_words)
                || (self.kind != Kind::Raw
                    && self.bit.is_multiple_of(8)
                    && self.width.is_multiple_of(8)),
            "{}: transforms require a byte-aligned numeric field",
            self.name
        );
        ensure!(
            !(self.swap_bytes_in_words || self.reverse_words) || self.width.is_multiple_of(16),
            "{}: word transforms require whole 16-bit words",
            self.name
        );
        Ok(())
    }

    pub fn fits(&self, bytes: usize) -> bool {
        self.bit
            .checked_add(self.width)
            .is_some_and(|end| end <= bytes * 8)
    }

    pub fn bits(&self, payload: &[u8]) -> Option<u64> {
        if self.kind == Kind::Raw || self.width == 0 || self.width > 64 || !self.fits(payload.len())
        {
            return None;
        }
        if self.bit.is_multiple_of(8) && self.width.is_multiple_of(8) {
            let mut bytes = [0u8; 8];
            let size = self.width / 8;
            let data = &mut bytes[..size];
            data.copy_from_slice(&payload[self.bit / 8..self.bit / 8 + size]);
            if self.swap_bytes_in_words {
                for word in data.as_chunks_mut::<2>().0 {
                    word.swap(0, 1);
                }
            }
            if self.reverse_words {
                for word in 0..size / 4 {
                    let other = size / 2 - 1 - word;
                    data.swap(2 * word, 2 * other);
                    data.swap(2 * word + 1, 2 * other + 1);
                }
            }
            if self.big_endian {
                data.reverse();
            }
            return Some(u64::from_le_bytes(bytes));
        }
        let mut value = 0;
        for offset in 0..self.width {
            let bit = self.bit + offset;
            value |= u64::from((payload[bit / 8] >> (bit % 8)) & 1) << offset;
        }
        Some(value)
    }

    fn raw<'a>(&self, payload: &'a [u8]) -> Option<&'a [u8]> {
        let end = self.bit.checked_add(self.width)?;
        payload.get(self.bit / 8..end / 8)
    }

    pub fn changed(&self, current: &[u8], previous: &[u8]) -> bool {
        if self.kind == Kind::Raw {
            return self.raw(current) != self.raw(previous);
        }
        self.bits(current) != self.bits(previous)
    }

    pub fn decode(&self, payload: &[u8]) -> Option<String> {
        if self.kind == Kind::Raw {
            return self.raw(payload).map(hex::encode_upper);
        }
        let bits = self.bits(payload)?;
        Some(match self.kind {
            Kind::Unsigned => bits.to_string(),
            Kind::Signed => {
                let shift = 64 - self.width;
                (((bits << shift) as i64) >> shift).to_string()
            }
            Kind::Bool => (bits != 0).to_string(),
            Kind::F32 => f32::from_bits(bits as u32).to_string(),
            Kind::F64 => f64::from_bits(bits).to_string(),
            Kind::Raw => unreachable!(),
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scheduler {
    #[default]
    Deadline,
    Relative,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogMode {
    #[default]
    Every,
    Change,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Profile {
    pub version: u32,
    pub name: String,
    pub nic: String,
    pub expected_identity: Option<Identity>,
    pub esi: Option<EsiSource>,
    pub requested_cycle_us: u64,
    pub scheduler: Scheduler,
    pub mode: LogMode,
    pub queue_capacity: usize,
    pub rotate_rows: u64,
    pub tx_bytes: usize,
    pub rx_bytes: usize,
    pub tx: Vec<Field>,
    pub rx: Vec<Field>,
    pub staged_rx_hex: String,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            version: 1,
            name: "New profile".into(),
            nic: String::new(),
            expected_identity: None,
            esi: None,
            requested_cycle_us: 1000,
            scheduler: Scheduler::Deadline,
            mode: LogMode::Every,
            queue_capacity: 4096,
            rotate_rows: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            tx: Vec::new(),
            rx: Vec::new(),
            staged_rx_hex: String::new(),
        }
    }
}

impl Profile {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "unsupported profile version {}",
            self.version
        );
        ensure!(
            (250..=1_000_000).contains(&self.requested_cycle_us),
            "cycle must be 250–1000000 µs"
        );
        ensure!(
            (1..=65_536).contains(&self.queue_capacity),
            "queue must hold 1–65536 samples"
        );
        for (len, fields) in [(self.tx_bytes, &self.tx), (self.rx_bytes, &self.rx)] {
            ensure!(
                len <= MAX_PAYLOAD && fields.len() <= MAX_FIELDS,
                "PDO image or field count exceeds the bench limit"
            );
            let mut names = HashSet::new();
            for field in fields {
                field.validate()?;
                ensure!(
                    field.fits(len),
                    "{} is outside the configured PDO image",
                    field.name
                );
                ensure!(
                    names.insert(&field.name),
                    "duplicate field name {:?}",
                    field.name
                );
                ensure!(
                    field.source != Source::Esi || self.esi.is_some(),
                    "ESI field is missing its source"
                );
            }
        }
        if !self.staged_rx_hex.trim().is_empty() {
            ensure!(
                payload_hex(&self.staged_rx_hex)?.len() == self.rx_bytes,
                "staged RxPDO length differs from profile"
            );
        }
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let profile: Self = serde_json::from_reader(
            std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?,
        )?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        use std::io::Write;
        self.validate()?;
        let text = serde_json::to_string_pretty(self)?;
        let mut file = std::fs::File::create_new(path)
            .with_context(|| format!("create {}", path.display()))?;
        writeln!(file, "{text}")?;
        file.sync_all()?;
        Ok(())
    }
}

pub fn payload_hex(value: &str) -> Result<Vec<u8>> {
    let clean: String = value.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if clean.len() > MAX_PAYLOAD * 2 {
        bail!("payload exceeds {MAX_PAYLOAD} bytes");
    }
    hex::decode(clean).context("use pairs of hexadecimal digits, with optional spaces")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_bit_offsets_signed_words_and_floats() {
        let mut field = Field {
            bit: 6,
            width: 5,
            kind: Kind::Signed,
            ..Field::default()
        };
        assert_eq!(field.decode(&[0xc0, 0x07]).as_deref(), Some("-1"));
        assert_eq!(field.decode(&[0xc0]), None);
        field = Field {
            width: 32,
            reverse_words: true,
            big_endian: true,
            ..Field::default()
        };
        assert_eq!(field.bits(&[0x33, 0x44, 0x11, 0x22]), Some(0x11223344));
        field = Field {
            width: 32,
            kind: Kind::F32,
            swap_bytes_in_words: true,
            ..Field::default()
        };
        assert_eq!(field.decode(&[0, 0, 0x3f, 0x80]).as_deref(), Some("1"));
    }
}

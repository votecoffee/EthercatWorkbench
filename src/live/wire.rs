pub const APRD: u8 = 0x01;
pub const FPRD: u8 = 0x04;
pub const BRD: u8 = 0x07;
pub const LRD: u8 = 0x0a;

const SOURCE: [u8; 6] = [0x10, 0x45, 0x43, 0x57, 0x42, 0x31];
pub const CUSTOM_REPLY: [u8; 6] = [0x12, 0x45, 0x43, 0x57, 0x42, 0x31];
pub const ETHERCRAB_REPLY: [u8; 6] = [0x12, 0x10, 0x10, 0x10, 0x10, 0x10];
const ETHERTYPE: [u8; 2] = [0x88, 0xa4];

#[derive(Clone, Copy)]
pub struct Datagram {
    pub command: u8,
    pub address: [u8; 4],
    pub len: usize,
}

impl Datagram {
    pub fn register(command: u8, station: u16, offset: u16, len: usize) -> Self {
        let [a, b] = station.to_le_bytes();
        let [c, d] = offset.to_le_bytes();
        Self {
            command,
            address: [a, b, c, d],
            len,
        }
    }
}

pub struct Frame<const N: usize> {
    bytes: [u8; 1514],
    end: usize,
    parts: [Datagram; N],
}

impl<const N: usize> Frame<N> {
    pub fn new(seq: u8, parts: [Datagram; N]) -> Self {
        let mut bytes = [0; 1514];
        bytes[..6].fill(0xff);
        bytes[6..12].copy_from_slice(&SOURCE);
        bytes[12..14].copy_from_slice(&ETHERTYPE);
        let mut end = 16;
        for (i, p) in parts.iter().enumerate() {
            assert!(matches!(p.command, APRD | FPRD | BRD | LRD));
            bytes[end] = p.command;
            bytes[end + 1] = seq;
            bytes[end + 2..end + 6].copy_from_slice(&p.address);
            let more = if i + 1 < N { 0x8000 } else { 0 };
            bytes[end + 6..end + 8].copy_from_slice(&(more | p.len as u16).to_le_bytes());
            end += 12 + p.len;
        }
        bytes[14..16].copy_from_slice(&(0x1000 | (end - 16) as u16).to_le_bytes());
        assert!(end <= bytes.len());
        Self { bytes, end, parts }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.end.max(60)]
    }

    pub fn reply<'a>(&self, bytes: &'a [u8]) -> Option<[(&'a [u8], u16); N]> {
        if bytes.len() < self.end
            || bytes[6..12] != CUSTOM_REPLY
            || bytes[12..16] != self.bytes[12..16]
        {
            return None;
        }
        let mut result = [(&[][..], 0); N];
        let mut offset = 16;
        for (i, part) in self.parts.iter().enumerate() {
            if bytes[offset..offset + 2] != self.bytes[offset..offset + 2]
                || bytes[offset + 4..offset + 7] != self.bytes[offset + 4..offset + 7]
                || bytes[offset + 7] & 0x87 != self.bytes[offset + 7]
                || (matches!(part.command, FPRD | LRD)
                    && bytes[offset + 2..offset + 4] != self.bytes[offset + 2..offset + 4])
            {
                return None;
            }
            let end = offset + 10 + part.len;
            result[i] = (&bytes[offset + 10..end], super::word(&bytes[end..end + 2]));
            offset = end + 2;
        }
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_outbound_stale_and_wrong_frames_and_keeps_both_counters() {
        let frame = Frame::new(
            8,
            [
                Datagram {
                    command: LRD,
                    address: [0; 4],
                    len: 2,
                },
                Datagram::register(FPRD, 0x1000, 0x0130, 6),
            ],
        );
        let mut raw = frame.bytes().to_vec();
        assert_eq!(&raw[12..20], &[0x88, 0xa4, 32, 0x10, 0x0a, 8, 0, 0]);
        assert!(frame.reply(&raw).is_none());
        raw[6..12].copy_from_slice(&CUSTOM_REPLY);
        raw[26..30].copy_from_slice(&[0xab, 0xcd, 1, 0]);
        raw[40] = 4;
        raw[46] = 1;
        assert_eq!(
            frame.reply(&raw),
            Some([(&[0xab, 0xcd][..], 1), (&[4, 0, 0, 0, 0, 0][..], 1)])
        );
        assert!(frame.reply(&raw[..47]).is_none());
        raw[17] = 9;
        assert!(frame.reply(&raw).is_none());
        raw[17] = 8;
        raw[32] = 0xaa;
        assert!(frame.reply(&raw).is_none());
    }
}

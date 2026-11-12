use crate::{
    model::{MAX_PAYLOAD, Profile},
    run::{Bus, Exchange},
    wire::{Frame, input_datagrams, input_reply},
};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{collections::VecDeque, path::Path, time::Instant};

const MAX_FIXTURE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FRAME_BYTES: usize = 1514;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    version: u32,
    origin: String,
    station_address: u16,
    tx_bytes: usize,
    exchanges: Vec<Recorded>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Recorded {
    request_hex: String,
    received_hex: Vec<String>,
}

struct RecordedExchange {
    request: Frame<2>,
    packets: Vec<Vec<u8>>,
}

pub struct Replay {
    pub origin: String,
    pub station_address: u16,
    exchanges: VecDeque<RecordedExchange>,
}

impl Replay {
    pub fn load(path: &Path, profile: &Profile) -> Result<Self> {
        let file =
            std::fs::File::open(path).with_context(|| format!("open replay {}", path.display()))?;
        ensure!(
            file.metadata()?.len() <= MAX_FIXTURE_BYTES,
            "replay fixture exceeds 16 MiB"
        );
        let fixture: Fixture =
            serde_json::from_reader(file).context("parse raw-frame replay fixture")?;
        ensure!(
            fixture.version == 1,
            "unsupported replay version {}",
            fixture.version
        );
        ensure!(
            !fixture.origin.trim().is_empty() && fixture.origin.len() <= 1024,
            "replay origin must contain 1–1024 bytes"
        );
        ensure!(
            fixture.tx_bytes == profile.tx_bytes && (1..=MAX_PAYLOAD).contains(&fixture.tx_bytes),
            "replay TxPDO size differs from profile"
        );
        ensure!(
            (1..=4096).contains(&fixture.exchanges.len()),
            "replay must contain 1–4096 exchanges"
        );
        let mut exchanges = VecDeque::with_capacity(fixture.exchanges.len());
        for (index, recorded) in fixture.exchanges.into_iter().enumerate() {
            let request = decode(&recorded.request_hex)?;
            let seq = *request
                .get(17)
                .with_context(|| format!("replay exchange {} request is truncated", index + 1))?;
            let expected = Frame::new(
                seq,
                input_datagrams(fixture.station_address, fixture.tx_bytes),
            );
            ensure!(
                expected.bytes() == request.as_slice(),
                "replay exchange {} request differs from the LRD/AL read path",
                index + 1
            );
            ensure!(
                recorded.received_hex.len() <= 64,
                "too many received candidates in replay exchange {}",
                index + 1
            );
            let packets = recorded
                .received_hex
                .iter()
                .map(|hex| decode(hex))
                .collect::<Result<Vec<_>>>()?;
            for (candidate, bytes) in packets.iter().enumerate() {
                ensure!(
                    expected.reply(bytes).is_none() || candidate + 1 == packets.len(),
                    "matching response must be the final candidate in replay exchange {}",
                    index + 1
                );
            }
            exchanges.push_back(RecordedExchange {
                request: expected,
                packets,
            });
        }
        Ok(Self {
            origin: fixture.origin,
            station_address: fixture.station_address,
            exchanges,
        })
    }

    pub fn len(&self) -> usize {
        self.exchanges.len()
    }
}

fn decode(text: &str) -> Result<Vec<u8>> {
    ensure!(
        text.len() <= MAX_FRAME_BYTES * 3,
        "encoded replay frame exceeds Ethernet size"
    );
    let clean: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let bytes = hex::decode(clean).context("decode replay Ethernet hex")?;
    ensure!(
        bytes.len() <= MAX_FRAME_BYTES,
        "replay frame exceeds Ethernet size"
    );
    Ok(bytes)
}

impl Bus for Replay {
    fn exchange(&mut self, _cycle: u64) -> Result<Option<Exchange>> {
        let Some(recorded) = self.exchanges.pop_front() else {
            return Ok(None);
        };
        let sent = Instant::now();
        let mut ignored_frames = 0;
        for packet in recorded.packets {
            let received = Instant::now();
            if let Some(parts) = recorded.request.reply(&packet) {
                let input = input_reply(parts);
                return Ok(Some(Exchange {
                    sent,
                    received: Some(received),
                    wkc: input.wkc,
                    status: input.status,
                    data: input.data,
                    ignored_frames,
                }));
            }
            ignored_frames += 1;
        }
        Ok(Some(Exchange {
            sent,
            received: None,
            wkc: 0,
            status: None,
            data: [0; MAX_PAYLOAD],
            ignored_frames,
        }))
    }

    fn stop(&mut self) -> Result<Option<(u16, u16)>> {
        Ok(None)
    }
}

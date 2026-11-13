//! Device synchronization readback, separate from requested host timing.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterRead<T> {
    pub value: Option<T>,
    pub unavailable: Option<String>,
}

impl<T> RegisterRead<T> {
    pub fn from_result(result: std::result::Result<T, impl Display>) -> Self {
        match result {
            Ok(value) => Self {
                value: Some(value),
                unavailable: None,
            },
            Err(error) => Self {
                value: None,
                unavailable: Some(error.to_string()),
            },
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Synchronization {
    pub source: String,
    pub tx_sync_type: Option<RegisterRead<u16>>,
    pub rx_sync_type: Option<RegisterRead<u16>>,
    pub dc: DcReadback,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DcReadback {
    pub support: String,
    pub enhanced_sync_supported: bool,
    pub requested_sync: String,
    pub initial_offset_setup_attempted: bool,
    pub static_sync_iterations: u32,
    pub cyclic_clock_distribution: bool,
    pub activation: Option<RegisterRead<u8>>,
    pub assign_activate: Option<RegisterRead<u16>>,
    pub sync0_cycle_ns: Option<RegisterRead<u32>>,
    pub sync1_cycle_ns: Option<RegisterRead<u32>>,
    pub system_time_offset_ns: Option<RegisterRead<i64>>,
    pub transmission_delay_ns: Option<RegisterRead<u32>>,
}

impl DcReadback {
    pub fn confirm_disabled(&self) -> Result<()> {
        ensure!(
            !self.enhanced_sync_supported || self.activation.is_some(),
            "cannot confirm disabled DC synchronization: activation not read"
        );
        if let Some(activation) = &self.activation {
            let value = activation.value.ok_or_else(|| {
                anyhow::anyhow!(
                    "cannot confirm disabled DC synchronization: activation readback unavailable"
                )
            })?;
            ensure!(
                value & 0x07 == 0,
                "unexpected active DC synchronization: ESC activation {value:#04x}"
            );
        }
        Ok(())
    }

    pub fn summary(&self) -> String {
        let activation = match &self.activation {
            Some(read) => match read.value {
                Some(value) => format!("ESC activation {value:#04x}"),
                None => "ESC activation unavailable".into(),
            },
            None if self.enhanced_sync_supported => "ESC activation not read".into(),
            None => "SYNC registers not applicable".into(),
        };
        format!(
            "requested {}; support {}; {}; static sync {} iterations; cyclic clock distribution {}",
            self.requested_sync,
            self.support,
            activation,
            self.static_sync_iterations,
            self.cyclic_clock_distribution
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_or_unavailable_sync_cannot_be_confirmed_disabled() {
        let mut dc = DcReadback::default();
        dc.confirm_disabled().unwrap(); // No enhanced SYNC capability.
        dc.enhanced_sync_supported = true;
        assert!(dc.confirm_disabled().is_err());
        for value in [1, 2, 3, 4, 7] {
            dc.activation = Some(RegisterRead::from_result(Ok::<_, &str>(value)));
            assert!(dc.confirm_disabled().is_err());
        }
        dc.activation = Some(RegisterRead::from_result(Err::<u8, _>("WKC mismatch")));
        assert!(dc.confirm_disabled().is_err());
        dc.activation = Some(RegisterRead::from_result(Ok::<_, &str>(0)));
        dc.confirm_disabled().unwrap();
    }
}

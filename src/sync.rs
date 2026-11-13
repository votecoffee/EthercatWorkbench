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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coe_cycle: Option<CoeCycleReadback>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CoeCycleReadback {
    pub tx: Option<CoeCycleParameters>,
    pub rx: Option<CoeCycleParameters>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoeCycleParameters {
    pub object_index: u16,
    pub cycle_ns: RegisterRead<u32>,
    pub minimum_cycle_ns: RegisterRead<u32>,
}

impl Synchronization {
    pub fn coe_cycle_summary(&self) -> String {
        let Some(cycle) = &self.coe_cycle else {
            return "CoE setup cycle/minimum not read".into();
        };
        let value =
            |read: &RegisterRead<u32>| read.value.map_or("unavailable".into(), |v| v.to_string());
        let channel = |label, read: &Option<CoeCycleParameters>| {
            read.as_ref().map_or_else(
                || format!("{label} not queried"),
                |r| {
                    format!(
                        "{label} {:#06x} cycle {} minimum {}",
                        r.object_index,
                        value(&r.cycle_ns),
                        value(&r.minimum_cycle_ns)
                    )
                },
            )
        };
        format!(
            "CoE setup ns: {} / {}",
            channel("Tx", &cycle.tx),
            channel("Rx", &cycle.rx)
        )
    }
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
    fn cycle_readback_keeps_zero_unavailable_and_unqueried_separate_in_json_and_summary() {
        let mut sync = Synchronization::default();
        assert!(sync.coe_cycle_summary().contains("not read"));
        sync.coe_cycle = Some(CoeCycleReadback {
            tx: Some(CoeCycleParameters {
                object_index: 0x1c33,
                cycle_ns: RegisterRead::from_result(Ok::<_, &str>(u32::MAX)),
                minimum_cycle_ns: RegisterRead::from_result(Ok::<_, &str>(0)),
            }),
            rx: None,
        });
        let summary = sync.coe_cycle_summary();
        assert!(summary.contains("4294967295 minimum 0"));
        assert!(summary.contains("Rx not queried"));
        let value = serde_json::to_value(&sync).unwrap();
        assert_eq!(value["coe_cycle"]["tx"]["minimum_cycle_ns"]["value"], 0);
        assert!(value["coe_cycle"]["rx"].is_null());
        sync.coe_cycle
            .as_mut()
            .unwrap()
            .tx
            .as_mut()
            .unwrap()
            .cycle_ns = RegisterRead::from_result(Err::<u32, _>("server abort"));
        assert!(sync.coe_cycle_summary().contains("cycle unavailable"));
        let value = serde_json::to_value(&sync).unwrap();
        assert!(value["coe_cycle"]["tx"]["cycle_ns"]["value"].is_null());
        assert_eq!(
            value["coe_cycle"]["tx"]["cycle_ns"]["unavailable"],
            "server abort"
        );
    }

    #[test]
    fn older_synchronization_reports_omit_unqueried_cycle_fields_on_round_trip() {
        let old = serde_json::json!({"source":"older setup snapshot","tx_sync_type":null,"rx_sync_type":null,"dc":serde_json::to_value(DcReadback::default()).unwrap()});
        let parsed: Synchronization = serde_json::from_value(old.clone()).unwrap();
        assert!(parsed.coe_cycle.is_none());
        assert_eq!(serde_json::to_value(parsed).unwrap(), old);
    }

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

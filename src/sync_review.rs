//! Offline ESI timing review. These values never configure the bus.
use crate::{
    model::{Identity, Profile},
    sync::{RegisterRead, Synchronization},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timing {
    pub value_ns: i32,
    pub factor: Option<i32>,
    pub input: Option<bool>,
    pub input_delay_ns: Option<i32>,
    pub output_delay_ns: Option<i32>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DcMode {
    pub name: String,
    pub description: Option<String>,
    pub xml_path: String,
    pub assign_activate: u16,
    pub cycle_sync0: Option<Timing>,
    pub shift_sync0: Option<Timing>,
    pub cycle_sync1: Option<Timing>,
    pub shift_sync1: Option<Timing>,
    #[serde(default)]
    pub notes: Vec<String>,
}

impl DcMode {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.name.trim().is_empty()
                && self.name.len() <= 256
                && !self.name.contains(['\r', '\n']),
            "ESI DC mode needs a single-line name of at most 256 bytes"
        );
        ensure!(
            self.description.as_ref().is_none_or(|d| d.len() <= 4096),
            "DC mode description exceeds limit"
        );
        ensure!(self.xml_path.len() <= 128, "DC mode path exceeds limit");
        for notes in std::iter::once(&self.notes).chain(
            [
                &self.cycle_sync0,
                &self.shift_sync0,
                &self.cycle_sync1,
                &self.shift_sync1,
            ]
            .into_iter()
            .flatten()
            .map(|t| &t.notes),
        ) {
            ensure!(
                notes.len() <= 64 && notes.iter().all(|n| n.len() <= 4096),
                "DC mode notes exceed limit"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ResolvedTime {
    pub value_ns: Option<i64>,
    pub detail: String,
}

fn resolved(value: i64, detail: &str) -> ResolvedTime {
    ResolvedTime {
        value_ns: Some(value),
        detail: detail.into(),
    }
}

fn unresolved(detail: &str) -> ResolvedTime {
    ResolvedTime {
        value_ns: None,
        detail: detail.into(),
    }
}

fn cycle(
    time: Option<&Timing>,
    sync1: bool,
    unit: Option<u32>,
    sync0: Option<i64>,
) -> ResolvedTime {
    let Some(time) = time else {
        return unresolved("Not declared in ESI");
    };
    if !time.notes.is_empty()
        || time.input.is_some()
        || time.input_delay_ns.is_some()
        || time.output_delay_ns.is_some()
    {
        return unresolved("Cycle contains unsupported annotations; review the source ESI");
    }
    let factor = i64::from(time.factor.unwrap_or(0));
    let value = if time.value_ns != 0 || factor == 0 {
        i64::from(time.value_ns)
    } else if sync1 && factor > 0 {
        let Some(sync0) = sync0 else {
            return unresolved("SYNC1 factor requires resolved SYNC0");
        };
        sync0 * factor
    } else {
        let Some(unit) = unit else {
            return unresolved("Factor requires an explicit manual sync-unit cycle assumption");
        };
        let unit = i64::from(unit);
        if sync1 || factor > 0 {
            unit * factor.abs()
        } else {
            if unit % -factor != 0 {
                return unresolved("SYNC0 division is not an exact integer number of nanoseconds");
            }
            unit / -factor
        }
    };
    if !(0..=i64::from(u32::MAX)).contains(&value) {
        return unresolved("Cycle is outside the unsigned 32-bit ESC cycle register range");
    }
    resolved(
        value,
        if time.value_ns != 0 || factor == 0 {
            "ESI literal (a Factor on a nonzero cycle is unused)"
        } else {
            "Calculated ESI factor; sync-unit assumption is manual when required"
        },
    )
}

fn shift(time: Option<&Timing>) -> ResolvedTime {
    let Some(time) = time else {
        return unresolved("Not declared in ESI");
    };
    if time.factor.is_some_and(|f| f != 0)
        || time.input == Some(true)
        || time.input_delay_ns.is_some()
        || time.output_delay_ns.is_some()
        || !time.notes.is_empty()
    {
        return unresolved(
            "Shift factors and input/output timing annotations need device-specific review",
        );
    }
    resolved(
        i64::from(time.value_ns),
        "ESI signed shift literal; not compared with the absolute ESC start-time register",
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckState {
    Matched,
    Different,
    Unavailable,
    Unresolved,
    NotDeclared,
}

#[derive(Clone, Debug, Serialize)]
pub struct SettingCheck {
    pub setting: String,
    pub expected: Option<i64>,
    pub actual: Option<i64>,
    pub state: CheckState,
    pub detail: String,
}

fn check<T: Copy + Into<i64>>(
    name: &str,
    expected: Option<i64>,
    declared: bool,
    actual: Option<&RegisterRead<T>>,
) -> SettingCheck {
    let value = actual.and_then(|r| r.value).map(Into::into);
    let (state, detail) = if !declared {
        (
            CheckState::NotDeclared,
            "Not declared in selected ESI mode".into(),
        )
    } else if expected.is_none() {
        (
            CheckState::Unresolved,
            "Staged expectation is unresolved".into(),
        )
    } else if value.is_none() {
        (
            CheckState::Unavailable,
            actual
                .and_then(|r| r.unavailable.clone())
                .unwrap_or_else(|| "Register readback unavailable or not applicable".into()),
        )
    } else if expected == value {
        (
            CheckState::Matched,
            "Staged value equals this register readback; mode was not applied".into(),
        )
    } else {
        (
            CheckState::Different,
            "Staged value differs from readback; mode was not applied".into(),
        )
    };
    SettingCheck {
        setting: name.into(),
        expected,
        actual: value,
        state,
        detail,
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Review {
    pub applied: bool,
    pub esi_file_name: String,
    pub esi_sha256: String,
    pub identity: Identity,
    pub mode_index: usize,
    pub mode_source: String,
    pub mode: DcMode,
    pub sync_unit_cycle_ns: Option<u32>,
    pub sync_unit_source: Option<String>,
    pub cycle_sync0: ResolvedTime,
    pub cycle_sync1: ResolvedTime,
    pub shift_sync0: ResolvedTime,
    pub shift_sync1: ResolvedTime,
    pub readback_source: Option<String>,
    pub checks: Vec<SettingCheck>,
    pub notes: Vec<String>,
}

pub fn review(profile: &Profile, bus: Option<&Synchronization>) -> Result<Option<Review>> {
    let Some(index) = profile.staged_esi_dc_mode else {
        return Ok(None);
    };
    let source = profile
        .esi
        .as_ref()
        .context("staged DC mode needs an ESI baseline")?;
    ensure!(
        profile.expected_identity.as_ref() == Some(&source.identity),
        "staged DC mode requires the exact ESI identity baseline"
    );
    let mode = source
        .dc_modes
        .get(index)
        .context("staged ESI DC mode index out of range")?;
    let sync0 = cycle(
        mode.cycle_sync0.as_ref(),
        false,
        profile.sync_unit_cycle_ns,
        None,
    );
    let sync1 = cycle(
        mode.cycle_sync1.as_ref(),
        true,
        profile.sync_unit_cycle_ns,
        sync0.value_ns,
    );
    let dc = bus.map(|s| &s.dc);
    let checks = vec![
        check(
            "AssignActivate 0x0980:0x0981",
            Some(i64::from(mode.assign_activate)),
            true,
            dc.and_then(|d| d.assign_activate.as_ref()),
        ),
        check(
            "SYNC0 cycle 0x09A0",
            sync0.value_ns,
            mode.cycle_sync0.is_some(),
            dc.and_then(|d| d.sync0_cycle_ns.as_ref()),
        ),
        check(
            "SYNC1 cycle 0x09A4",
            sync1.value_ns,
            mode.cycle_sync1.is_some(),
            dc.and_then(|d| d.sync1_cycle_ns.as_ref()),
        ),
    ];
    let mut notes = vec![
        "Offline review only. Runtime policy requests disabled SYNC; selecting a mode sends no writes."
            .into(),
        "The requested host cycle is not used as the device sync-unit cycle.".into(),
    ];
    notes.extend(mode.notes.iter().cloned());
    if mode.assign_activate & 0x0600 != 0 && sync0.value_ns == Some(0) {
        notes.push(
            "Enabled SYNC mode has a zero SYNC0 cycle; device-specific review is required.".into(),
        );
    }
    Ok(Some(Review {
        applied: false,
        esi_file_name: source.file_name.clone(),
        esi_sha256: source.sha256.clone(),
        identity: source.identity.clone(),
        mode_index: index,
        mode_source: "esi".into(),
        mode: mode.clone(),
        sync_unit_cycle_ns: profile.sync_unit_cycle_ns,
        sync_unit_source: profile.sync_unit_cycle_ns.map(|_| "manual".into()),
        shift_sync0: shift(mode.shift_sync0.as_ref()),
        shift_sync1: shift(mode.shift_sync1.as_ref()),
        cycle_sync0: sync0,
        cycle_sync1: sync1,
        readback_source: bus.map(|s| s.source.clone()),
        checks,
        notes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn timing(value_ns: i32, factor: Option<i32>) -> Timing {
        Timing {
            value_ns,
            factor,
            input: None,
            input_delay_ns: None,
            output_delay_ns: None,
            notes: vec![],
        }
    }

    #[test]
    fn resolves_distinct_sync0_and_sync1_factor_rules_without_using_host_cycle() {
        let t = timing(0, Some(-2));
        assert_eq!(
            cycle(Some(&t), false, Some(1_000_000), None).value_ns,
            Some(500_000)
        );
        assert_eq!(
            cycle(Some(&t), true, Some(1_000_000), None).value_ns,
            Some(2_000_000)
        );
        let t = timing(0, Some(3));
        assert_eq!(
            cycle(Some(&t), true, None, Some(500_000)).value_ns,
            Some(1_500_000)
        );
        assert_eq!(cycle(Some(&t), false, None, None).value_ns, None);
        assert_eq!(
            cycle(Some(&timing(7, Some(3))), false, None, None).value_ns,
            Some(7)
        );
        assert_eq!(
            cycle(Some(&timing(0, Some(-3))), false, Some(1_000_000), None).value_ns,
            None
        );
        assert_eq!(
            cycle(
                Some(&timing(0, Some(i32::MAX))),
                true,
                None,
                Some(i64::from(u32::MAX))
            )
            .value_ns,
            None
        );
        assert_eq!(
            cycle(Some(&timing(-1, None)), false, None, None).value_ns,
            None
        );
    }

    #[test]
    fn leaves_device_timing_dependent_shifts_unresolved_and_zero_readback_explicit() {
        let mut t = timing(-1000, None);
        assert_eq!(shift(Some(&t)).value_ns, Some(-1000));
        t.input = Some(true);
        assert_eq!(shift(Some(&t)).value_ns, None);
        let actual = RegisterRead::from_result(Ok::<u16, &str>(0));
        assert_eq!(
            check("assign", Some(0), true, Some(&actual)).state,
            CheckState::Matched
        );
        assert_eq!(
            check("assign", Some(0x300), true, Some(&actual)).state,
            CheckState::Different
        );
        assert_eq!(
            check::<u16>("assign", Some(0), true, None).state,
            CheckState::Unavailable
        );
    }
}

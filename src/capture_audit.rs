//! Read-only audit of a completed capture's declared CSV parts.
use crate::{
    benchmark::{RunContext, hash, read_report_bytes_with_stop},
    capture::{CaptureStats, METADATA, part_path},
    model::{Field, Kind, LogMode, Scheduler},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering::Relaxed},
};

const MAX_RECORD: u64 = 1024 * 1024;
const MAX_PARTS: u64 = 100_000;
const MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;

#[derive(Deserialize)]
struct SavedCapture {
    context: Option<RunContext>,
    scheduler: Scheduler,
    requested_cycle_us: u64,
    input_loss_timeout_ms: u64,
    connection_generation: u64,
    cycles: u64,
    replies: u64,
    valid: u64,
    timeouts: u64,
    transport_errors: u64,
    missed_deadlines: u64,
    wkc_mismatches: u64,
    state_mismatches: u64,
    capture: Option<CaptureStats>,
    cancelled: bool,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Part {
    pub file: PathBuf,
    pub sha256: String,
    pub bytes: u64,
    pub rows: u64,
    pub eol: String,
    pub utf8_bom: bool,
}

#[derive(Debug, Serialize)]
pub struct Audit {
    pub schema: u32,
    pub auditor_version: String,
    pub report: PathBuf,
    pub report_sha256: String,
    pub profile_sha256: String,
    pub app_version: String,
    pub csv_base: PathBuf,
    pub mode: LogMode,
    pub fields: Vec<String>,
    pub utc_start: String,
    pub connection_generation: u64,
    pub rows: u64,
    pub parts: Vec<Part>,
    pub selected: u64,
    pub valid_exchanges: u64,
    pub invalid_exchanges: u64,
    pub reply_timeouts: u64,
    pub wkc_mismatches: u64,
    pub state_mismatches: u64,
    pub transport_errors: u64,
    pub logger_overruns: u64,
    pub leading_index_gap: u64,
    pub interior_index_gaps: u64,
    pub trailing_index_gap: u64,
    pub first_elapsed_us: Option<u64>,
    pub last_elapsed_us: Option<u64>,
    pub first_cycle_index: Option<u64>,
    pub last_cycle_index: Option<u64>,
    pub non_finite_values: u64,
    pub ambiguous_nan_repeats: u64,
    pub run_cancelled: bool,
    pub run_error: Option<String>,
    pub warnings: Vec<String>,
}

struct Hashed<'a> {
    file: File,
    digest: Sha256,
    bytes: u64,
    limit: u64,
    stop: Option<&'a AtomicBool>,
}
impl Read for Hashed<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.stop.is_some_and(|stop| stop.load(Relaxed)) {
            return Err(io::Error::other("saved-file review cancelled"));
        }
        let n = self.file.read(buf)?;
        self.bytes += n as u64;
        if self.bytes > self.limit {
            return Err(io::Error::other("capture exceeds 64 GiB audit limit"));
        }
        self.digest.update(&buf[..n]);
        Ok(n)
    }
}

fn number(value: &str) -> Result<u64> {
    let number: u64 = value.parse().context("expected unsigned decimal integer")?;
    ensure!(
        number.to_string() == value,
        "integer text is not canonical decimal"
    );
    Ok(number)
}

// Workbench values and field names never contain record separators. Bound each physical record,
// then use the CSV parser and canonical writer to reject its permissive malformed-quote forms.
fn record(bytes: &[u8], header: bool) -> Result<(csv::StringRecord, bool, bool)> {
    let bom = header && bytes.starts_with(b"\xef\xbb\xbf");
    let bytes = if bom { &bytes[3..] } else { bytes };
    ensure!(
        bytes.ends_with(b"\n"),
        "CSV record is missing its final newline"
    );
    let crlf = bytes.ends_with(b"\r\n");
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .buffer_capacity(1024)
        .from_reader(bytes);
    let row = reader.records().next().context("blank CSV record")??;
    ensure!(
        reader.records().next().is_none(),
        "multiple CSV records in one physical record"
    );
    let mut writer = csv::WriterBuilder::new()
        .buffer_capacity(1024)
        .terminator(if crlf {
            csv::Terminator::CRLF
        } else {
            csv::Terminator::Any(b'\n')
        })
        .from_writer(Vec::new());
    writer.write_record(&row)?;
    let encoded = writer.into_inner().map_err(|error| error.into_error())?;
    ensure!(
        encoded == bytes,
        "CSV quoting or record encoding differs from Workbench writer format"
    );
    Ok((row, crlf, bom))
}

/// Returns (non-finite floating point value, ambiguous NaN representation).
fn typed(field: &Field, value: &str) -> Result<(bool, bool)> {
    match field.kind {
        Kind::Unsigned => {
            let n = number(value)?;
            ensure!(
                field.width == 64 || n < (1u64 << field.width),
                "unsigned value exceeds field width"
            );
        }
        Kind::Signed => {
            let n: i64 = value.parse().context("expected signed decimal integer")?;
            ensure!(
                n.to_string() == value,
                "signed integer text is not canonical decimal"
            );
            let magnitude = 1i128 << (field.width - 1);
            ensure!(
                (-magnitude..magnitude).contains(&i128::from(n)),
                "signed value exceeds field width"
            );
        }
        Kind::Bool => ensure!(matches!(value, "true" | "false"), "expected true or false"),
        Kind::F32 => {
            let n: f32 = value.parse().context("expected f32 text")?;
            ensure!(n.to_string() == value, "value is not canonical f32 text");
            return Ok((!n.is_finite(), n.is_nan()));
        }
        Kind::F64 => {
            let n: f64 = value.parse().context("expected f64 text")?;
            ensure!(n.to_string() == value, "value is not canonical f64 text");
            return Ok((!n.is_finite(), n.is_nan()));
        }
        Kind::Raw => ensure!(
            value.len() == field.width / 4
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)),
            "expected exact-length uppercase raw hex"
        ),
    }
    Ok((false, false))
}

#[derive(Default)]
struct Cursor {
    rows: u64,
    first: Option<(u64, u64, u64)>, // sample, elapsed, cycle
    last: Option<(u64, u64, u64)>,
    values: Vec<String>,
    non_finite: u64,
    nan_repeats: u64,
}

impl Cursor {
    fn accept(
        &mut self,
        row: &csv::StringRecord,
        saved: &SavedCapture,
        ctx: &RunContext,
        cap: &CaptureStats,
        fields: &[&Field],
        max_cycle: u64,
    ) -> Result<()> {
        ensure!(
            row.len() == METADATA.len() + fields.len(),
            "CSV row width differs from header"
        );
        ensure!(
            row[0] == cap.utc_start,
            "capture UTC anchor differs from report"
        );
        let elapsed = number(&row[1])?;
        let sample = number(&row[2])?;
        ensure!(
            number(&row[3])? == saved.connection_generation,
            "connection generation differs from report"
        );
        let cycle = number(&row[4])?;
        ensure!(
            sample > 0 && sample <= cap.selected && cycle >= sample && cycle <= max_cycle,
            "sample or cycle index outside report bounds"
        );
        if let Some((previous, at, previous_cycle)) = self.last {
            ensure!(
                sample > previous && elapsed >= at && cycle > previous_cycle,
                "sample/cycle indexes or elapsed timestamps are out of order"
            );
            ensure!(
                cycle - previous_cycle >= sample - previous,
                "sample indexes advance faster than cycle indexes"
            );
        }
        if ctx.profile.mode == LogMode::Every {
            let skipped = max_cycle - saved.valid;
            ensure!(
                cycle - sample <= skipped,
                "every-valid cycle/sample indexes contradict report losses"
            );
        }
        let mut nan = false;
        for (field, value) in fields.iter().zip(row.iter().skip(METADATA.len())) {
            let (non_finite, is_nan) =
                typed(field, value).with_context(|| format!("field {}", field.name))?;
            self.non_finite += u64::from(non_finite);
            nan |= is_nan;
        }
        if ctx.profile.mode == LogMode::Change
            && self.last.is_some()
            && self
                .values
                .iter()
                .map(String::as_str)
                .eq(row.iter().skip(METADATA.len()))
        {
            ensure!(nan, "on-change CSV repeats identical selected values");
            self.nan_repeats += 1;
        }
        self.values.clear();
        self.values
            .extend(row.iter().skip(METADATA.len()).map(str::to_owned));
        self.first.get_or_insert((sample, elapsed, cycle));
        self.last = Some((sample, elapsed, cycle));
        self.rows += 1;
        ensure!(
            self.rows <= cap.written,
            "CSV has more rows than report written count"
        );
        Ok(())
    }
}

pub fn verify(report: &Path, base: &Path) -> Result<Audit> {
    verify_with_stop(report, base, None)
}

pub(crate) fn verify_cancelable(report: &Path, base: &Path, stop: &AtomicBool) -> Result<Audit> {
    verify_with_stop(report, base, Some(stop))
}

pub(crate) fn verify_with_stop(
    report: &Path,
    base: &Path,
    stop: Option<&AtomicBool>,
) -> Result<Audit> {
    crate::review::check_cancel(stop)?;
    ensure!(
        base.extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("csv")),
        "CSV base must end in .csv"
    );
    let report_bytes = read_report_bytes_with_stop(report, stop)?;
    let saved: SavedCapture = serde_json::from_slice(
        report_bytes
            .strip_prefix(b"\xef\xbb\xbf")
            .unwrap_or(&report_bytes),
    )
    .context("parse capture report")?;
    let ctx = saved
        .context
        .as_ref()
        .context("capture report has no versioned run context")?;
    ctx.validate()?;
    let cap = saved
        .capture
        .as_ref()
        .context("report has no capture counters")?;
    ensure!(
        saved.scheduler == ctx.profile.scheduler
            && saved.requested_cycle_us == ctx.profile.requested_cycle_us
            && saved.input_loss_timeout_ms == ctx.profile.input_loss_timeout_ms,
        "report settings differ from run context"
    );
    ensure!(
        saved.connection_generation > 0
            && saved.cycles
                <= ctx
                    .duration_limit_us
                    .div_ceil(ctx.profile.requested_cycle_us)
            && saved.valid <= saved.replies
            && saved.replies <= saved.cycles
            && saved.cycles - saved.replies
                == saved
                    .timeouts
                    .checked_add(saved.transport_errors)
                    .context("exchange count overflow")?,
        "inconsistent exchange counters"
    );
    let invalid_replies = saved.replies - saved.valid;
    ensure!(
        saved.wkc_mismatches <= invalid_replies
            && saved.state_mismatches <= invalid_replies
            && invalid_replies <= saved.wkc_mismatches.saturating_add(saved.state_mismatches),
        "inconsistent WKC/AL counters"
    );
    ensure!(
        cap.selected <= saved.valid
            && cap.overruns <= cap.selected
            && cap.written == cap.selected - cap.overruns,
        "capture is incomplete or selected/written/overrun counters disagree"
    );
    if ctx.profile.mode == LogMode::Every {
        ensure!(
            cap.selected == saved.valid,
            "every-valid capture omitted valid samples"
        );
    }
    let utc = chrono::DateTime::parse_from_rfc3339(&cap.utc_start)
        .context("invalid capture UTC anchor")?;
    ensure!(
        utc.offset().local_minus_utc() == 0,
        "capture anchor must be UTC"
    );
    let fields: Vec<_> = ctx.profile.tx.iter().filter(|f| f.log).collect();
    ensure!(
        fields.iter().all(|f| !METADATA.contains(&f.name.as_str())),
        "CSV field conflicts with metadata header"
    );
    let header: Vec<_> = METADATA
        .into_iter()
        .chain(fields.iter().map(|f| f.name.as_str()))
        .collect();
    let rotate = ctx.profile.rotate_rows;
    let expected_parts = if rotate == 0 {
        1
    } else {
        cap.written.div_ceil(rotate).max(1)
    };
    ensure!(
        cap.parts == expected_parts && cap.parts <= MAX_PARTS,
        "capture part count or rotation disagrees with report (limit 100000 parts)"
    );
    let max_cycle = saved
        .cycles
        .checked_add(if saved.scheduler == Scheduler::Deadline {
            saved.missed_deadlines
        } else {
            0
        })
        .context("cycle index bound overflow")?;
    let mut parts = Vec::new();
    let contract = Contract {
        saved: &saved,
        ctx,
        cap,
        fields: &fields,
        header: &header,
        max_cycle,
        stop,
    };
    let mut total_bytes = 0;
    let mut cursor = Cursor::default();
    for index in 1..=cap.parts {
        let path = part_path(base, index, rotate)?;
        let part = inspect(
            &path,
            index,
            &contract,
            MAX_BYTES - total_bytes,
            &mut cursor,
        )
        .with_context(|| format!("CSV part {}", path.display()))?;
        let expected_rows = if rotate == 0 {
            cap.written
        } else {
            (cap.written - (index - 1) * rotate).min(rotate)
        };
        ensure!(
            part.rows == expected_rows,
            "CSV part {} row count differs from rotation/written count",
            path.display()
        );
        total_bytes += part.bytes;
        parts.push(part);
    }
    ensure!(
        cursor.rows == cap.written,
        "CSV total row count differs from report"
    );
    let leading = cursor.first.map_or(cap.selected, |v| v.0 - 1);
    let trailing = cursor.last.map_or(0, |v| cap.selected - v.0);
    let mut warnings = vec![
        "Audit covers only the report's declared CSV part sequence; other files are not inspected.".into(),
        "Typed text and metadata do not independently establish original PDO bits, mapping meaning or physical input validity.".into(),
        "Hashes identify the report and CSV bytes read; editable saved files are not signed runtime evidence or hardware acceptance.".into(),
    ];
    if saved.error.is_some() || saved.cancelled {
        warnings.push(
            "Capture structure passes, but the run failed or was cancelled; inspect its outcome."
                .into(),
        );
    }
    if cap.overruns > 0 {
        warnings.push("Sample-index gaps account for reported logger overruns.".into());
    }
    if cursor.non_finite > 0 {
        warnings.push("Capture contains non-finite floating point values; NaN text cannot retain NaN payload bits.".into());
    }
    crate::review::check_cancel(stop)?;
    Ok(Audit {
        schema: 1,
        auditor_version: env!("CARGO_PKG_VERSION").into(),
        report: report.to_owned(),
        report_sha256: hash(&report_bytes),
        profile_sha256: ctx.profile_sha256.clone(),
        app_version: ctx.app_version.clone(),
        csv_base: base.to_owned(),
        mode: ctx.profile.mode,
        fields: fields.iter().map(|f| f.name.clone()).collect(),
        utc_start: cap.utc_start.clone(),
        connection_generation: saved.connection_generation,
        rows: cursor.rows,
        parts,
        selected: cap.selected,
        valid_exchanges: saved.valid,
        invalid_exchanges: saved.cycles - saved.valid,
        reply_timeouts: saved.timeouts,
        wkc_mismatches: saved.wkc_mismatches,
        state_mismatches: saved.state_mismatches,
        transport_errors: saved.transport_errors,
        logger_overruns: cap.overruns,
        leading_index_gap: leading,
        trailing_index_gap: trailing,
        interior_index_gaps: cap.overruns - leading - trailing,
        first_elapsed_us: cursor.first.map(|v| v.1),
        last_elapsed_us: cursor.last.map(|v| v.1),
        first_cycle_index: cursor.first.map(|v| v.2),
        last_cycle_index: cursor.last.map(|v| v.2),
        non_finite_values: cursor.non_finite,
        ambiguous_nan_repeats: cursor.nan_repeats,
        run_cancelled: saved.cancelled,
        run_error: saved.error,
        warnings,
    })
}

struct Contract<'a> {
    saved: &'a SavedCapture,
    ctx: &'a RunContext,
    cap: &'a CaptureStats,
    fields: &'a [&'a Field],
    header: &'a [&'a str],
    max_cycle: u64,
    stop: Option<&'a AtomicBool>,
}

fn inspect(
    path: &Path,
    index: u64,
    contract: &Contract<'_>,
    limit: u64,
    cursor: &mut Cursor,
) -> Result<Part> {
    crate::review::check_cancel(contract.stop)?;
    let file = File::open(path)?;
    let initial = file.metadata()?;
    ensure!(
        initial.is_file() && initial.len() <= limit,
        "capture must be a regular file within 64 GiB total"
    );
    let hashed = Hashed {
        file,
        digest: Sha256::new(),
        bytes: 0,
        limit,
        stop: contract.stop,
    };
    let mut reader = BufReader::new(hashed);
    let mut line = Vec::new();
    let mut eol = None;
    let mut bom = false;
    let start_rows = cursor.rows;
    let mut is_header = true;
    loop {
        crate::review::check_cancel(contract.stop)?;
        line.clear();
        if reader
            .by_ref()
            .take(MAX_RECORD + 1)
            .read_until(b'\n', &mut line)?
            == 0
        {
            break;
        }
        ensure!(line.len() as u64 <= MAX_RECORD, "CSV record exceeds 1 MiB");
        let (row, crlf, has_bom) = record(&line, is_header)?;
        ensure!(
            eol.is_none_or(|old| old == crlf),
            "mixed CSV record terminators in one part"
        );
        eol = Some(crlf);
        if is_header {
            ensure!(
                row.iter().eq(contract.header.iter().copied()),
                "CSV header differs from selected fields/order"
            );
            bom = has_bom;
            is_header = false;
        } else {
            let row_number = cursor.rows - start_rows + 1;
            cursor
                .accept(
                    &row,
                    contract.saved,
                    contract.ctx,
                    contract.cap,
                    contract.fields,
                    contract.max_cycle,
                )
                .with_context(|| format!("part {index}, data row {row_number}"))?;
        }
    }
    ensure!(!is_header, "CSV part is empty (header missing)");
    let hashed = reader.into_inner();
    let after = hashed.file.metadata()?;
    ensure!(
        hashed.bytes == initial.len()
            && after.len() == initial.len()
            && after.modified().ok() == initial.modified().ok(),
        "CSV file changed during audit"
    );
    Ok(Part {
        file: path.to_owned(),
        sha256: hex::encode(hashed.digest.finalize()),
        bytes: hashed.bytes,
        rows: cursor.rows - start_rows,
        eol: if eol == Some(true) { "CRLF" } else { "LF" }.into(),
        utf8_bom: bom,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        benchmark::Frontend,
        model::Profile,
        run::{Mode, RunOptions},
    };
    use std::time::Duration;

    fn saved(kind: Kind, width: usize, mode: LogMode) -> SavedCapture {
        let profile = Profile {
            tx_bytes: 8,
            tx: vec![Field {
                kind,
                width,
                ..Field::default()
            }],
            mode,
            ..Profile::default()
        };
        let options = RunOptions {
            frontend: Frontend::Cli,
            mode: Mode::Simulate { faults: false },
            duration: Duration::from_secs(1),
            csv: Some("unused.csv".into()),
            generation: 3,
        };
        SavedCapture {
            context: Some(RunContext::new(&profile, &options).unwrap()),
            scheduler: Scheduler::Deadline,
            requested_cycle_us: 1000,
            input_loss_timeout_ms: 1000,
            connection_generation: 3,
            cycles: 9,
            replies: 8,
            valid: 6,
            timeouts: 1,
            transport_errors: 0,
            missed_deadlines: 2,
            wkc_mismatches: 1,
            state_mismatches: 1,
            capture: Some(CaptureStats {
                selected: 6,
                written: 3,
                overruns: 3,
                utc_start: "2026-01-01T00:00:00Z".into(),
                parts: 1,
            }),
            cancelled: false,
            error: None,
        }
    }

    fn accept(
        cursor: &mut Cursor,
        saved: &SavedCapture,
        sample: u64,
        elapsed: u64,
        cycle: u64,
        value: &str,
    ) -> Result<()> {
        let ctx = saved.context.as_ref().unwrap();
        let cap = saved.capture.as_ref().unwrap();
        let row = csv::StringRecord::from(vec![
            cap.utc_start.clone(),
            elapsed.to_string(),
            sample.to_string(),
            saved.connection_generation.to_string(),
            cycle.to_string(),
            value.into(),
        ]);
        let fields: Vec<_> = ctx.profile.tx.iter().collect();
        cursor.accept(
            &row,
            saved,
            ctx,
            cap,
            &fields,
            saved.cycles + saved.missed_deadlines,
        )
    }

    #[test]
    fn parses_writer_quoting_utf8_bom_and_both_record_terminators() {
        let (row, crlf, bom) = record("\"A,B\",\"say \"\"yes\"\"\",µs\n".as_bytes(), true).unwrap();
        assert_eq!(
            row.iter().collect::<Vec<_>>(),
            vec!["A,B", "say \"yes\"", "µs"]
        );
        assert!(!crlf && !bom);
        let (row, crlf, bom) = record(b"\xef\xbb\xbfA,B\r\n", true).unwrap();
        assert_eq!(row.iter().collect::<Vec<_>>(), vec!["A", "B"]);
        assert!(crlf && bom);
        assert!(record(b"\xef\xbb\xbfA,B\n", false).is_err());
    }

    #[test]
    fn rejects_permissive_quotes_blank_records_invalid_utf8_and_unterminated_records() {
        for bytes in [
            b"\"a\n".as_slice(),
            b"a\"b\n",
            b"\"a\",b\n",
            b"a,b",
            b"\n",
            b"\xff\n",
            b"a,b\rc,d\n",
        ] {
            assert!(record(bytes, false).is_err(), "{bytes:?}");
        }
    }

    #[test]
    fn checks_integer_widths_and_canonical_signed_boolean_and_raw_text() {
        let field = |kind, width| Field {
            kind,
            width,
            ..Field::default()
        };
        for (kind, width, good, bad) in [
            (Kind::Unsigned, 8, "255", "256"),
            (Kind::Signed, 8, "-128", "-129"),
            (Kind::Signed, 1, "-1", "1"),
            (Kind::Bool, 1, "true", "1"),
            (Kind::Raw, 16, "AB00", "ab00"),
            (
                Kind::Unsigned,
                64,
                "18446744073709551615",
                "18446744073709551616",
            ),
            (
                Kind::Signed,
                64,
                "-9223372036854775808",
                "9223372036854775808",
            ),
        ] {
            assert!(typed(&field(kind, width), good).is_ok());
            assert!(typed(&field(kind, width), bad).is_err());
        }
        for text in ["+1", "01", "1.0", " 1", ""] {
            assert!(typed(&field(Kind::Unsigned, 8), text).is_err());
        }
        assert!(typed(&field(Kind::Signed, 16), "-0").is_err());
        assert!(typed(&field(Kind::Raw, 16), "A0").is_err());
    }

    #[test]
    fn preserves_float_special_values_and_detects_noncanonical_or_overflowing_text() {
        for (kind, width) in [(Kind::F32, 32), (Kind::F64, 64)] {
            let f = Field {
                kind,
                width,
                ..Field::default()
            };
            assert_eq!(typed(&f, "NaN").unwrap(), (true, true));
            assert_eq!(typed(&f, "inf").unwrap(), (true, false));
            assert_eq!(typed(&f, "-inf").unwrap(), (true, false));
            assert_eq!(typed(&f, "-0").unwrap(), (false, false));
            assert_eq!(typed(&f, "1.5").unwrap(), (false, false));
            assert!(typed(&f, "1e999").is_err());
            assert!(typed(&f, "1.0").is_err());
        }
    }

    #[test]
    fn keeps_index_and_time_state_across_parts_and_allows_declared_queue_gaps() {
        let saved = saved(Kind::Unsigned, 8, LogMode::Every);
        let mut cursor = Cursor::default();
        accept(&mut cursor, &saved, 2, 100, 3, "1").unwrap();
        accept(&mut cursor, &saved, 4, 200, 5, "1").unwrap();
        accept(&mut cursor, &saved, 5, 300, 8, "2").unwrap();
        assert_eq!(cursor.first, Some((2, 100, 3)));
        assert_eq!(cursor.last, Some((5, 300, 8)));
        for (sample, elapsed, cycle) in [
            (0, 100, 3),
            (7, 100, 8),
            (2, 90, 4),
            (4, 200, 3),
            (2, 200, 12),
        ] {
            let mut cursor = Cursor::default();
            accept(&mut cursor, &saved, 1, 100, 1, "1").unwrap();
            assert!(accept(&mut cursor, &saved, sample, elapsed, cycle, "2").is_err());
        }
        let mut cursor = Cursor::default();
        accept(&mut cursor, &saved, 1, 100, 3, "1").unwrap();
        assert!(accept(&mut cursor, &saved, 4, 200, 5, "2").is_err());
    }

    #[test]
    fn on_change_repeats_are_invalid_except_for_hidden_nan_payload_changes() {
        let changed = saved(Kind::Unsigned, 8, LogMode::Change);
        let mut cursor = Cursor::default();
        accept(&mut cursor, &changed, 1, 100, 1, "1").unwrap();
        assert!(accept(&mut cursor, &changed, 2, 200, 2, "1").is_err());
        let changed = saved(Kind::F32, 32, LogMode::Change);
        let mut cursor = Cursor::default();
        accept(&mut cursor, &changed, 1, 100, 1, "NaN").unwrap();
        accept(&mut cursor, &changed, 2, 200, 2, "NaN").unwrap();
        assert_eq!(cursor.nan_repeats, 1);
        assert_eq!(cursor.non_finite, 2);
    }
}

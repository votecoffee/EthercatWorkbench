//! Background saved-file review, shared with the desktop without owning any bus state.
use crate::{benchmark, capture_audit};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering::Relaxed},
    },
    thread::{self, JoinHandle},
};

pub(crate) fn check_cancel(stop: Option<&AtomicBool>) -> Result<()> {
    ensure!(
        !stop.is_some_and(|stop| stop.load(Relaxed)),
        "saved-file review cancelled"
    );
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub report: PathBuf,
    pub csv: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Task {
    Audit(Input),
    Compare { inputs: Vec<Input>, audit_csv: bool },
}

impl Task {
    pub fn validate(&self) -> Result<()> {
        let (inputs, csv) = match self {
            Self::Audit(input) => (std::slice::from_ref(input), true),
            Self::Compare { inputs, audit_csv } => {
                ensure!(
                    (2..=32).contains(&inputs.len()),
                    "select 2–32 reports for comparison"
                );
                (inputs.as_slice(), *audit_csv)
            }
        };
        for input in inputs {
            ensure!(
                !input.report.as_os_str().is_empty(),
                "enter a saved report path"
            );
            if csv {
                ensure!(
                    input
                        .csv
                        .as_ref()
                        .is_some_and(|path| !path.as_os_str().is_empty()),
                    "enter a CSV base for every audited report"
                );
            }
        }
        Ok(())
    }

    pub fn execute(&self, stop: &AtomicBool) -> Result<Outcome> {
        self.validate()?;
        check_cancel(Some(stop))?;
        let outcome = match self {
            Self::Audit(input) => Outcome::Audit(Box::new(capture_audit::verify_cancelable(
                &input.report,
                input.csv.as_deref().context("CSV base missing")?,
                stop,
            )?)),
            Self::Compare { inputs, audit_csv } => {
                let reports: Vec<_> = inputs.iter().map(|input| input.report.clone()).collect();
                let bases: Vec<_> = inputs
                    .iter()
                    .filter_map(|input| input.csv.clone())
                    .collect();
                Outcome::Comparison(Box::new(benchmark::compare_cancelable(
                    &reports,
                    audit_csv.then_some(bases.as_slice()),
                    stop,
                )?))
            }
        };
        check_cancel(Some(stop))?;
        Ok(outcome)
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Outcome {
    Audit(Box<capture_audit::Audit>),
    Comparison(Box<benchmark::Comparison>),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum State {
    #[default]
    Idle,
    Running,
    Cancelling,
    Complete,
    Cancelled,
    Failed,
}
impl State {
    pub fn label(self) -> &'static str {
        match self {
            Self::Idle => "Ready",
            Self::Running => "Reviewing saved files",
            Self::Cancelling => "Cancelling saved-file review",
            Self::Complete => "Saved-file review complete",
            Self::Cancelled => "Saved-file review cancelled",
            Self::Failed => "Saved-file review failed",
        }
    }
}

pub struct Completed {
    pub task: Task,
    pub outcome: Outcome,
}
struct Job {
    task: Task,
    stop: Arc<AtomicBool>,
    worker: JoinHandle<Result<Outcome>>,
}

#[derive(Default)]
pub struct Controller {
    job: Option<Job>,
    completed: Option<Completed>,
    error: Option<String>,
    state: State,
}

impl Controller {
    pub fn is_running(&self) -> bool {
        self.job.is_some()
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn completed(&self) -> Option<&Completed> {
        self.completed.as_ref()
    }
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn start(&mut self, task: Task) -> Result<()> {
        let execute = task.clone();
        self.launch(task, move |stop| execute.execute(stop))
    }

    fn launch(
        &mut self,
        task: Task,
        operation: impl FnOnce(&AtomicBool) -> Result<Outcome> + Send + 'static,
    ) -> Result<()> {
        ensure!(!self.is_running(), "a saved-file review is already running");
        task.validate()?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let worker = thread::Builder::new()
            .name("saved-file-review".into())
            .spawn(move || operation(&flag))
            .context("start saved-file review worker")?;
        self.job = Some(Job { task, stop, worker });
        self.completed = None;
        self.error = None;
        self.state = State::Running;
        Ok(())
    }

    pub fn cancel(&mut self) {
        if let Some(job) = &self.job {
            job.stop.store(true, Relaxed);
            self.state = State::Cancelling;
        }
    }

    pub fn poll(&mut self) {
        if !self
            .job
            .as_ref()
            .is_some_and(|job| job.worker.is_finished())
        {
            return;
        }
        let job = self.job.take().expect("finished job");
        let result = job.worker.join();
        if job.stop.load(Relaxed) {
            self.state = State::Cancelled;
            return;
        }
        match result {
            Ok(Ok(outcome)) => {
                self.completed = Some(Completed {
                    task: job.task,
                    outcome,
                });
                self.state = State::Complete;
            }
            Ok(Err(error)) => {
                self.error = Some(format!("{error:#}"));
                self.state = State::Failed;
            }
            Err(_) => {
                self.error = Some("saved-file review worker panicked".into());
                self.state = State::Failed;
            }
        }
    }

    pub fn save_new(&self, path: &Path) -> Result<()> {
        ensure!(
            !self.is_running(),
            "wait for saved-file review to finish before exporting"
        );
        let completed = self
            .completed
            .as_ref()
            .context("no completed review to export")?;
        ensure!(
            path.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json")),
            "export path must end in .json"
        );
        let mut file = std::fs::File::create_new(path)
            .context("create new review export; existing files are preserved")?;
        serde_json::to_writer_pretty(&mut file, &completed.outcome)?;
        writeln!(file)?;
        file.sync_all().context("flush review export")?;
        Ok(())
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        // Jobs only read source files. Closing the window does not wait on a blocked file system.
        if let Some(job) = &self.job {
            job.stop.store(true, Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        benchmark::{Frontend, RunContext},
        model::{Field, Profile},
        run::{Mode, RunOptions},
    };
    use std::{
        sync::{atomic::AtomicU64, mpsc},
        time::{Duration, Instant},
    };

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let parent = std::env::current_dir().unwrap().join(".local");
            std::fs::create_dir_all(&parent).unwrap();
            let root = parent.join(format!(
                "review-test-{}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Relaxed),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&root).unwrap();
            assert!(
                root.canonicalize()
                    .unwrap()
                    .starts_with(parent.canonicalize().unwrap())
            );
            let profile = Profile {
                tx_bytes: 1,
                tx: vec![Field {
                    name: "Counter".into(),
                    width: 8,
                    ..Field::default()
                }],
                ..Profile::default()
            };
            let options = RunOptions {
                frontend: Frontend::Cli,
                mode: Mode::Simulate { faults: false },
                duration: Duration::from_secs(1),
                csv: Some(root.join("capture.csv")),
                generation: 1,
            };
            let context = RunContext::new(&profile, &options).unwrap();
            let saved = serde_json::json!({"context":context,"scheduler":"deadline","requested_cycle_us":1000,
                "input_loss_timeout_ms":1000,"connection_generation":1,"cycles":1,"replies":1,"valid":0,
                "timeouts":0,"transport_errors":0,"missed_deadlines":0,"wkc_mismatches":1,"state_mismatches":0,
                "capture":{"selected":0,"written":0,"overruns":0,"utc_start":"2026-01-01T00:00:00Z","parts":1},
                "cancelled":false,"error":"Authored zero-valid review fixture"});
            std::fs::write(
                root.join("run.json"),
                serde_json::to_vec_pretty(&saved).unwrap(),
            )
            .unwrap();
            std::fs::write(root.join("capture.csv"),b"capture_start_utc,elapsed_us,sample_index,connection_generation,cycle_index,Counter\n").unwrap();
            Self(root)
        }
        fn task(&self) -> Task {
            Task::Audit(Input {
                report: self.0.join("run.json"),
                csv: Some(self.0.join("capture.csv")),
            })
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            for name in [
                "run.json",
                "capture.csv",
                "result.json",
                "trial-0.json",
                "trial-1.json",
                "trial-0.csv",
                "trial-1.csv",
            ] {
                let _ = std::fs::remove_file(self.0.join(name));
            }
            let _ = std::fs::remove_dir(&self.0); // Nonrecursive; unknown files are preserved.
        }
    }
    fn finish(controller: &mut Controller) {
        let end = Instant::now() + Duration::from_secs(5);
        while controller.is_running() && Instant::now() < end {
            controller.poll();
            thread::sleep(Duration::from_millis(1));
        }
        assert!(
            !controller.is_running(),
            "review worker exceeded test bound"
        );
    }

    #[test]
    fn validates_paths_counts_and_pre_cancelled_work_without_opening_files() {
        let input = Input {
            report: "missing.json".into(),
            csv: None,
        };
        assert!(Task::Audit(input.clone()).validate().is_err());
        assert!(
            Task::Compare {
                inputs: vec![input.clone()],
                audit_csv: false
            }
            .validate()
            .is_err()
        );
        assert!(
            Task::Compare {
                inputs: vec![input.clone(); 33],
                audit_csv: false
            }
            .validate()
            .is_err()
        );
        assert!(
            Task::Compare {
                inputs: vec![input.clone(); 2],
                audit_csv: false
            }
            .validate()
            .is_ok()
        );
        let task = Task::Audit(Input {
            csv: Some("missing.csv".into()),
            ..input
        });
        assert!(
            task.execute(&AtomicBool::new(true))
                .unwrap_err()
                .to_string()
                .contains("cancelled")
        );
    }

    #[test]
    fn real_audit_preserves_outcome_and_exports_the_cli_schema_without_overwriting_inputs() {
        let fixture = Fixture::new();
        let mut controller = Controller::default();
        assert_eq!(controller.state(), State::Idle);
        controller.start(fixture.task()).unwrap();
        finish(&mut controller);
        assert_eq!(controller.state(), State::Complete);
        let Outcome::Audit(audit) = &controller.completed().unwrap().outcome else {
            panic!("expected audit")
        };
        assert_eq!(audit.rows, 0);
        assert!(audit.run_error.is_some());
        let original = std::fs::read(fixture.0.join("run.json")).unwrap();
        assert!(controller.save_new(&fixture.0.join("run.json")).is_err());
        assert_eq!(std::fs::read(fixture.0.join("run.json")).unwrap(), original);
        controller.save_new(&fixture.0.join("result.json")).unwrap();
        let exported = std::fs::read(fixture.0.join("result.json")).unwrap();
        assert!(!exported.starts_with(b"\xef\xbb\xbf") && exported.ends_with(b"\n"));
        let value: serde_json::Value = serde_json::from_slice(&exported).unwrap();
        assert_eq!(value["rows"], 0);
        assert_eq!(value["report_sha256"], audit.report_sha256);
        assert!(value.get("Audit").is_none());
        assert!(controller.save_new(&fixture.0.join("wrong.txt")).is_err());
        assert!(!fixture.0.join("wrong.txt").exists());
    }

    #[test]
    fn rejects_overlapping_jobs_and_exports_then_cancels_without_a_result() {
        let fixture = Fixture::new();
        let task = fixture.task();
        let execute = task.clone();
        let (release, wait) = mpsc::channel();
        let mut controller = Controller::default();
        controller
            .launch(task, move |stop| {
                wait.recv_timeout(Duration::from_secs(5))?;
                execute.execute(stop)
            })
            .unwrap();
        assert!(controller.start(fixture.task()).is_err());
        assert!(controller.save_new(&fixture.0.join("result.json")).is_err());
        controller.cancel();
        assert_eq!(controller.state(), State::Cancelling);
        release.send(()).unwrap();
        finish(&mut controller);
        assert_eq!(controller.state(), State::Cancelled);
        assert!(controller.completed().is_none() && controller.error().is_none());
        assert!(controller.save_new(&fixture.0.join("result.json")).is_err());
        assert!(!fixture.0.join("result.json").exists());
    }

    #[test]
    fn late_cancellation_discards_an_unpublished_success() {
        let fixture = Fixture::new();
        let mut controller = Controller::default();
        controller.start(fixture.task()).unwrap();
        let end = Instant::now() + Duration::from_secs(5);
        while !controller.job.as_ref().unwrap().worker.is_finished() && Instant::now() < end {
            thread::yield_now();
        }
        assert!(controller.job.as_ref().unwrap().worker.is_finished());
        controller.cancel();
        finish(&mut controller);
        assert_eq!(controller.state(), State::Cancelled);
        assert!(controller.completed().is_none());
    }

    #[test]
    fn failures_clear_previous_results_and_allow_an_explicit_new_job() {
        let fixture = Fixture::new();
        let mut controller = Controller::default();
        controller.start(fixture.task()).unwrap();
        finish(&mut controller);
        controller
            .start(Task::Audit(Input {
                report: fixture.0.join("missing.json"),
                csv: Some(fixture.0.join("capture.csv")),
            }))
            .unwrap();
        assert!(controller.completed().is_none());
        finish(&mut controller);
        assert_eq!(controller.state(), State::Failed);
        assert!(controller.error().unwrap().contains("missing.json"));
        controller.start(fixture.task()).unwrap();
        finish(&mut controller);
        assert_eq!(controller.state(), State::Complete);
        assert!(controller.error().is_none());
    }

    #[test]
    fn completed_results_keep_the_original_request_when_editor_copies_change() {
        let fixture = Fixture::new();
        let mut edited = fixture.task();
        let original = edited.clone();
        let execute = edited.clone();
        let (release, wait) = mpsc::channel();
        let mut controller = Controller::default();
        controller
            .launch(edited.clone(), move |stop| {
                wait.recv_timeout(Duration::from_secs(5))?;
                execute.execute(stop)
            })
            .unwrap();
        if let Task::Audit(input) = &mut edited {
            input.report = "different.json".into();
        }
        release.send(()).unwrap();
        finish(&mut controller);
        assert_eq!(controller.completed().unwrap().task, original);
        assert_ne!(controller.completed().unwrap().task, edited);
    }

    #[test]
    fn dropping_the_controller_requests_stop_without_waiting_on_the_worker() {
        let fixture = Fixture::new();
        let (stopped, wait) = mpsc::channel();
        let mut controller = Controller::default();
        controller
            .launch(fixture.task(), move |stop| {
                while !stop.load(Relaxed) {
                    thread::sleep(Duration::from_millis(1));
                }
                stopped.send(()).unwrap();
                anyhow::bail!("cancelled")
            })
            .unwrap();
        drop(controller);
        wait.recv_timeout(Duration::from_secs(5)).unwrap();
    }

    #[test]
    fn background_comparison_uses_the_real_csv_auditor_and_retains_each_trial() {
        let fixture = Fixture::new();
        let mut inputs = Vec::new();
        for (index, scheduler) in [
            crate::model::Scheduler::Deadline,
            crate::model::Scheduler::Relative,
        ]
        .into_iter()
        .enumerate()
        {
            let mut saved: serde_json::Value =
                serde_json::from_slice(&std::fs::read(fixture.0.join("run.json")).unwrap())
                    .unwrap();
            let mut profile: Profile =
                serde_json::from_value(saved["context"]["profile"].clone()).unwrap();
            profile.scheduler = scheduler;
            let csv = fixture.0.join(format!("trial-{index}.csv"));
            let options = RunOptions {
                frontend: Frontend::Cli,
                mode: Mode::Simulate { faults: false },
                duration: Duration::from_secs(1),
                csv: Some(csv.clone()),
                generation: 1,
            };
            saved["context"] =
                serde_json::to_value(RunContext::new(&profile, &options).unwrap()).unwrap();
            saved["scheduler"] = serde_json::to_value(scheduler).unwrap();
            let utc = format!("2026-01-01T00:00:{index:02}Z");
            let fields = saved.as_object_mut().unwrap();
            // Authored host-stall evidence: two exchanges, then a late wake at the duration limit.
            fields.extend(serde_json::json!({"cycles":2,"replies":2,"valid":2,"wkc_mismatches":0,
                "missed_deadlines":998,"cyclic_elapsed_us":1000000,"backend":"Synthetic fixture","expected_wkc":1,
                "send_spacing":{"count":1,"p50_us":1000,"p95_us":1000,"p99_us":1000,"longest_gap_us":1000},
                "receive_spacing":{"count":1,"p50_us":1000,"p95_us":1000,"p99_us":1000,"longest_gap_us":1000},
                "capture":{"selected":2,"written":2,"overruns":0,"parts":1,"utc_start":utc},
                "devices":[{"position":0,"station_address":0,"alias":0,"link_ports":[false,false,false,false],"identity":null,"serial":null,"tx_bytes":1,"rx_bytes":0}],
                "synchronization":null,"pdo_verification":null,"stopped_al":null,"ignored_frames":0,"error":null
            }).as_object().unwrap().clone());
            let report = fixture.0.join(format!("trial-{index}.json"));
            std::fs::write(&report, serde_json::to_vec_pretty(&saved).unwrap()).unwrap();
            std::fs::write(&csv,format!("capture_start_utc,elapsed_us,sample_index,connection_generation,cycle_index,Counter\n{utc},100,1,1,1,1\n{utc},1100,2,1,2,1\n")).unwrap();
            inputs.push(Input {
                report,
                csv: Some(csv),
            });
        }
        let mut controller = Controller::default();
        controller
            .start(Task::Compare {
                inputs,
                audit_csv: true,
            })
            .unwrap();
        finish(&mut controller);
        assert_eq!(
            controller.state(),
            State::Complete,
            "{:?}",
            controller.error()
        );
        let Outcome::Comparison(result) = &controller.completed().unwrap().outcome else {
            panic!("expected comparison")
        };
        assert_eq!(result.trials.len(), 2);
        assert_eq!(result.trials[0].missed_deadlines, 998);
        assert!(
            result
                .csv_audits
                .as_ref()
                .unwrap()
                .iter()
                .all(|a| a.rows == 2)
        );
    }
}

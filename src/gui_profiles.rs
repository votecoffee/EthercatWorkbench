//! Desktop profile drafts and create-new saves.
use super::*;

pub(super) enum ProfileAction {
    Load(PathBuf),
    Demo,
    Close,
}

#[derive(Default)]
pub(super) struct ProfileEditor {
    baseline: Profile,
    source: Option<PathBuf>,
    pub(super) load_path: String,
    save_path: String,
    pending: Option<ProfileAction>,
    feedback: String,
    pub(super) close_confirmed: bool,
}

impl App {
    pub(super) fn profile_is_dirty(&self) -> bool {
        self.profile != self.profile_editor.baseline
    }

    pub(super) fn load_profile(&mut self, path: PathBuf) {
        match Profile::load(&path) {
            Ok(profile) => {
                let message = format!("Loaded {}", path.display());
                self.replace_profile(profile, Some(path), message);
            }
            Err(error) => {
                // Keep the current draft, even after the user confirmed replacement.
                self.profile_feedback(format!("Load profile: {error:#}"));
            }
        }
    }

    fn replace_profile(&mut self, profile: Profile, source: Option<PathBuf>, message: String) {
        self.profile_editor.baseline = profile.clone();
        self.profile_editor.source = source;
        self.profile_editor.save_path.clear();
        self.profile = profile;
        self.profile_pdo_draft = None;
        self.stage = gui_stage::Panel::default();
        self.mode_pdos = gui_mode_pdo::Panel::default();
        self.invalidate_bench_review();
        self.last = None;
        self.profile_feedback(message);
    }

    fn profile_feedback(&mut self, message: String) {
        self.message.clone_from(&message);
        self.profile_editor.feedback = message;
    }

    fn save_profile_draft(&mut self) -> bool {
        let path = PathBuf::from(self.profile_editor.save_path.trim());
        match self.profile.save(&path) {
            Ok(()) => {
                self.profile_editor.baseline = self.profile.clone();
                self.profile_feedback(format!("Saved {}", path.display()));
                self.profile_editor.source = Some(path);
                self.profile_editor.save_path.clear();
                true
            }
            Err(error) => {
                self.profile_feedback(format!("Save profile: {error:#}"));
                false
            }
        }
    }

    pub(super) fn request_profile_action(&mut self, ctx: &egui::Context, action: ProfileAction) {
        if self.profile_is_dirty() {
            if matches!(action, ProfileAction::Close) {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            }
            self.profile_editor.pending = Some(action);
            self.profile_editor.feedback.clear();
        } else {
            self.perform_profile_action(ctx, action);
        }
    }

    fn perform_profile_action(&mut self, ctx: &egui::Context, action: ProfileAction) {
        match action {
            ProfileAction::Load(path) => self.load_profile(path),
            ProfileAction::Demo => {
                let demo = serde_json::from_str(include_str!("../samples/synthetic.json"))
                    .expect("authored demo profile");
                self.replace_profile(
                    demo,
                    None,
                    "Offline demo loaded. Choose Connect… to start an offline session.".into(),
                );
            }
            ProfileAction::Close => {
                self.profile_editor.close_confirmed = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    fn continue_profile_action(&mut self, ctx: &egui::Context, save: bool) {
        let Some(action) = &self.profile_editor.pending else {
            return;
        };
        if self.session.is_some() || self.host_check.is_running() {
            return;
        }
        // Closing can proceed after the acquisition/host workers have drained, even
        // when a cancelled file review or a read-only discovery is still finishing.
        if self.busy() && (save || !matches!(action, ProfileAction::Close)) {
            return;
        }
        if save && !self.save_profile_draft() {
            return;
        }
        let action = self
            .profile_editor
            .pending
            .take()
            .expect("pending profile action");
        self.perform_profile_action(ctx, action);
    }

    pub(super) fn profile_file_controls(&mut self, ui: &mut egui::Ui) {
        if self.profile_is_dirty() {
            ui.strong("Unsaved profile changes");
        }
        if let Some(path) = &self.profile_editor.source {
            ui.label(format!("Last loaded or saved · {}", path.display()));
        }
        if !self.profile_editor.feedback.is_empty() {
            ui.label(&self.profile_editor.feedback);
        }
        ui.add_enabled_ui(!self.busy(), |ui| {
            ui.label("Profile name");
            ui.text_edit_singleline(&mut self.profile.name);
            ui.separator();
            ui.label("Existing profile JSON");
            ui.horizontal_wrapped(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.profile_editor.load_path)
                        .desired_width(410.0),
                );
                let path = self.profile_editor.load_path.trim();
                if ui
                    .add_enabled(!path.is_empty(), egui::Button::new("Load"))
                    .clicked()
                {
                    self.request_profile_action(ui.ctx(), ProfileAction::Load(PathBuf::from(path)));
                }
            });
            ui.label("New profile JSON");
            ui.horizontal_wrapped(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.profile_editor.save_path)
                        .desired_width(410.0),
                );
                if ui
                    .add_enabled(
                        !self.profile_editor.save_path.trim().is_empty(),
                        egui::Button::new("Save new"),
                    )
                    .clicked()
                {
                    self.save_profile_draft();
                }
            });
        });
    }

    pub(super) fn show_profile_confirmation(&mut self, ctx: &egui::Context) {
        let Some(action) = &self.profile_editor.pending else {
            return;
        };
        let (prompt, discard, closing) = match action {
            ProfileAction::Load(path) => (
                format!("Load {}?", path.display()),
                "Discard edits and load",
                false,
            ),
            ProfileAction::Demo => (
                "Replace this profile with the offline demo?".into(),
                "Discard edits and load demo",
                false,
            ),
            ProfileAction::Close => (
                "Close EtherCAT Workbench?".into(),
                "Discard edits and close",
                true,
            ),
        };
        let response = egui::Modal::new(egui::Id::new("unsaved_profile")).show(ctx, |ui| {
            ui.set_width(500.0);
            ui.heading("Unsaved profile changes");
            ui.add(egui::Label::new(prompt).wrap());
            ui.label("Save your edits to a new JSON file, discard them, or keep editing.");
            if !self.profile_editor.feedback.is_empty() {
                ui.label(&self.profile_editor.feedback);
            }
            if self.busy() {
                ui.label("Saving is available after the current work finishes.");
            }
            ui.add_enabled_ui(!self.busy(), |ui| {
                ui.label("New profile JSON");
                ui.add(
                    egui::TextEdit::singleline(&mut self.profile_editor.save_path)
                        .desired_width(450.0),
                );
            });
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        !self.busy() && !self.profile_editor.save_path.trim().is_empty(),
                        egui::Button::new("Save new and continue"),
                    )
                    .clicked()
                {
                    self.continue_profile_action(ctx, true);
                }
                if ui
                    .add_enabled(closing || !self.busy(), egui::Button::new(discard))
                    .clicked()
                {
                    self.continue_profile_action(ctx, false);
                }
                if ui.button("Cancel").clicked() {
                    self.profile_editor.pending = None;
                }
            });
        });
        if response.should_close() {
            self.profile_editor.pending = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_before_load_preserves_the_draft_and_freezes_the_requested_source() {
        let dir = PathBuf::from(".local").join(format!(
            "profile-gui-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let replacement = dir.join("replacement.json");
        let saved = dir.join("draft.json");
        let mut source = Profile {
            name: "Replacement".into(),
            ..Default::default()
        };
        source.save(&replacement).unwrap();
        let original = std::fs::read(&replacement).unwrap();
        let ctx = egui::Context::default();
        let mut app = App::new(Args::parse_from(["ethercat-workbench"]));
        app.request_profile_action(&ctx, ProfileAction::Demo);
        assert!(!app.profile_is_dirty());
        app.profile.name = "Edited demo".into();
        let draft = app.profile.clone();
        app.request_profile_action(&ctx, ProfileAction::Load(replacement.clone()));
        app.profile_editor.load_path = "unrelated.json".into();

        app.profile_editor.save_path = replacement.to_string_lossy().into_owned();
        app.continue_profile_action(&ctx, true);
        assert!(app.profile_editor.pending.is_some() && app.profile_is_dirty());
        assert_eq!(app.profile, draft);
        assert_eq!(std::fs::read(&replacement).unwrap(), original);

        app.profile_editor.save_path = saved.to_string_lossy().into_owned();
        app.continue_profile_action(&ctx, true);
        assert_eq!(Profile::load(&saved).unwrap(), draft);
        assert_eq!(app.profile, source);
        assert_eq!(app.profile_editor.source, Some(replacement.clone()));
        assert!(!app.profile_is_dirty() && app.profile_editor.pending.is_none());

        source.name.push('!');
        app.profile = source.clone();
        app.request_profile_action(&ctx, ProfileAction::Load(dir.join("missing.json")));
        app.continue_profile_action(&ctx, false);
        assert_eq!(app.profile, source);
        assert_eq!(app.profile_editor.source, Some(replacement.clone()));
        assert!(app.profile_is_dirty() && app.message.contains("Load profile:"));

        std::fs::remove_file(saved).unwrap();
        std::fs::remove_file(replacement).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn deferred_close_protects_dirty_profile_after_work_finishes() {
        let ctx = egui::Context::default();
        let mut app = App::new(Args::parse_from(["ethercat-workbench"]));
        app.profile.name = "Unsaved edit".into();
        let (tx, rx) = std::sync::mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        app.session = Some(Session {
            csv_base: None,
            stop: stop.clone(),
            view: Arc::new(Mutex::new(Snapshot::default())),
            worker: std::thread::spawn(move || {
                rx.recv().unwrap();
                Report::default()
            }),
        });
        let output = ctx.run(Default::default(), |ctx| app.prepare_close(ctx));
        assert!(stop.load(Relaxed));
        assert!(app.deferred_close && app.profile_editor.pending.is_none());
        assert!(
            output.viewport_output[&egui::ViewportId::ROOT]
                .commands
                .iter()
                .any(|c| matches!(c, egui::ViewportCommand::CancelClose))
        );
        tx.send(()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while app.session.is_some() {
            let output = ctx.run(Default::default(), |ctx| app.refresh(ctx));
            assert!(
                !output.viewport_output[&egui::ViewportId::ROOT]
                    .commands
                    .iter()
                    .any(|c| matches!(c, egui::ViewportCommand::Close))
            );
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(!app.deferred_close);
        assert!(matches!(
            app.profile_editor.pending,
            Some(ProfileAction::Close)
        ));
        let output = ctx.run(Default::default(), |ctx| {
            app.continue_profile_action(ctx, false)
        });
        assert!(app.profile_editor.close_confirmed);
        assert!(
            output.viewport_output[&egui::ViewportId::ROOT]
                .commands
                .iter()
                .any(|c| matches!(c, egui::ViewportCommand::Close))
        );
    }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Output},
    sync::{Arc, Mutex},
    thread::JoinHandle,
};

fn project_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn kernel_path() -> PathBuf {
    project_root()
        .join("uml-kernel/cache")
        .join(format!("linux-{}", std::env::consts::ARCH))
}

fn bin_dir() -> PathBuf {
    let bin = assert_cmd::cargo::cargo_bin!("pinchyd");
    bin.parent().unwrap().to_path_buf()
}

fn init_script() -> PathBuf {
    project_root().join("uml-kernel/uml-test-runner.sh")
}

#[derive(Clone, Debug)]
pub enum TestMode {
    Standard,
    ServerOnly,
    CheckCaps,
    AutoQuit,
    AutoQuitAfterClient,
}

impl TestMode {
    fn as_str(&self) -> &'static str {
        match self {
            TestMode::Standard => "standard",
            TestMode::ServerOnly => "server_only",
            TestMode::CheckCaps => "check_caps",
            TestMode::AutoQuit => "auto_quit",
            TestMode::AutoQuitAfterClient => "auto_quit_after_client",
        }
    }
}

struct UmlResult {
    pinchy_output: Output,
    pinchyd_output: Output,
}

pub struct PinchyTest {
    output_dir: tempfile::TempDir,
    mode: TestMode,
    result: Arc<Mutex<Option<UmlResult>>>,
}

fn describe_file(path: &Path) -> String {
    match fs::read(path) {
        Ok(contents) if contents.is_empty() => "<exists but empty>".to_string(),
        Ok(contents) => String::from_utf8_lossy(&contents).into_owned(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "<file not found>".to_string(),
        Err(e) => {
            format!("<read error: {e}>")
        }
    }
}

fn read_file_or_empty(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_default()
}

fn read_exit_code(path: &Path) -> i32 {
    fs::read_to_string(path)
        .unwrap_or_else(|_| "1".to_string())
        .trim()
        .parse()
        .unwrap_or(1)
}

fn make_exit_status(code: i32) -> ExitStatus {
    // On Unix, ExitStatus::from_raw expects the wait(2) status format
    // where the exit code is in bits 8-15.
    std::os::unix::process::ExitStatusExt::from_raw(code << 8)
}

fn boot_uml(
    mode: &TestMode,
    output_dir: &Path,
    events: Option<&str>,
    workload: Option<&str>,
    test_name: Option<&str>,
) -> UmlResult {
    let kpath = kernel_path();

    assert!(
        kpath.exists(),
        "UML kernel not found at {}. Build it with: \
         ./uml-kernel/build-kernel.sh",
        kpath.display()
    );

    let bdir = bin_dir();
    let proj = project_root();
    let init = init_script();

    let events_str = events.unwrap_or("");
    let workload_str = workload.unwrap_or("");
    let test_name_str = test_name.unwrap_or("");

    let args = vec![
        "mem=64M".to_string(),
        "root=/dev/root".to_string(),
        "rootfstype=hostfs".to_string(),
        "hostfs=/".to_string(),
        format!("init={}", init.display()),
        "con0=fd:1,fd:1".to_string(),
        "con=null".to_string(),
        format!("PINCHY_TEST_EVENTS={events_str}"),
        format!("PINCHY_TEST_WORKLOAD={workload_str}"),
        format!("PINCHY_TEST_OUTDIR={}", output_dir.display()),
        format!("PINCHY_TEST_BINDIR={}", bdir.display()),
        format!("PINCHY_TEST_PROJDIR={}", proj.display()),
        format!("PINCHY_TEST_MODE={}", mode.as_str()),
        format!("PINCHY_TEST_NAME={test_name_str}"),
    ];

    let output = Command::new(&kpath)
        .args(&args)
        .output()
        .expect("Failed to spawn UML kernel");

    // Save UML console output for debugging
    let console_path = output_dir.join("uml-console.log");
    let _ = fs::write(&console_path, &output.stdout);

    if !output.status.success() {
        eprintln!(
            "UML kernel exited with status: {}. \
             Output dir: {}",
            output.status,
            output_dir.display()
        );
    }

    let done_marker = output_dir.join("done");

    if !done_marker.exists() {
        let console = String::from_utf8_lossy(&output.stdout);

        panic!(
            "UML did not complete: 'done' marker not found \
             in {}\n\
             Test mode: {:?}, events: {:?}, \
             workload: {:?}, name: {:?}\n\
             UML exit status: {}\n\
             UML console output:\n{}\n\
             pinchyd.out: {}\n\
             pinchy.stderr: {}",
            output_dir.display(),
            mode,
            events,
            workload,
            test_name,
            output.status,
            console,
            describe_file(&output_dir.join("pinchyd.out")),
            describe_file(&output_dir.join("pinchy.stderr")),
        );
    }

    let pinchy_stdout = read_file_or_empty(&output_dir.join("pinchy.stdout"));
    let pinchy_stderr = read_file_or_empty(&output_dir.join("pinchy.stderr"));
    let pinchy_exit = read_exit_code(&output_dir.join("pinchy.exit"));

    let pinchyd_stdout = read_file_or_empty(&output_dir.join("pinchyd.out"));
    let pinchyd_exit = read_exit_code(&output_dir.join("pinchyd.exit"));

    UmlResult {
        pinchy_output: Output {
            status: make_exit_status(pinchy_exit),
            stdout: pinchy_stdout,
            stderr: pinchy_stderr,
        },
        pinchyd_output: Output {
            status: make_exit_status(pinchyd_exit),
            stdout: pinchyd_stdout,
            stderr: vec![],
        },
    }
}

impl Default for PinchyTest {
    fn default() -> Self {
        Self::new()
    }
}

impl PinchyTest {
    pub fn new() -> Self {
        Self::with_mode(TestMode::ServerOnly)
    }

    pub fn with_mode(mode: TestMode) -> Self {
        let output_dir = tempfile::TempDir::with_prefix("uml-").expect("Failed to create temp dir");

        let result = Arc::new(Mutex::new(None));

        PinchyTest {
            output_dir,
            mode,
            result,
        }
    }

    pub fn read_file(&self, name: &str) -> String {
        self.ensure_booted();
        let path = self.output_dir.path().join(name);
        fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()))
    }

    pub fn read_timestamp(&self, name: &str) -> Option<u64> {
        self.ensure_booted();
        let path = self.output_dir.path().join(name);

        fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }

    fn ensure_booted(&self) {
        let has_result = self.result.lock().unwrap().is_some();

        if !has_result {
            let result = boot_uml(&self.mode, self.output_dir.path(), None, None, None);

            *self.result.lock().unwrap() = Some(result);
        }
    }

    pub fn wait(self) -> Output {
        self.ensure_booted();

        let mut result = self.result.lock().unwrap().take().unwrap();

        std::mem::replace(
            &mut result.pinchyd_output,
            Output {
                status: make_exit_status(0),
                stdout: vec![],
                stderr: vec![],
            },
        )
    }
}

pub fn run_workload(pinchy: &PinchyTest, events: &[&str], test_name: &str) -> JoinHandle<Output> {
    let events_str = events.join(",");
    let test_name = test_name.to_owned();
    let output_dir = pinchy.output_dir.path().to_path_buf();
    let result_arc = Arc::clone(&pinchy.result);

    std::thread::spawn(move || {
        let mode = TestMode::Standard;
        let mut uml_result = boot_uml(
            &mode,
            &output_dir,
            Some(&events_str),
            Some(&test_name),
            Some(&test_name),
        );

        // Take the pinchy output before storing the result
        let pinchy_output = std::mem::replace(
            &mut uml_result.pinchy_output,
            Output {
                status: make_exit_status(0),
                stdout: vec![],
                stderr: vec![],
            },
        );

        *result_arc.lock().unwrap() = Some(uml_result);

        pinchy_output
    })
}

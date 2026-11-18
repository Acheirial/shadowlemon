//! Daemon, pidfile and signal plumbing for Linux.
//!
//! The child is started in its own process group, pidfiles are created
//! atomically and carry the Linux `/proc/<pid>/stat` start time as an identity
//! token, and stopping sends SIGTERM before escalating to SIGKILL.
//!
//! This is the only module that uses `unsafe`: POSIX signal registration and
//! `kill(2)` have no safe std equivalent.

use std::{
    fs, io,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicI32, Ordering},
    time::{Duration, Instant},
};

use crate::{config::Mode, AppError};

/// Set by the POSIX signal handler; polled by the async run loops.
static STOP_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn record_signal(signal: i32) {
    STOP_SIGNAL.store(signal, Ordering::SeqCst);
}

/// Install SIGINT/SIGTERM handlers and return the shared flag.
pub fn install_signal_handlers() -> &'static AtomicI32 {
    // SAFETY: `record_signal` only writes to an `AtomicI32`, which is
    // async-signal-safe, and the handler has no captured state.
    unsafe {
        libc::signal(libc::SIGINT, record_signal as *const () as usize);
        libc::signal(libc::SIGTERM, record_signal as *const () as usize);
    }
    &STOP_SIGNAL
}

/// Whether a shutdown signal was observed.
pub fn shutdown_requested(flag: &AtomicI32) -> bool {
    flag.load(Ordering::SeqCst) != 0
}

/// PID file path for a mode, mirroring the Go deployment contract.
pub fn pid_path(mode: Mode) -> Result<PathBuf, AppError> {
    Ok(match mode {
        Mode::Client => crate::config::state_dir()?.join("shadowlemon.pid"),
        Mode::Server => PathBuf::from("/var/run/shadowlemon/shadowlemon.pid"),
    })
}

fn process_identity() -> String {
    if let Ok(stat) = fs::read_to_string("/proc/self/stat") {
        // Field 22 (starttime) follows the parenthesised command name.
        if let Some(close) = stat.rfind(')') {
            let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
            if let Some(starttime) = fields.get(19) {
                return (*starttime).to_owned();
            }
        }
    }
    String::new()
}

fn identity_of(pid: i32) -> Option<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.rfind(')')?;
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    fields.get(19).map(|value| (*value).to_owned())
}

fn process_alive(pid: i32) -> bool {
    // SAFETY: `kill` with signal 0 only checks permissions/liveness.
    unsafe { libc::kill(pid, 0) == 0 || *libc::__errno_location() == libc::EPERM }
}

fn send_signal(pid: i32, signal: i32) -> io::Result<()> {
    // SAFETY: `signal` is a plain number; no memory is passed.
    let result = unsafe { libc::kill(pid, signal) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_pidfile(path: &PathBuf) -> Result<(i32, String), AppError> {
    let text = fs::read_to_string(path)
        .map_err(|error| AppError::Daemon(format!("cannot read {}: {error}", path.display())))?;
    let mut fields = text.split_whitespace();
    let pid = fields
        .next()
        .and_then(|value| value.parse::<i32>().ok())
        .ok_or_else(|| AppError::Daemon(format!("invalid pid file {}", path.display())))?;
    let identity = fields.next().unwrap_or("").to_owned();
    Ok((pid, identity))
}

fn matches_process(pid: i32, identity: &str) -> bool {
    if !process_alive(pid) {
        return false;
    }
    if identity.is_empty() {
        return true;
    }
    identity_of(pid).as_deref() == Some(identity)
}

/// Guard held by `run` while it owns the pidfile.
pub struct PidFile {
    path: PathBuf,
    pid: i32,
    identity: String,
}

impl PidFile {
    /// Atomically acquire the pidfile for this process.
    pub fn acquire(mode: Mode) -> Result<Self, AppError> {
        let path = pid_path(mode)?;
        let pid = std::process::id() as i32;
        let identity = process_identity();
        let content = format!("{pid} {identity}\n");
        let mut last_error = None;
        for _ in 0..10 {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    use io::Write;
                    file.write_all(content.as_bytes()).map_err(|error| {
                        AppError::Daemon(format!("cannot write {}: {error}", path.display()))
                    })?;
                    return Ok(Self {
                        path,
                        pid,
                        identity,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if let Ok((old_pid, old_identity)) = read_pidfile(&path) {
                        if matches_process(old_pid, &old_identity) {
                            return Err(AppError::Daemon(format!(
                                "{} is already running (pid {old_pid})",
                                mode.as_str()
                            )));
                        }
                    }
                    let _ = fs::remove_file(&path);
                    last_error = Some(error);
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => return Err(AppError::Daemon(error.to_string())),
            }
        }
        Err(AppError::Daemon(format!(
            "could not acquire {}: {last_error:?}",
            path.display()
        )))
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        if let Ok((pid, identity)) = read_pidfile(&self.path) {
            if pid == self.pid && (identity == self.identity || identity.is_empty()) {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

/// Spawn `shadowlemon <mode> run` in a new process group and wait for its
/// pidfile (10 s timeout, matching the Go daemon contract).
pub fn start_daemon(mode: Mode) -> Result<(), AppError> {
    let path = pid_path(mode)?;
    if let Ok((pid, identity)) = read_pidfile(&path) {
        if matches_process(pid, &identity) {
            return Err(AppError::Daemon(format!(
                "{} is already running (pid {pid})",
                mode.as_str()
            )));
        }
        let _ = fs::remove_file(&path);
    }
    let executable = std::env::current_exe()
        .map_err(|error| AppError::Daemon(format!("cannot locate executable: {error}")))?;
    let mut command = Command::new(executable);
    command
        .arg(mode.as_str())
        .arg("run")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let child = command
        .spawn()
        .map_err(|error| AppError::Daemon(format!("cannot start daemon: {error}")))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok((pid, identity)) = read_pidfile(&path) {
            if pid == child.id() as i32 && (identity.is_empty() || matches_process(pid, &identity))
            {
                println!("{} started (pid {pid})", mode.as_str());
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(AppError::Daemon(format!(
        "{} daemon did not create its pidfile within 10s",
        mode.as_str()
    )))
}

/// Stop a daemon: SIGTERM, poll up to 10 s, then SIGKILL.
pub fn stop_daemon(mode: Mode) -> Result<bool, AppError> {
    let path = pid_path(mode)?;
    let (pid, identity) = match read_pidfile(&path) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    if !matches_process(pid, &identity) {
        let _ = fs::remove_file(&path);
        return Ok(false);
    }
    send_signal(pid, 15)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && process_alive(pid) {
        std::thread::sleep(Duration::from_millis(100));
    }
    if process_alive(pid) {
        send_signal(pid, 9)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline && process_alive(pid) {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    if let Ok((_, current)) = read_pidfile(&path) {
        if current == identity || current.is_empty() {
            let _ = fs::remove_file(&path);
        }
    }
    Ok(true)
}

/// Report whether a mode's pidfile describes a live process.
pub fn daemon_status(mode: Mode) -> Result<bool, AppError> {
    let path = pid_path(mode)?;
    match read_pidfile(&path) {
        Ok((pid, identity)) if matches_process(pid, &identity) => {
            println!("{} is RUNNING (pid {pid})", mode.as_str());
            Ok(true)
        }
        _ => {
            println!("{} is STOPPED", mode.as_str());
            Ok(false)
        }
    }
}

//! Daemon, pidfile, signal and socket-protection plumbing.
//!
//! Unix follows `rust/docs/platform-notes.md`: the child is started in its own
//! process group, pidfiles are created atomically and carry the Linux
//! `/proc/<pid>/stat` start time as an identity token, and stopping sends
//! SIGTERM before escalating to SIGKILL. Windows uses detached processes and
//! `taskkill` for compatibility. Android can additionally pass sockets to the
//! VPN service over a Unix domain socket with `SCM_RIGHTS`.
//!
//! This is the only module that uses `unsafe`: POSIX signal registration and
//! `sendmsg` for `SCM_RIGHTS` have no safe std/restricted-crate equivalent.

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

/// Install SIGINT/SIGTERM handlers (no-op off Unix) and return the shared flag.
pub fn install_signal_handlers() -> &'static AtomicI32 {
    #[cfg(unix)]
    {
        // SAFETY: `record_signal` only writes to an `AtomicI32`, which is
        // async-signal-safe, and the handler has no captured state.
        unsafe {
            libc::signal(libc::SIGINT, record_signal as *const () as usize);
            libc::signal(libc::SIGTERM, record_signal as *const () as usize);
        }
    }
    &STOP_SIGNAL
}

/// Whether a shutdown signal was observed.
pub fn shutdown_requested(flag: &AtomicI32) -> bool {
    flag.load(Ordering::SeqCst) != 0
}

/// Interface used by dialers to hand a freshly created socket to the platform
/// (for example an Android VPN service) before connecting.
pub trait SocketProtector: Send + Sync + std::fmt::Debug {
    /// Protect `fd`; returns whether a protector actually handled it.
    fn protect(&self, fd: i32, peer: Option<&std::net::SocketAddr>) -> io::Result<bool>;
}

/// Desktop/server/embedded no-op implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopProtector;

impl SocketProtector for NoopProtector {
    fn protect(&self, _fd: i32, _peer: Option<&std::net::SocketAddr>) -> io::Result<bool> {
        Ok(false)
    }
}

/// Pick the platform protector, honouring `SHADOWLEMON_PROTECT_PATH` on Android.
pub fn default_protector() -> std::sync::Arc<dyn SocketProtector> {
    #[cfg(all(unix, target_os = "android", feature = "android"))]
    {
        if let Some(path) = std::env::var_os("SHADOWLEMON_PROTECT_PATH") {
            return std::sync::Arc::new(UnixSocketProtector {
                path: PathBuf::from(path),
            });
        }
    }
    std::sync::Arc::new(NoopProtector)
}

/// Android protector using `SCM_RIGHTS` over `SHADOWLEMON_PROTECT_PATH`.
#[cfg(all(unix, target_os = "android", feature = "android"))]
#[derive(Debug)]
struct UnixSocketProtector {
    path: PathBuf,
}

#[cfg(all(unix, target_os = "android", feature = "android"))]
impl SocketProtector for UnixSocketProtector {
    fn protect(&self, fd: i32, _peer: Option<&std::net::SocketAddr>) -> io::Result<bool> {
        use std::{
            io::{Read, Write},
            mem,
            os::fd::AsRawFd,
            ptr,
        };
        let stream = std::os::unix::net::UnixStream::connect(&self.path)?;
        let byte = [1u8];
        let iov = libc::iovec {
            iov_base: byte.as_ptr() as *mut libc::c_void,
            iov_len: byte.len(),
        };
        let mut control =
            vec![0u8; unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as u32) as usize }];
        let mut message = libc::msghdr {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &iov as *const libc::iovec as *mut libc::iovec,
            msg_iovlen: 1,
            msg_control: control.as_mut_ptr() as *mut libc::c_void,
            msg_controllen: control.len(),
            msg_flags: 0,
        };
        // SAFETY: `message` points at live, correctly aligned buffers; the
        // control buffer is CMSG_SPACE bytes long, so the header and its data
        // slot are inside the allocation.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            if header.is_null() {
                return Err(io::Error::other("no SCM_RIGHTS control header"));
            }
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::c_int>() as u32) as _;
            ptr::copy_nonoverlapping(
                &fd as *const libc::c_int,
                libc::CMSG_DATA(header) as *mut libc::c_int,
                1,
            );
            if libc::sendmsg(stream.as_raw_fd(), &message, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let mut reply = [0u8; 1];
        let mut stream = stream;
        stream.write_all(&byte)?;
        let read = stream.read(&mut reply)?;
        Ok(read == 1 && reply[0] == 1)
    }
}

/// PID file path for a mode, mirroring the Go deployment contract.
pub fn pid_path(mode: Mode) -> Result<PathBuf, AppError> {
    Ok(match mode {
        Mode::Client => crate::config::state_dir()?.join("shadowlemon.pid"),
        Mode::Server => PathBuf::from("/var/run/shadowlemon/shadowlemon.pid"),
    })
}

fn process_identity() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(stat) = fs::read_to_string("/proc/self/stat") {
            // Field 22 (starttime) follows the parenthesised command name.
            if let Some(close) = stat.rfind(')') {
                let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
                if let Some(starttime) = fields.get(19) {
                    return (*starttime).to_owned();
                }
            }
        }
    }
    String::new()
}

fn identity_of(pid: i32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let close = stat.rfind(')')?;
        let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
        fields.get(19).map(|value| (*value).to_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

fn process_alive(pid: i32) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: `kill` with signal 0 only checks permissions/liveness.
        unsafe { libc::kill(pid, 0) == 0 || *libc::__errno_location() == libc::EPERM }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

fn send_signal(pid: i32, signal: i32) -> io::Result<()> {
    #[cfg(unix)]
    {
        // SAFETY: `signal` is a plain number; no memory is passed.
        let result = unsafe { libc::kill(pid, signal) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let code = if signal == 9 { "/F" } else { "" };
        Command::new("taskkill")
            .args([code, "/PID", &pid.to_string()])
            .status()?;
        Ok(())
    }
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
    #[cfg(target_os = "linux")]
    {
        if identity.is_empty() {
            return true;
        }
        identity_of(pid).as_deref() == Some(identity)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, identity);
        true
    }
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
    #[cfg(unix)]
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

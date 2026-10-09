use std::io::Write as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::process::CommandExt as _;

use anyhow::Context as _;

/// Inherited by the re-executed agent: the write end of the startup pipe.
const ACK_FD_ENV: &str = "BWU_AGENT_ACK_FD";
/// Exit code meaning "an agent is already running" (the CLI treats it as success).
const ALREADY_RUNNING: i32 = 23;

pub struct StartupAck {
    writer: std::os::unix::io::OwnedFd,
}

impl StartupAck {
    pub fn ack(self) -> anyhow::Result<()> {
        rustix::io::write(&self.writer, &[0])?;
        Ok(())
    }
}

/// Start the agent in the background.
///
/// The agent used to fork without exec (the `daemonize` crate) and then keep
/// running in the forked child. On macOS that is not fork-safe: the first
/// Security.framework call in the child (storing the master password in the
/// login keychain) crashed with SIGBUS inside os_log, so `unlock
/// --keychain-store` could never succeed. Now the parent re-executes the binary
/// with `--no-daemonize` in a new session and waits for its startup ack, so the
/// long-running agent is always a freshly exec'd process.
pub fn daemonize(no_daemonize: bool) -> anyhow::Result<Option<StartupAck>> {
    if no_daemonize {
        return foreground();
    }

    let stdout = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(rbw::dirs::agent_stdout_file())?;
    let stderr = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(rbw::dirs::agent_stderr_file())?;

    let (r, w) = rustix::pipe::pipe()?;
    // Only the write end crosses exec; the read end stays with this process.
    rustix::io::fcntl_setfd(&r, rustix::io::FdFlags::CLOEXEC)?;
    rustix::io::fcntl_setfd(&w, rustix::io::FdFlags::empty())?;

    let exe = std::env::current_exe()
        .context("failed to locate the agent binary")?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("--no-daemonize")
        .env(ACK_FD_ENV, w.as_raw_fd().to_string())
        .current_dir("/")
        .stdin(std::process::Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    // SAFETY: setsid is async-signal-safe; detaches the agent from the
    // caller's terminal so closing it does not take the agent down.
    unsafe {
        cmd.pre_exec(|| {
            rustix::process::setsid().map_err(std::io::Error::from)?;
            Ok(())
        });
    }
    let mut child = cmd.spawn().context("failed to start the agent")?;
    drop(w);

    let mut buf = [0; 1];
    match rustix::io::read(&r, &mut buf) {
        Ok(1) => std::process::exit(0),
        // EOF: the agent exited before acknowledging startup.
        _ => {
            let status =
                child.wait().context("failed to wait for the agent")?;
            std::process::exit(status.code().unwrap_or(1));
        }
    }
}

/// Run in the foreground: take the pid-file lock, and when started by
/// `daemonize` above, hand back the inherited startup pipe.
fn foreground() -> anyhow::Result<Option<StartupAck>> {
    let spawned = std::env::var(ACK_FD_ENV)
        .ok()
        .and_then(|v| v.parse::<i32>().ok());
    std::env::remove_var(ACK_FD_ENV);

    let mut pidfile = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o666)
        .open(rbw::dirs::pid_file())
        .context("failed to open pid file")?;
    if rustix::fs::flock(
        &pidfile,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .is_err()
    {
        if spawned.is_some() {
            // Another agent holds the lock: tell the waiting CLI it's fine.
            std::process::exit(ALREADY_RUNNING);
        }
        anyhow::bail!("failed to lock pid file: an agent is already running");
    }
    pidfile.set_len(0).context("failed to truncate pid file")?;
    writeln!(pidfile, "{}", std::process::id())
        .context("failed to write pid file")?;
    // don't close the pidfile until the process exits, to ensure it stays locked
    std::mem::forget(pidfile);

    Ok(spawned.map(|fd| StartupAck {
        // SAFETY: the fd was created for us by the parent and inherited across exec.
        writer: unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fd) },
    }))
}

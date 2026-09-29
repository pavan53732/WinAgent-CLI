use rmcp::transport::TokioChildProcess;
use std::io;
#[cfg(target_os = "linux")]
use std::sync::{mpsc, OnceLock};
use tokio::process::ChildStderr;
use tokio::process::Command;

#[cfg(windows)]
const CREATE_NO_WINDOW_FLAG: u32 = 0x08000000;

#[cfg(windows)]
pub struct Win32JobObject {
    handle: winapi::um::winnt::HANDLE,
}

#[cfg(windows)]
unsafe impl Send for Win32JobObject {}
#[cfg(windows)]
unsafe impl Sync for Win32JobObject {}

#[cfg(windows)]
impl Win32JobObject {
    pub fn new() -> io::Result<Self> {
        use std::ptr;
        use winapi::um::handleapi::INVALID_HANDLE_VALUE;
        use winapi::um::jobapi2::{CreateJobObjectW, SetInformationJobObject};
        use winapi::um::winnt::{
            JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        unsafe {
            let handle = CreateJobObjectW(ptr::null_mut(), ptr::null());
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }

            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            let res = SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &mut info as *mut _ as *mut _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );

            if res == 0 {
                let err = io::Error::last_os_error();
                winapi::um::handleapi::CloseHandle(handle);
                return Err(err);
            }

            Ok(Self { handle })
        }
    }

    /// Assign the current process to this Job Object.
    ///
    /// When the parent process is associated with the Job Object, Windows NT
    /// automatically and atomically associates all future child processes with
    /// the Job Object upon `CreateProcess` (unless explicitly broken away).
    pub fn assign_current_process(&self) -> io::Result<()> {
        use winapi::um::jobapi2::AssignProcessToJobObject;
        use winapi::um::processthreadsapi::GetCurrentProcess;

        unsafe {
            let proc_handle = GetCurrentProcess();
            let success = AssignProcessToJobObject(self.handle, proc_handle);
            if success == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    /// Verify the calling process is actually a member of this Job Object.
    ///
    /// `AssignProcessToJobObject` succeeding is not by itself proof of membership:
    /// the call can report success while the effective job hierarchy differs from
    /// the one requested, so the invariant is confirmed with `IsProcessInJob`.
    pub fn current_process_is_member(&self) -> io::Result<bool> {
        use winapi::um::processthreadsapi::GetCurrentProcess;

        #[link(name = "kernel32")]
        extern "system" {
            fn IsProcessInJob(
                process: *mut std::ffi::c_void,
                job: *mut std::ffi::c_void,
                is_member: *mut i32,
            ) -> i32;
        }

        unsafe {
            let mut is_member: i32 = 0;
            if IsProcessInJob(GetCurrentProcess(), self.handle, &mut is_member) == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(is_member != 0)
        }
    }

    pub fn assign_pid(&self, pid: u32) -> io::Result<()> {
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::jobapi2::AssignProcessToJobObject;
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::winnt::{PROCESS_SET_QUOTA, PROCESS_TERMINATE};

        unsafe {
            let proc_handle = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid);
            if proc_handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            let success = AssignProcessToJobObject(self.handle, proc_handle);
            CloseHandle(proc_handle);
            if success == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(windows)]
impl Drop for Win32JobObject {
    fn drop(&mut self) {
        use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
        unsafe {
            if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
                CloseHandle(self.handle);
            }
        }
    }
}

/// Runtime state of the Windows process-containment boundary.
///
/// Creating a Job Object and being *inside* it are separate facts. Only
/// [`ContainmentState::Active`] means child processes are guaranteed to be
/// terminated with the parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainmentState {
    Uninitialized,
    Active,
    Failed(String),
}

impl ContainmentState {
    pub fn is_active(&self) -> bool {
        matches!(self, ContainmentState::Active)
    }
}

#[cfg(windows)]
struct Containment {
    state: ContainmentState,
    job: Option<std::sync::Arc<Win32JobObject>>,
}

#[cfg(windows)]
static CONTAINMENT: std::sync::RwLock<Containment> = std::sync::RwLock::new(Containment {
    state: ContainmentState::Uninitialized,
    job: None,
});

fn lock_error(e: std::sync::PoisonError<impl Sized>) -> io::Error {
    io::Error::other(e.to_string())
}

/// Establish the process-containment boundary: create the Job Object, attach the
/// current process to it, and confirm membership.
///
/// This must be called at startup, before any child is spawned. Once the parent
/// is a member, every `CreateProcess` descendant inherits the Job Object at
/// creation time, so containment no longer depends on a post-spawn PID race.
///
/// A failure is terminal for the attempt: the state becomes
/// [`ContainmentState::Failed`] and the error is returned. Callers must not
/// continue as though containment were active.
#[cfg(windows)]
pub fn initialize_windows_process_containment() -> io::Result<std::sync::Arc<Win32JobObject>> {
    {
        let current = CONTAINMENT.read().map_err(lock_error)?;
        match &current.state {
            ContainmentState::Active => {
                if let Some(job) = current.job.as_ref() {
                    return Ok(job.clone());
                }
            }
            ContainmentState::Failed(reason) => {
                return Err(io::Error::other(format!(
                    "Windows process containment is unavailable: {reason}"
                )))
            }
            ContainmentState::Uninitialized => {}
        }
    }

    let outcome = (|| -> io::Result<std::sync::Arc<Win32JobObject>> {
        let job = std::sync::Arc::new(Win32JobObject::new()?);
        job.assign_current_process().map_err(|e| {
            io::Error::other(format!(
                "could not attach the current process to the Job Object: {e}"
            ))
        })?;
        if !job.current_process_is_member()? {
            return Err(io::Error::other(
                "IsProcessInJob reported the current process is not a member of the Job Object",
            ));
        }
        Ok(job)
    })();

    let mut current = CONTAINMENT.write().map_err(lock_error)?;
    match outcome {
        Ok(job) => {
            tracing::info!(
                "Windows process containment active: the current process is a member of a \
                 kill-on-close Job Object, so child processes inherit containment at creation"
            );
            current.state = ContainmentState::Active;
            current.job = Some(job.clone());
            Ok(job)
        }
        Err(e) => {
            tracing::error!("Windows process containment could not be established: {e}");
            current.state = ContainmentState::Failed(e.to_string());
            current.job = None;
            Err(e)
        }
    }
}

/// Return the active Job Object, or the reason containment is unavailable.
///
/// Unlike [`initialize_windows_process_containment`] this never retries: the
/// per-spawn path must not turn every tool call into a Job Object creation
/// attempt, and must fail closed once containment is known to be broken.
#[cfg(windows)]
pub fn get_or_init_global_job() -> io::Result<std::sync::Arc<Win32JobObject>> {
    let current = CONTAINMENT.read().map_err(lock_error)?;
    match (&current.state, &current.job) {
        (ContainmentState::Active, Some(job)) => Ok(job.clone()),
        (ContainmentState::Failed(reason), _) => Err(io::Error::other(format!(
            "Windows process containment is unavailable: {reason}"
        ))),
        _ => Err(io::Error::other(
            "Windows process containment was never initialized; call \
             initialize_windows_process_containment() during startup",
        )),
    }
}

#[cfg(windows)]
pub fn assign_to_global_job(pid: u32) -> io::Result<()> {
    get_or_init_global_job()?.assign_pid(pid)
}

#[cfg(windows)]
pub fn containment_state() -> ContainmentState {
    match CONTAINMENT.read() {
        Ok(current) => current.state.clone(),
        Err(_) => ContainmentState::Failed("containment state lock was poisoned".to_string()),
    }
}

/// Non-Windows platforms have no Job Object boundary; descendant cleanup is
/// handled by process groups and `PR_SET_PDEATHSIG` in `configure_subprocess`.
#[cfg(not(windows))]
pub fn initialize_windows_process_containment() -> io::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn get_or_init_global_job() -> io::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn assign_to_global_job(_pid: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn containment_state() -> ContainmentState {
    ContainmentState::Active
}

/// Decide whether a state permits child process execution.
///
/// `Active` always permits. `Failed` never does: the Job Object could not be
/// established, so descendants would not be contained and the boundary the rest
/// of the system believes in does not exist. `Uninitialized` permits, because
/// the WinAgent CLI establishes containment during startup before anything can
/// spawn, so this state only occurs in an embedder that never configured it.
pub fn containment_permits_execution(state: &ContainmentState) -> Result<(), String> {
    match state {
        ContainmentState::Active => Ok(()),
        ContainmentState::Uninitialized => Ok(()),
        ContainmentState::Failed(reason) => Err(format!(
            "Windows process containment is unavailable: {reason}"
        )),
    }
}

/// Gate for execution paths that require an established containment boundary.
pub fn require_active_containment() -> anyhow::Result<()> {
    containment_permits_execution(&containment_state()).map_err(anyhow::Error::msg)
}

#[cfg(target_os = "linux")]
fn configure_parent_death_signal(command: &mut Command) {
    let parent_pid = unsafe { libc::getpid() };

    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            if libc::getppid() != parent_pid {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }

            Ok(())
        });
    }
}

pub trait SubprocessExt {
    fn set_no_window(&mut self) -> &mut Self;
}

/// Creates a Git command that rejects implicit bare repositories and cannot run a
/// repository-configured fsmonitor hook.
pub fn git_command() -> std::process::Command {
    let mut command = std::process::Command::new("git");
    command.args([
        "-c",
        "safe.bareRepository=explicit",
        "-c",
        "core.fsmonitor=false",
    ]);
    command
}

impl SubprocessExt for Command {
    fn set_no_window(&mut self) -> &mut Self {
        #[cfg(windows)]
        {
            self.creation_flags(CREATE_NO_WINDOW_FLAG);
        }
        self
    }
}

impl SubprocessExt for std::process::Command {
    fn set_no_window(&mut self) -> &mut Self {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            self.creation_flags(CREATE_NO_WINDOW_FLAG);
        }
        self
    }
}

fn configure_common_subprocess(command: &mut Command) {
    // Isolate subprocess into its own process group so it does not receive
    // SIGINT when the user presses Ctrl+C in the terminal.
    #[cfg(unix)]
    command.process_group(0);
    command.set_no_window();
}

#[allow(unused_variables)]
pub fn configure_subprocess(command: &mut Command) {
    configure_common_subprocess(command);
    #[cfg(target_os = "linux")]
    configure_parent_death_signal(command);
}

#[cfg(target_os = "linux")]
struct LongLivedSpawnRequest {
    command: Command,
    runtime: tokio::runtime::Handle,
    response: tokio::sync::oneshot::Sender<io::Result<(TokioChildProcess, Option<ChildStderr>)>>,
}

#[cfg(target_os = "linux")]
fn long_lived_spawn_sender() -> io::Result<mpsc::Sender<LongLivedSpawnRequest>> {
    static SENDER: OnceLock<io::Result<mpsc::Sender<LongLivedSpawnRequest>>> = OnceLock::new();

    match SENDER.get_or_init(|| {
        let (sender, receiver) = mpsc::channel::<LongLivedSpawnRequest>();
        std::thread::Builder::new()
            .name("goose-extension-spawner".to_owned())
            .spawn(move || {
                while let Ok(mut request) = receiver.recv() {
                    let _runtime_guard = request.runtime.enter();
                    configure_subprocess(&mut request.command);
                    let result = TokioChildProcess::builder(request.command)
                        .stderr(std::process::Stdio::piped())
                        .spawn();
                    let _ = request.response.send(result);
                }
            })
            .map(|_| sender)
    }) {
        Ok(sender) => Ok(sender.clone()),
        Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
    }
}

/// Spawn a long-lived MCP subprocess without tying Linux parent-death cleanup
/// to the Tokio worker that happened to request it.
pub async fn spawn_long_lived_mcp_subprocess(
    command: Command,
) -> io::Result<(TokioChildProcess, Option<ChildStderr>)> {
    #[cfg(target_os = "linux")]
    {
        let runtime = tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        long_lived_spawn_sender()?
            .send(LongLivedSpawnRequest {
                command,
                runtime,
                response: response_tx,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "extension spawner exited"))?;
        response_rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "extension spawner exited"))?
    }

    #[cfg(not(target_os = "linux"))]
    {
        let mut command = command;
        configure_subprocess(&mut command);
        let result = TokioChildProcess::builder(command)
            .stderr(std::process::Stdio::piped())
            .spawn();

        #[cfg(windows)]
        if let Ok((ref child, _)) = result {
            if let Some(pid) = child.id() {
                if let Err(e) = assign_to_global_job(pid) {
                    tracing::warn!(
                        "Failed to assign MCP subprocess {} to Win32 Job Object: {}",
                        pid,
                        e
                    );
                }
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_containment_permits_execution() {
        assert!(containment_permits_execution(&ContainmentState::Active).is_ok());
    }

    #[test]
    fn failed_containment_blocks_execution() {
        let error = containment_permits_execution(&ContainmentState::Failed(
            "IsProcessInJob reported the current process is not a member".to_string(),
        ))
        .unwrap_err();
        assert!(error.contains("not a member"));
    }

    #[test]
    fn uninitialized_containment_permits_execution() {
        assert!(containment_permits_execution(&ContainmentState::Uninitialized).is_ok());
    }

    // Membership is deliberately not verified in-process: the Job Object is
    // created with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, so dropping a test-owned
    // instance would terminate the test binary itself.
}

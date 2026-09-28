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

#[cfg(windows)]
static GLOBAL_JOB: std::sync::RwLock<Option<std::sync::Arc<Win32JobObject>>> =
    std::sync::RwLock::new(None);

#[cfg(windows)]
pub fn get_or_init_global_job() -> io::Result<std::sync::Arc<Win32JobObject>> {
    {
        let r = GLOBAL_JOB
            .read()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        if let Some(ref job) = *r {
            return Ok(job.clone());
        }
    }
    let mut w = GLOBAL_JOB
        .write()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    if let Some(ref job) = *w {
        return Ok(job.clone());
    }
    let job = std::sync::Arc::new(Win32JobObject::new()?);
    // Assign current process so all descendant processes created by WinAgent
    // automatically inherit the Job Object at spawn time without race condition.
    if let Err(e) = job.assign_current_process() {
        tracing::debug!(
            "Parent WinAgent process not assigned to Win32 Job Object (already constrained or in container): {}",
            e
        );
    } else {
        tracing::debug!(
            "Assigned parent WinAgent process to Win32 Job Object (all child processes inherit containment)"
        );
    }
    *w = Some(job.clone());
    Ok(job)
}

#[cfg(windows)]
pub fn assign_to_global_job(pid: u32) -> io::Result<()> {
    let job = get_or_init_global_job()?;
    job.assign_pid(pid)
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

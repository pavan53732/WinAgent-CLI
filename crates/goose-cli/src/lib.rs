#![recursion_limit = "256"]

#[cfg(not(any(feature = "rustls-tls", feature = "native-tls")))]
compile_error!("At least one of `rustls-tls` or `native-tls` features must be enabled");

#[cfg(all(feature = "rustls-tls", feature = "native-tls"))]
compile_error!("Features `rustls-tls` and `native-tls` are mutually exclusive");

pub mod cli;
pub mod commands;
pub mod logging;
pub mod recipes;
pub mod scenario_tests;
pub mod session;
pub mod signal;

// Re-export commonly used types
pub use cli::Cli;
pub use session::CliSession;

/// Enable ANSI/VT escape sequence processing and UTF-8 encoding on Windows Console Host.
///
/// Sets console code pages to CP_UTF8 (65001) and applies ENABLE_VIRTUAL_TERMINAL_PROCESSING
/// (0x0004) to stdout and stderr handles via SetConsoleMode.
/// Returns (stdout_vt_enabled, stderr_vt_enabled).
#[cfg(windows)]
pub fn enable_windows_vt_processing() -> (bool, bool) {
    let _ = console::Term::stdout().features().colors_supported();
    let _ = console::Term::stderr().features().colors_supported();

    unsafe {
        #[link(name = "kernel32")]
        extern "system" {
            fn SetConsoleOutputCP(wCodePageID: u32) -> i32;
            fn SetConsoleCP(wCodePageID: u32) -> i32;
            fn GetStdHandle(nStdHandle: u32) -> *mut std::ffi::c_void;
            fn GetConsoleMode(hConsoleHandle: *mut std::ffi::c_void, lpMode: *mut u32) -> i32;
            fn SetConsoleMode(hConsoleHandle: *mut std::ffi::c_void, dwMode: u32) -> i32;
        }

        let _ = SetConsoleOutputCP(65001);
        let _ = SetConsoleCP(65001);

        const STD_OUTPUT_HANDLE: u32 = (-11i32) as u32; // 0xFFFFFFF5
        const STD_ERROR_HANDLE: u32 = (-12i32) as u32; // 0xFFFFFFF4
        const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

        let enable_vt = |handle_id: u32| -> bool {
            let handle = GetStdHandle(handle_id);
            if handle.is_null() || handle == (-1isize as *mut std::ffi::c_void) {
                return false;
            }
            let mut mode: u32 = 0;
            if GetConsoleMode(handle, &mut mode) == 0 {
                return false;
            }
            if (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0 {
                return true;
            }
            SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
        };

        let stdout_vt = enable_vt(STD_OUTPUT_HANDLE);
        let stderr_vt = enable_vt(STD_ERROR_HANDLE);
        (stdout_vt, stderr_vt)
    }
}

async fn run() -> anyhow::Result<()> {
    if let Err(e) = logging::setup_logging(None) {
        eprintln!("Warning: Failed to initialize logging: {}", e);
    }

    let result = cli::cli().await;

    #[cfg(feature = "otel")]
    if goose::otel::otlp::is_otlp_initialized() {
        goose::otel::otlp::shutdown_otlp();
    }

    result
}

pub fn run_main() -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        enable_windows_vt_processing();
        // Establish the process-containment boundary before any child is
        // spawned. Once the current process is a member of the kill-on-close
        // Job Object, descendants inherit containment at creation time.
        if let Err(e) = goose::subprocess::initialize_windows_process_containment() {
            eprintln!(
                "Warning: Windows process containment is unavailable: {e}\n\
                 Shell execution will be refused for this process."
            );
        }
    }

    let handle = std::thread::Builder::new()
        .name("winagent-cli-main".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to build Tokio runtime");
            runtime.block_on(run())
        })
        .map_err(|e| anyhow::anyhow!("Failed to spawn winagent-cli main thread: {}", e))?;

    handle
        .join()
        .map_err(|_| anyhow::anyhow!("winagent-cli main thread panicked"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn test_windows_vt_and_codepage_initialization() {
        let (stdout_vt, stderr_vt) = enable_windows_vt_processing();
        // Verifies the Win32 API calls execute without panicking.
        // In interactive terminals, stdout_vt will be true; in non-interactive CI pipes it safely returns false.
        let _ = (stdout_vt, stderr_vt);
    }
}

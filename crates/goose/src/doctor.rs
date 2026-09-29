use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

use crate::agents::platform_extensions::developer;
use crate::agents::ExtensionConfig;
use crate::config::Config;
use crate::conversation::message::Message;
use crate::providers;
use crate::providers::base::Provider;
use crate::session::{
    config_path, latest_llm_log_path, read_capped, read_tail, recent_cli_log_paths, SystemInfo,
};
use goose_providers::errors::ProviderError;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiagnosticStatus {
    Pass,
    Warning,
    Fail,
    OptionalMissing,
}

impl DiagnosticStatus {
    pub fn badge(&self) -> &'static str {
        match self {
            DiagnosticStatus::Pass => "[PASS]",
            DiagnosticStatus::Warning => "[WARN]",
            DiagnosticStatus::Fail => "[FAIL]",
            DiagnosticStatus::OptionalMissing => "[OPTIONAL]",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticCheck {
    pub name: String,
    pub category: String,
    pub status: DiagnosticStatus,
    pub version: Option<String>,
    pub path: Option<String>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub os_name: String,
    pub architecture: String,
    pub checks: Vec<DiagnosticCheck>,
}

impl DiagnosticReport {
    pub async fn gather() -> Self {
        Self::collect_deterministic().await
    }

    pub async fn collect_deterministic() -> Self {
        let os_name = std::env::consts::OS.to_string();
        let architecture = std::env::consts::ARCH.to_string();
        let mut checks = Vec::new();

        // 1. PowerShell Check
        checks.push(check_powershell().await);

        // 2. Git Check
        checks.push(check_git().await);

        // 3. .NET SDK & MSBuild
        checks.push(check_dotnet_msbuild().await);

        // 4. Rust Toolchain
        checks.push(check_rust().await);

        // 5. Node.js & Package Managers
        checks.push(check_node().await);

        // 6. Python
        checks.push(check_python().await);

        // 7. Android SDK & ADB
        checks.push(check_android_adb().await);

        // 8. Ollama Local Model Server
        checks.push(check_ollama().await);

        // 9. Windows Kernel & Subsystem
        #[cfg(windows)]
        checks.push(check_windows_subsystem());

        Self {
            os_name,
            architecture,
            checks,
        }
    }

    pub fn format_cli(&self) -> String {
        let mut out = String::new();
        out.push_str("\n=== WinAgent Deterministic System Audit ===\n");
        out.push_str(&format!("OS: {} ({})\n\n", self.os_name, self.architecture));
        out.push_str(&format!(
            "{:<14} {:<20} {:<12} {}\n",
            "Category", "Component", "Status", "Details"
        ));
        out.push_str(&format!("{}\n", "─".repeat(80)));
        for c in &self.checks {
            out.push_str(&format!(
                "{:<14} {:<20} {:<12} {}\n",
                c.category,
                c.name,
                c.status.badge(),
                c.details
            ));
        }
        out.push('\n');
        out
    }

    pub fn print_cli(&self) {
        println!("{}", self.format_cli());
    }

    pub fn format_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("### WinAgent Deterministic Environment Audit\n\n");
        out.push_str(&format!(
            "**OS:** {} ({})\n\n",
            self.os_name, self.architecture
        ));
        out.push_str("| Category | Component | Status | Version | Path / Details |\n");
        out.push_str("|---|---|---|---|---|\n");
        for c in &self.checks {
            let ver = c.version.as_deref().unwrap_or("-");
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                c.category,
                c.name,
                c.status.badge(),
                ver,
                c.details.replace('|', "/")
            ));
        }
        out
    }
}

async fn probe_command(program: &str, args: &[&str]) -> Option<String> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    #[cfg(windows)]
    {
        use crate::subprocess::SubprocessExt;
        cmd.set_no_window();
    }
    let child = cmd.spawn().ok()?;
    let output = tokio::time::timeout(Duration::from_secs(3), child.wait_with_output())
        .await
        .ok()?
        .ok()?;
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !stdout.is_empty() {
            return Some(stdout);
        }
    }
    None
}

async fn check_powershell() -> DiagnosticCheck {
    if let Ok(path) = which::which("pwsh") {
        let ver = probe_command(
            "pwsh",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$PSVersionTable.PSVersion.ToString()",
            ],
        )
        .await
        .unwrap_or_else(|| "7+".to_string());
        DiagnosticCheck {
            name: "PowerShell".to_string(),
            category: "Shell".to_string(),
            status: DiagnosticStatus::Pass,
            version: Some(ver.clone()),
            path: Some(path.display().to_string()),
            details: format!("PowerShell Core {} at {}", ver, path.display()),
        }
    } else if let Ok(path) = which::which("powershell") {
        let ver = probe_command(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$PSVersionTable.PSVersion.ToString()",
            ],
        )
        .await
        .unwrap_or_else(|| "5.1".to_string());
        DiagnosticCheck {
            name: "PowerShell".to_string(),
            category: "Shell".to_string(),
            status: DiagnosticStatus::Pass,
            version: Some(ver),
            path: Some(path.display().to_string()),
            details: format!(
                "Windows PowerShell 5.1 (Recommended: winget install Microsoft.PowerShell) at {}",
                path.display()
            ),
        }
    } else {
        DiagnosticCheck {
            name: "PowerShell".to_string(),
            category: "Shell".to_string(),
            status: DiagnosticStatus::Fail,
            version: None,
            path: None,
            details: "Neither pwsh nor powershell found on PATH".to_string(),
        }
    }
}

async fn check_git() -> DiagnosticCheck {
    if let Ok(path) = which::which("git") {
        let ver = probe_command("git", &["--version"])
            .await
            .unwrap_or_else(|| "installed".to_string());
        DiagnosticCheck {
            name: "Git".to_string(),
            category: "VCS".to_string(),
            status: DiagnosticStatus::Pass,
            version: Some(ver.clone()),
            path: Some(path.display().to_string()),
            details: format!("{} at {}", ver, path.display()),
        }
    } else {
        DiagnosticCheck {
            name: "Git".to_string(),
            category: "VCS".to_string(),
            status: DiagnosticStatus::Fail,
            version: None,
            path: None,
            details: "Git is not installed or not in PATH".to_string(),
        }
    }
}

async fn check_dotnet_msbuild() -> DiagnosticCheck {
    let Ok(path) = which::which("dotnet") else {
        return DiagnosticCheck {
            name: ".NET / MSBuild".to_string(),
            category: "Build System".to_string(),
            status: DiagnosticStatus::OptionalMissing,
            version: None,
            path: None,
            details: "Not installed (Optional: winget install Microsoft.DotNet.SDK.9)".to_string(),
        };
    };

    // Discovery and functionality are separate facts: a `dotnet` on PATH that
    // cannot report an SDK version, or cannot drive MSBuild, is not a working
    // .NET environment.
    let sdk_version = probe_command("dotnet", &["--version"]).await;
    let msbuild = probe_command("dotnet", &["msbuild", "-version"]).await;

    let (status, details) = match (&sdk_version, &msbuild) {
        (Some(sdk), Some(msbuild)) => {
            let msbuild_line = msbuild.lines().next().unwrap_or("").trim();
            (
                DiagnosticStatus::Pass,
                format!("SDK discovered and MSBuild functional (SDK {sdk}, {msbuild_line})"),
            )
        }
        (Some(sdk), None) => (
            DiagnosticStatus::Warning,
            format!("SDK {sdk} discovered, but MSBuild did not respond"),
        ),
        (None, Some(_)) => (
            DiagnosticStatus::Warning,
            "MSBuild responded, but no .NET SDK version was reported".to_string(),
        ),
        (None, None) => (
            DiagnosticStatus::Warning,
            "dotnet is on PATH but reported neither an SDK version nor an MSBuild version"
                .to_string(),
        ),
    };

    DiagnosticCheck {
        name: ".NET / MSBuild".to_string(),
        category: "Build System".to_string(),
        status,
        version: sdk_version,
        path: Some(path.display().to_string()),
        details,
    }
}

async fn check_rust() -> DiagnosticCheck {
    if let Ok(path) = which::which("rustc") {
        let ver = probe_command("rustc", &["--version"])
            .await
            .unwrap_or_else(|| "installed".to_string());
        DiagnosticCheck {
            name: "Rust / Cargo".to_string(),
            category: "Build System".to_string(),
            status: DiagnosticStatus::Pass,
            version: Some(ver.clone()),
            path: Some(path.display().to_string()),
            details: format!("{} at {}", ver, path.display()),
        }
    } else {
        DiagnosticCheck {
            name: "Rust / Cargo".to_string(),
            category: "Build System".to_string(),
            status: DiagnosticStatus::OptionalMissing,
            version: None,
            path: None,
            details: "Not installed (Optional for Rust builds)".to_string(),
        }
    }
}

async fn check_node() -> DiagnosticCheck {
    if let Ok(path) = which::which("node") {
        let ver = probe_command("node", &["--version"])
            .await
            .unwrap_or_else(|| "installed".to_string());
        let mut pms = Vec::new();
        if which::which("pnpm").is_ok() {
            pms.push("pnpm");
        }
        if which::which("npm").is_ok() {
            pms.push("npm");
        }
        if which::which("yarn").is_ok() {
            pms.push("yarn");
        }
        if which::which("bun").is_ok() {
            pms.push("bun");
        }

        let details = if pms.is_empty() {
            format!("Node {} at {}", ver, path.display())
        } else {
            format!("Node {} ({}) at {}", ver, pms.join(", "), path.display())
        };

        DiagnosticCheck {
            name: "Node.js".to_string(),
            category: "Runtime".to_string(),
            status: DiagnosticStatus::Pass,
            version: Some(ver),
            path: Some(path.display().to_string()),
            details,
        }
    } else {
        DiagnosticCheck {
            name: "Node.js".to_string(),
            category: "Runtime".to_string(),
            status: DiagnosticStatus::OptionalMissing,
            version: None,
            path: None,
            details: "Not installed (Optional: winget install OpenJS.NodeJS)".to_string(),
        }
    }
}

async fn check_python() -> DiagnosticCheck {
    let py = which::which("python").or_else(|_| which::which("py"));
    if let Ok(path) = py {
        let ver = probe_command(path.to_str().unwrap_or("python"), &["--version"])
            .await
            .unwrap_or_else(|| "installed".to_string());
        DiagnosticCheck {
            name: "Python".to_string(),
            category: "Runtime".to_string(),
            status: DiagnosticStatus::Pass,
            version: Some(ver.clone()),
            path: Some(path.display().to_string()),
            details: format!("{} at {}", ver, path.display()),
        }
    } else {
        DiagnosticCheck {
            name: "Python".to_string(),
            category: "Runtime".to_string(),
            status: DiagnosticStatus::OptionalMissing,
            version: None,
            path: None,
            details: "Not installed (Optional for Python workflows)".to_string(),
        }
    }
}

async fn check_android_adb() -> DiagnosticCheck {
    let android_home = std::env::var("ANDROID_HOME")
        .or_else(|_| std::env::var("ANDROID_SDK_ROOT"))
        .ok();
    if let Ok(path) = which::which("adb") {
        let ver = probe_command("adb", &["version"]).await;
        let ver_str = ver
            .as_deref()
            .and_then(|v| v.lines().next())
            .unwrap_or("installed");
        let details = if let Some(home) = android_home {
            format!("{} (ANDROID_HOME: {})", ver_str, home)
        } else {
            format!("{} at {}", ver_str, path.display())
        };
        DiagnosticCheck {
            name: "Android SDK / ADB".to_string(),
            category: "SDK".to_string(),
            status: DiagnosticStatus::Pass,
            version: Some(ver_str.to_string()),
            path: Some(path.display().to_string()),
            details,
        }
    } else if let Some(home) = android_home {
        DiagnosticCheck {
            name: "Android SDK / ADB".to_string(),
            category: "SDK".to_string(),
            status: DiagnosticStatus::Warning,
            version: None,
            path: Some(home.clone()),
            details: format!("ANDROID_HOME set to {} but adb not found in PATH", home),
        }
    } else {
        DiagnosticCheck {
            name: "Android SDK / ADB".to_string(),
            category: "SDK".to_string(),
            status: DiagnosticStatus::OptionalMissing,
            version: None,
            path: None,
            details: "Not installed or ANDROID_HOME not configured".to_string(),
        }
    }
}

async fn check_ollama() -> DiagnosticCheck {
    // An open TCP port only proves something is listening. Ask the API whether
    // the service is actually usable, and report model availability separately.
    let api = tokio::time::timeout(
        Duration::from_millis(1500),
        reqwest::Client::new()
            .get("http://127.0.0.1:11434/api/tags")
            .send(),
    )
    .await;

    let installed = which::which("ollama").ok();

    let (status, details) = match api {
        Ok(Ok(response)) if response.status().is_success() => {
            let models = response
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|value| {
                    value
                        .get("models")
                        .and_then(|models| models.as_array())
                        .map(|models| models.len())
                })
                .unwrap_or(0);
            (
                DiagnosticStatus::Pass,
                format!("API reachable at http://127.0.0.1:11434, {models} model(s) pulled"),
            )
        }
        Ok(Ok(response)) => (
            DiagnosticStatus::Warning,
            format!(
                "Endpoint answered with HTTP {}; the Ollama API is not serving",
                response.status()
            ),
        ),
        Ok(Err(e)) => (
            DiagnosticStatus::Warning,
            format!("TCP port is open but the HTTP API is not usable: {e}"),
        ),
        Err(_) => match &installed {
            Some(_) => (
                DiagnosticStatus::OptionalMissing,
                "CLI installed but the server did not respond. Run 'ollama serve' to activate"
                    .to_string(),
            ),
            None => (
                DiagnosticStatus::OptionalMissing,
                "Not installed (Optional for local open-weights model inference)".to_string(),
            ),
        },
    };

    DiagnosticCheck {
        name: "Ollama (Local AI)".to_string(),
        category: "AI Runtime".to_string(),
        status,
        version: None,
        path: installed.map(|path| path.display().to_string()),
        details,
    }
}

#[cfg(windows)]
fn check_windows_subsystem() -> DiagnosticCheck {
    // Creating a Job Object, attaching the current process to it, and verifying
    // that membership are three separate facts. Only the last one means child
    // processes are actually contained.
    let (status, details) = match crate::subprocess::containment_state() {
        crate::subprocess::ContainmentState::Active => (
            DiagnosticStatus::Pass,
            "Job Object created, the current process was assigned, and IsProcessInJob confirmed \
             membership: child processes are contained from creation"
                .to_string(),
        ),
        crate::subprocess::ContainmentState::Uninitialized => (
            DiagnosticStatus::Warning,
            "Process containment has not been initialized; child processes are not contained"
                .to_string(),
        ),
        crate::subprocess::ContainmentState::Failed(reason) => (
            DiagnosticStatus::Fail,
            format!(
                "Process containment is NOT active: {reason}. Shell execution is refused while \
                 containment is unavailable"
            ),
        ),
    };

    DiagnosticCheck {
        name: "Win32 Containment".to_string(),
        category: "Kernel".to_string(),
        status,
        version: None,
        path: None,
        details,
    }
}

pub(crate) const DEVELOPER_EXTENSION_REQUIRED_MESSAGE: &str = "**WinAgent Doctor**\n\n\
`/doctor` requires the Developer extension, but it is disabled for this session.\n\n\
Enable it for this session and run `/doctor` again:\n\
- CLI: `/builtin developer`\n\
- Desktop: select **Developer** in the session extension selector.";

pub async fn run(agent: &crate::agents::Agent, session_id: &str) -> anyhow::Result<Message> {
    if let Some(message) = require_developer_extension(agent).await {
        return Ok(message);
    }

    if let Some(msg) = ensure_working_provider(agent, session_id).await? {
        return Ok(msg);
    }

    let info = SystemInfo::collect();
    let extensions = agent.list_extensions().await;

    let mut prompt = format!(
        "I ran /doctor because something seems off. Here's my system info:\n\n\
         {}\n\
         Loaded extensions: {}\n\
         Config file: {}\n",
        info.to_text(),
        if extensions.is_empty() {
            "none".to_string()
        } else {
            extensions.join(", ")
        },
        config_path().display(),
    );

    if let Some(path) = recent_cli_log_paths().into_iter().next() {
        if let Some(tail) = read_tail(&path, 50) {
            prompt.push_str(&format!("\nRecent CLI log:\n```\n{}\n```\n", tail));
        }
    }

    if let Some(path) = latest_llm_log_path() {
        if let Some(content) = read_capped(&path, 10_000) {
            prompt.push_str(&format!("\nLast LLM request log:\n```\n{}\n```\n", content));
        }
    }

    let report = DiagnosticReport::collect_deterministic().await;
    prompt.push_str("\n\n");
    prompt.push_str(&report.format_markdown());
    prompt.push_str(
        "\n\nReview the deterministic environment audit above. If any required toolchains have FAIL or unexpected WARNING status, \
         explain the concrete cause and provide precise Windows remediation commands (e.g. winget install, PATH adjustments, or environment settings)."
    );

    Ok(Message::user().with_text(prompt))
}

async fn require_developer_extension(agent: &crate::agents::Agent) -> Option<Message> {
    let has_developer = agent
        .extension_manager
        .get_extension_configs()
        .await
        .iter()
        .any(is_developer_platform_config);

    (!has_developer).then(|| Message::assistant().with_text(DEVELOPER_EXTENSION_REQUIRED_MESSAGE))
}

fn is_developer_platform_config(config: &ExtensionConfig) -> bool {
    matches!(
        config,
        ExtensionConfig::Builtin { .. } | ExtensionConfig::Platform { .. }
    ) && config.key() == developer::EXTENSION_NAME
}

async fn ensure_working_provider(
    agent: &crate::agents::Agent,
    session_id: &str,
) -> anyhow::Result<Option<Message>> {
    let config = Config::global();
    let mut log: Vec<String> = Vec::new();

    let provider_name = config.get_goose_provider().ok();
    let model_name = config.get_goose_model().ok();

    if let (Some(ref pname), Some(ref mname)) = (&provider_name, &model_name) {
        log.push(format!("Checking {} / {} ...", pname, mname));
        match try_create_and_test(pname, mname).await {
            Ok(_) => {
                return Ok(None);
            }
            Err(e) => {
                log.push(format!("❌ {} / {}: {}", pname, mname, describe_error(&e)));
            }
        }

        log.push(format!("Looking for alternative models on {} ...", pname));
        if let Some((working, model_config)) = try_other_models(pname, mname, &mut log).await {
            let new_model = model_config.model_name.clone();
            save_and_set(agent, session_id, working, model_config).await?;
            let preamble = log.join("\n");
            return Ok(Some(Message::assistant().with_text(format!(
                "**Goose Doctor**\n\n{}\n\n\
                 Your configured model wasn't working, so I switched to \
                 **{} / {}**. You can continue chatting now.",
                preamble, pname, new_model,
            ))));
        }
    } else {
        log.push("No provider/model configured.".to_string());
    }

    log.push("Looking for other configured providers ...".to_string());
    let skip = provider_name.as_deref().unwrap_or("");
    if let Some((working, model_config)) = try_other_providers(skip, &mut log).await {
        let name = working.get_name().to_string();
        let model = model_config.model_name.clone();
        save_and_set(agent, session_id, working, model_config).await?;
        let preamble = log.join("\n");
        return Ok(Some(Message::assistant().with_text(format!(
            "**Goose Doctor**\n\n{}\n\n\
             Switched to **{} / {}**. You can continue chatting now.",
            preamble, name, model,
        ))));
    }

    let preamble = log.join("\n");
    Ok(Some(Message::assistant().with_text(format!(
        "**Goose Doctor**\n\n{}\n\n\
         No working provider found. Run `goose configure` to set one up.",
        preamble,
    ))))
}

async fn save_and_set(
    agent: &crate::agents::Agent,
    session_id: &str,
    provider: Arc<dyn Provider>,
    model_config: goose_providers::model::ModelConfig,
) -> anyhow::Result<()> {
    let config = Config::global();
    crate::config::set_active_provider(config, provider.get_name(), &model_config.model_name)?;
    agent
        .update_provider(provider, model_config, session_id)
        .await
}

async fn test_provider(
    provider: &dyn Provider,
    model_config: &goose_providers::model::ModelConfig,
) -> Result<(), ProviderError> {
    let messages = vec![Message::user().with_text("Say 'hello' and nothing else.")];
    crate::session_context::with_session_id(
        Some("doctor-check".to_string()),
        provider.complete(
            model_config,
            "Respond as briefly as possible.",
            &messages,
            &[],
        ),
    )
    .await?;
    Ok(())
}

async fn try_create_and_test(
    provider_name: &str,
    model_name: &str,
) -> Result<(Arc<dyn Provider>, goose_providers::model::ModelConfig), ProviderError> {
    let model_config =
        crate::model_config::model_config_from_user_config(provider_name, model_name)
            .map_err(|e| ProviderError::ExecutionError(e.to_string()))?;

    let provider = providers::create(provider_name, vec![])
        .await
        .map_err(|e| ProviderError::ExecutionError(e.to_string()))?;

    test_provider(provider.as_ref(), &model_config).await?;
    Ok((provider, model_config))
}

async fn try_other_models(
    provider_name: &str,
    skip_model: &str,
    log: &mut Vec<String>,
) -> Option<(Arc<dyn Provider>, goose_providers::model::ModelConfig)> {
    let entry = providers::get_from_registry(provider_name).await.ok()?;
    let temp = entry.create_with_default_model(vec![]).await.ok()?;
    let toolshim = Config::global()
        .get_param::<bool>("GOOSE_TOOLSHIM")
        .unwrap_or(false);
    let models = temp.fetch_recommended_models(toolshim).await.ok()?;

    for model in models.iter().filter(|m| m.as_str() != skip_model).take(3) {
        log.push(format!("  Trying {} / {} ...", provider_name, model));
        match try_create_and_test(provider_name, model).await {
            Ok(p) => {
                log.push(format!("  ✓ {} / {} works", provider_name, model));
                return Some(p);
            }
            Err(e) => log.push(format!("  ✗ {}", describe_error(&e))),
        }
    }
    None
}

async fn try_other_providers(
    skip: &str,
    log: &mut Vec<String>,
) -> Option<(Arc<dyn Provider>, goose_providers::model::ModelConfig)> {
    for (meta, _) in providers::providers().await {
        if meta.name == skip {
            continue;
        }
        let entry = match providers::get_from_registry(&meta.name).await {
            Ok(e) => e,
            Err(_) => continue,
        };
        let model_name = entry.metadata().default_model.clone();
        let model_config =
            match crate::model_config::model_config_from_user_config(&meta.name, &model_name) {
                Ok(config) => config,
                Err(_) => continue,
            };
        let provider = match entry.create_with_default_model(vec![]).await {
            Ok(p) => p,
            Err(_) => continue,
        };
        log.push(format!("  Trying {} / {} ...", meta.name, model_name));
        match test_provider(provider.as_ref(), &model_config).await {
            Ok(()) => {
                log.push(format!("  ✓ {} / {} works", meta.name, model_name));
                return Some((provider, model_config));
            }
            Err(e) => log.push(format!("  ✗ {}", describe_error(&e))),
        }
    }
    None
}

fn describe_error(e: &ProviderError) -> String {
    match e {
        ProviderError::NotConfigured => {
            "Provider is not configured. Run `goose configure` to set it up.".to_string()
        }
        ProviderError::Authentication(_) => {
            "Authentication failed — check your API key. Run `goose configure` to update it."
                .to_string()
        }
        ProviderError::CreditsExhausted { top_up_url, .. } => {
            let mut msg = "Credits exhausted.".to_string();
            if let Some(url) = top_up_url {
                msg.push_str(&format!(" Top up at: {}", url));
            }
            msg
        }
        ProviderError::RateLimitExceeded { .. } => {
            "Rate limited — wait a moment and try again.".to_string()
        }
        ProviderError::EndpointNotFound(_) => {
            "Model not found — the model name may be wrong for this provider.".to_string()
        }
        ProviderError::NetworkError(_) => {
            "Network error — check your internet connection.".to_string()
        }
        ProviderError::ServerError(_) => {
            "Provider server error — the service may be temporarily down.".to_string()
        }
        other => format!("{}", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn developer_requirement_accepts_enabled_extension() {
        let agent = crate::agents::Agent::new();
        agent
            .extension_manager
            .add_extension(
                ExtensionConfig::Platform {
                    name: developer::EXTENSION_NAME.to_string(),
                    description: "Developer tools".to_string(),
                    display_name: Some("Developer".to_string()),
                    bundled: None,
                    available_tools: vec![],
                },
                None,
                None,
                Some("doctor-enabled-test"),
            )
            .await
            .expect("developer extension should load");

        assert!(require_developer_extension(&agent).await.is_none());
    }

    #[test]
    fn custom_extension_named_developer_does_not_satisfy_requirement() {
        let config = ExtensionConfig::stdio(
            developer::EXTENSION_NAME,
            "custom-developer",
            "Unrelated custom extension",
            30_u64,
        );

        assert!(!is_developer_platform_config(&config));
    }

    #[tokio::test]
    async fn test_deterministic_diagnostic_report() {
        let report = DiagnosticReport::gather().await;
        assert!(
            !report.checks.is_empty(),
            "Diagnostic report must contain checks"
        );
        let categories: Vec<&str> = report.checks.iter().map(|c| c.category.as_str()).collect();
        assert!(categories.contains(&"Shell"), "Must include Shell check");
        assert!(categories.contains(&"VCS"), "Must include VCS check");
        assert!(
            categories.contains(&"Kernel"),
            "Must include Kernel containment check"
        );

        let cli_output = report.format_cli();
        assert!(cli_output.contains("WinAgent Deterministic System Audit"));
        assert!(cli_output.contains("Category"));

        let md_output = report.format_markdown();
        assert!(md_output.contains("WinAgent Deterministic Environment Audit"));
    }
}

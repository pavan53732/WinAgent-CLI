//! 3-Tier capability policy for WinAgent.
//!
//! The tiers describe what may run without asking a human:
//!
//! 1. `SAFE` — read-only inspection only. Every mutation requires approval.
//! 2. `EDIT` — mutations confined to the workspace run automatically; anything
//!    reaching outside the workspace, or touching the machine rather than the
//!    repository, requires approval.
//! 3. `AUTONOMOUS` — policy-permitted workspace operations run uninterrupted.
//!    Autonomous is not unrestricted: system administration, registry and
//!    credential operations, paths outside the workspace, and unrecognised
//!    commands all still stop for a human.
//!
//! The tier is derived from the session's [`GooseMode`] so this policy can only
//! ever *tighten* the existing approval system, never contradict it.

use serde::{Deserialize, Serialize};

use std::path::{Path, PathBuf};

use crate::config::GooseMode;
use crate::permission::path_security::resolve_and_validate_workspace_path;

/// Tools exposed by the WinAgent developer extension. This is the execution
/// surface WinAgent itself controls, so the policy is authoritative for it.
pub const WINAGENT_TOOLS: &[&str] = &[
    "shell",
    "read",
    "write",
    "edit",
    "tree",
    "read_image",
    "git_status",
    "git_diff",
    "git_commit",
    "git_log",
];

pub fn is_winagent_tool(tool_name: &str) -> bool {
    WINAGENT_TOOLS.contains(&tool_name)
}

/// A tool served by an MCP server is namespaced `mcp__<server>__<tool>`.
///
/// The session's approval mode is the authority for third-party extensions, so
/// the capability policy only owns the WinAgent execution surface and anything
/// it cannot attribute to a source.
pub fn is_delegated_third_party_tool(tool_name: &str) -> bool {
    tool_name.starts_with("mcp__")
}

/// Argument names that carry a filesystem path.
pub const PATH_ARGUMENT_NAMES: &[&str] = &[
    "path",
    "file_path",
    "directory",
    "dir",
    "cwd",
    "working_dir",
    "filename",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityTier {
    #[default]
    Safe,
    Edit,
    Autonomous,
}

impl CapabilityTier {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "safe" => Some(Self::Safe),
            "edit" => Some(Self::Edit),
            "autonomous" | "auto" => Some(Self::Autonomous),
            _ => None,
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Safe => "SAFE",
            Self::Edit => "EDIT",
            Self::Autonomous => "AUTONOMOUS",
        }
    }

    /// Map the session mode onto a capability tier.
    ///
    /// `Auto` is the only mode that authorizes unattended mutation, so it maps
    /// to `Autonomous`; the approval modes map to the tiers that stop sooner.
    pub fn for_goose_mode(mode: GooseMode) -> Self {
        match mode {
            GooseMode::Auto => Self::Autonomous,
            GooseMode::SmartApprove => Self::Edit,
            GooseMode::Approve | GooseMode::Chat => Self::Safe,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    Allow,
    AskApproval,
    Deny,
}

/// Semantic class of a shell command segment.
///
/// A Job Object bounds process lifetime. It is not a filesystem, registry, or
/// network sandbox, so "autonomous" can only ever mean "workspace-scoped and
/// recognised". Anything else must stop for a human.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellCommandClass {
    /// Build, test, or type-check inside the workspace.
    WorkspaceBuild,
    /// Repository inspection or history rewriting.
    SourceControl,
    /// Read-only inspection of the machine.
    ReadOnlyInspection,
    /// Installing software or packages.
    PackageInstall,
    /// Reaching the network.
    Network,
    /// Starting, stopping, or signalling processes.
    ProcessAdministration,
    /// Reading or writing the registry.
    Registry,
    /// Creating, reconfiguring, or deleting services.
    ServiceManagement,
    /// Disk, volume, or boot configuration.
    DiskOperation,
    /// Credential stores, tokens, or privilege inspection.
    CredentialAccess,
    /// A path outside the workspace root.
    ExternalPathAccess,
    /// Not recognised.
    Unknown,
}

impl ShellCommandClass {
    /// Classes that are refused under every tier.
    fn is_always_denied(self) -> bool {
        matches!(
            self,
            ShellCommandClass::Registry
                | ShellCommandClass::DiskOperation
                | ShellCommandClass::ServiceManagement
                | ShellCommandClass::CredentialAccess
        )
    }

    /// Classes that always require a human decision.
    fn requires_approval(self) -> bool {
        matches!(
            self,
            ShellCommandClass::Network
                | ShellCommandClass::ProcessAdministration
                | ShellCommandClass::ExternalPathAccess
                | ShellCommandClass::Unknown
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityPolicy {
    pub tier: CapabilityTier,
    pub workspace_root: Option<PathBuf>,
    pub allow_package_install: bool,
    /// True when no human is watching, i.e. `GooseMode::Auto`.
    ///
    /// An approval prompt has no responder in an unattended run, so a decision
    /// that would normally ask is refused instead. This keeps the policy from
    /// stalling a run without a human, and surfaces the restriction as an error
    /// the agent can act on.
    pub unattended: bool,
}

impl Default for CapabilityPolicy {
    fn default() -> Self {
        Self {
            tier: CapabilityTier::Safe,
            workspace_root: None,
            allow_package_install: false,
            unattended: false,
        }
    }
}

impl CapabilityPolicy {
    pub fn new(tier: CapabilityTier, workspace_root: Option<PathBuf>) -> Self {
        Self {
            tier,
            workspace_root,
            allow_package_install: false,
            unattended: false,
        }
    }

    pub fn for_goose_mode(mode: GooseMode, workspace_root: Option<PathBuf>) -> Self {
        Self {
            unattended: mode == GooseMode::Auto,
            ..Self::new(CapabilityTier::for_goose_mode(mode), workspace_root)
        }
    }

    /// Turn a decision into one the current mode can actually act on.
    fn apply_unattended(&self, decision: PolicyDecision) -> PolicyDecision {
        match (self.unattended, decision) {
            (true, PolicyDecision::AskApproval) => PolicyDecision::Deny,
            (_, decision) => decision,
        }
    }

    /// Verify a path argument stays inside the workspace.
    ///
    /// Returns the resolved path so callers operate on the path that was
    /// validated rather than on the string they supplied.
    pub fn resolve_path(&self, path: &Path) -> anyhow::Result<PathBuf> {
        let root = self.workspace_root.as_deref().ok_or_else(|| {
            anyhow::anyhow!("no workspace root is configured for path validation")
        })?;
        resolve_and_validate_workspace_path(path, root)
    }

    pub fn evaluate_path(&self, path: &Path) -> PolicyDecision {
        match self.resolve_path(path) {
            Ok(_) => PolicyDecision::Allow,
            Err(e) => {
                tracing::warn!("blocked path outside the workspace: {e}");
                PolicyDecision::Deny
            }
        }
    }

    /// Evaluate a tool call against the capability policy.
    ///
    /// Tool names outside [`WINAGENT_TOOLS`] are the responsibility of the
    /// session's approval mode, so this only constrains the WinAgent execution
    /// surface. Path arguments are checked for every tool.
    pub fn evaluate_tool(&self, tool_name: &str, target_path: Option<&Path>) -> PolicyDecision {
        if let Some(path) = target_path {
            if self.workspace_root.is_some() && self.evaluate_path(path) == PolicyDecision::Deny {
                return PolicyDecision::Deny;
            }
        }

        if is_delegated_third_party_tool(tool_name) {
            return PolicyDecision::Allow;
        }

        let decision = match tool_name {
            "read" | "tree" | "read_image" | "git_status" | "git_diff" | "git_log" => {
                PolicyDecision::Allow
            }
            "write" | "edit" => match self.tier {
                CapabilityTier::Safe => PolicyDecision::AskApproval,
                CapabilityTier::Edit | CapabilityTier::Autonomous => PolicyDecision::Allow,
            },
            "git_commit" => match self.tier {
                CapabilityTier::Safe => PolicyDecision::AskApproval,
                CapabilityTier::Edit | CapabilityTier::Autonomous => PolicyDecision::Allow,
            },
            "shell" => self.evaluate_shell_command(""),
            // Deny by default: an unrecognised capability is never automatic.
            _ => PolicyDecision::AskApproval,
        };
        self.apply_unattended(decision)
    }

    /// Evaluate a full shell command line.
    pub fn evaluate_shell_command(&self, command_line: &str) -> PolicyDecision {
        let classes = classify_shell_command(command_line);

        if classes.iter().any(|class| class.is_always_denied()) {
            return PolicyDecision::Deny;
        }

        // Any drive-qualified or UNC reference is checked, whatever the
        // command's class: a "read-only" utility can still be pointed outside
        // the workspace.
        if self.validate_referenced_paths(command_line).is_err()
            && !absolute_path_references(command_line).is_empty()
        {
            tracing::warn!("shell command references a path outside the workspace");
            return PolicyDecision::Deny;
        }

        let needs_approval = classes.iter().any(|class| {
            class.requires_approval()
                || *class == ShellCommandClass::PackageInstall && !self.allow_package_install
        });

        let decision = match self.tier {
            // Only inspection runs unattended; building and committing the
            // repository are still mutations.
            CapabilityTier::Safe => {
                if classes
                    .iter()
                    .all(|class| *class == ShellCommandClass::ReadOnlyInspection)
                {
                    PolicyDecision::Allow
                } else {
                    PolicyDecision::AskApproval
                }
            }
            CapabilityTier::Edit | CapabilityTier::Autonomous => {
                if needs_approval {
                    PolicyDecision::AskApproval
                } else {
                    PolicyDecision::Allow
                }
            }
        };
        self.apply_unattended(decision)
    }

    /// Extract Windows absolute paths and drive-qualified references from a
    /// command line and require each to resolve inside the workspace.
    fn validate_referenced_paths(&self, command_line: &str) -> anyhow::Result<()> {
        if self.workspace_root.is_none() {
            anyhow::bail!("no workspace root is configured");
        }
        for reference in absolute_path_references(command_line) {
            self.resolve_path(Path::new(&reference))?;
        }
        Ok(())
    }
}

/// Split a command line into independently classified segments.
fn split_segments(command_line: &str) -> Vec<String> {
    command_line
        .split([';', '|', '\n'])
        .flat_map(|segment| segment.split("&&"))
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
        .collect()
}

fn first_word(segment: &str) -> Option<String> {
    segment
        .split_whitespace()
        .next()
        .map(|word| word.to_lowercase())
}

fn program_name(segment: &str) -> String {
    let word = first_word(segment).unwrap_or_default();
    word.rsplit(['\\', '/']).next().unwrap_or(&word).to_string()
}

fn contains_any(segment: &str, needles: &[&str]) -> bool {
    let lowered = segment.to_lowercase();
    needles.iter().any(|needle| lowered.contains(needle))
}

fn is_drive_or_unc_reference(segment: &str) -> bool {
    contains_any(segment, &[":\\", "://", "\\\\"])
}

/// Classify each segment of a command line.
///
/// Classification is intentionally conservative: a segment that is not
/// positively recognised is [`ShellCommandClass::Unknown`], which never runs
/// unattended. This is an allow-list, so the failure mode is a prompt rather
/// than an unapproved system mutation.
pub fn classify_shell_command(command_line: &str) -> Vec<ShellCommandClass> {
    let mut classes = Vec::new();
    for segment in split_segments(command_line) {
        classify_segment(&segment, &mut classes);
    }
    if classes.is_empty() {
        classes.push(ShellCommandClass::Unknown);
    }
    classes
}

fn classify_segment(segment: &str, classes: &mut Vec<ShellCommandClass>) {
    let program = program_name(segment);
    let is_shell_wrapper = matches!(
        program.as_str(),
        "cmd" | "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe" | "bash" | "sh" | "wsl"
    );

    if is_shell_wrapper {
        let inner = segment
            .split_once("-Command")
            .or_else(|| segment.split_once("-c"))
            .or_else(|| segment.split_once("/C"))
            .or_else(|| segment.split_once("/c"))
            .map(|(_, rest)| rest.trim_matches(['"', '\'']))
            .unwrap_or(segment);
        for nested in split_segments(inner) {
            classify_segment(&nested, classes);
        }
        return;
    }

    let class = match program.as_str() {
        "git" => {
            let subcommand = segment
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .trim_start_matches('-')
                .to_string();
            const READ_ONLY_SUBCOMMANDS: &[&str] = &[
                "status",
                "diff",
                "log",
                "show",
                "rev-parse",
                "blame",
                "describe",
                "ls-files",
                "shortlog",
                "cat-file",
                "config",
                "version",
                "reflog",
            ];
            if READ_ONLY_SUBCOMMANDS.contains(&subcommand.as_str()) {
                ShellCommandClass::ReadOnlyInspection
            } else {
                ShellCommandClass::SourceControl
            }
        }
        "cargo" | "dotnet" | "msbuild" | "npm" | "npx" | "pnpm" | "yarn" | "bun" | "pytest"
        | "go" | "javac" | "gradlew" | "mvn" | "tsc" => {
            if contains_any(
                segment,
                &["install", "publish", "add ", "remove ", "uninstall"],
            ) {
                ShellCommandClass::PackageInstall
            } else {
                ShellCommandClass::WorkspaceBuild
            }
        }
        "winget" | "choco" | "scoop" | "scoopctl" | "nuget" | "msiexec" | "pip" | "pip3" => {
            ShellCommandClass::PackageInstall
        }
        "curl" | "wget" | "ssh" | "scp" | "ftp" | "aria2c" | "certutil" => {
            ShellCommandClass::Network
        }
        "reg" | "regedit" | "regedit.exe" | "reg.exe" | "setx" => ShellCommandClass::Registry,
        "sc" | "schtasks" | "service" | "nssm" => ShellCommandClass::ServiceManagement,
        "taskkill" | "shutdown" => ShellCommandClass::ProcessAdministration,
        "net" | "wmic" | "tasklist" => {
            if contains_any(
                segment,
                &["kill", "create", "config", "start", "stop", "delete"],
            ) {
                ShellCommandClass::ProcessAdministration
            } else {
                ShellCommandClass::ReadOnlyInspection
            }
        }
        "format" | "diskpart" | "fsutil" | "cipher" | "bcdedit" | "manage-bde" | "mountvol" => {
            ShellCommandClass::DiskOperation
        }
        "whoami" | "net1" | "cmdkey" | "runas" => ShellCommandClass::CredentialAccess,
        "echo" | "type" | "cat" | "ls" | "dir" | "pwd" | "date" | "time" | "sleep" | "head"
        | "tail" | "grep" | "find" | "wc" | "sort" | "diff" | "stat" | "env" | "printenv"
        | "where" | "which" | "hostname" | "systeminfo" | "ver" => {
            ShellCommandClass::ReadOnlyInspection
        }
        _ => {
            if contains_any(
                segment,
                &[
                    "invoke-webrequest",
                    "invoke-restmethod",
                    "iwr ",
                    "irm ",
                    "start-process",
                    "start-service",
                    "stop-service",
                    "new-service",
                    "set-service",
                    "remove-service",
                    "restart-computer",
                    "stop-computer",
                    "get-credential",
                    "get-accredential",
                    "set-itemproperty",
                    "remove-itemproperty",
                    "new-itemproperty",
                    "invoke-expression",
                ],
            ) {
                ShellCommandClass::ProcessAdministration
            } else if is_drive_or_unc_reference(segment) {
                ShellCommandClass::ExternalPathAccess
            } else {
                ShellCommandClass::Unknown
            }
        }
    };

    classes.push(class);
}

/// Collect drive-qualified path references from a command line.
///
/// Deliberately narrow: it only matches tokens that look like `X:\...` or
/// `\\server\...`, which is what a path escape has to look like in practice.
fn absolute_path_references(command_line: &str) -> Vec<String> {
    let mut references = Vec::new();
    for token in command_line.split(['"', '\'', ' ', '\t', ',', ';', '|']) {
        let token = token.trim();
        if token.len() < 4 {
            continue;
        }
        let bytes = token.as_bytes();
        let drive_qualified = bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/');
        let unc = token.starts_with("\\\\");
        if drive_qualified || unc {
            references.push(token.to_string());
        }
    }
    references
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn tier_is_derived_from_goose_mode() {
        assert_eq!(
            CapabilityTier::for_goose_mode(GooseMode::Auto),
            CapabilityTier::Autonomous
        );
        assert_eq!(
            CapabilityTier::for_goose_mode(GooseMode::SmartApprove),
            CapabilityTier::Edit
        );
        assert_eq!(
            CapabilityTier::for_goose_mode(GooseMode::Approve),
            CapabilityTier::Safe
        );
        assert_eq!(
            CapabilityTier::for_goose_mode(GooseMode::Chat),
            CapabilityTier::Safe
        );
    }

    #[test]
    fn read_only_tools_are_allowed_in_every_tier() {
        for tier in [
            CapabilityTier::Safe,
            CapabilityTier::Edit,
            CapabilityTier::Autonomous,
        ] {
            let policy = CapabilityPolicy::new(tier, None);
            for tool in [
                "read",
                "tree",
                "read_image",
                "git_status",
                "git_diff",
                "git_log",
            ] {
                assert_eq!(policy.evaluate_tool(tool, None), PolicyDecision::Allow);
            }
        }
    }

    #[test]
    fn mutations_require_approval_in_safe_tier() {
        let policy = CapabilityPolicy::new(CapabilityTier::Safe, None);
        assert_eq!(
            policy.evaluate_tool("write", None),
            PolicyDecision::AskApproval
        );
        assert_eq!(
            policy.evaluate_tool("edit", None),
            PolicyDecision::AskApproval
        );
        assert_eq!(
            policy.evaluate_tool("git_commit", None),
            PolicyDecision::AskApproval
        );
    }

    #[test]
    fn mutations_are_allowed_in_edit_and_autonomous_tiers() {
        for tier in [CapabilityTier::Edit, CapabilityTier::Autonomous] {
            let policy = CapabilityPolicy::new(tier, None);
            assert_eq!(policy.evaluate_tool("write", None), PolicyDecision::Allow);
            assert_eq!(policy.evaluate_tool("edit", None), PolicyDecision::Allow);
        }
    }

    #[test]
    fn unknown_winagent_capabilities_never_default_to_allow() {
        for tier in [
            CapabilityTier::Safe,
            CapabilityTier::Edit,
            CapabilityTier::Autonomous,
        ] {
            let policy = CapabilityPolicy::new(tier, None);
            let decision = policy.evaluate_tool("totally_unknown_capability", None);
            assert_ne!(decision, PolicyDecision::Allow);
        }
    }

    #[test]
    fn third_party_tools_defer_to_the_session_approval_mode() {
        let policy = CapabilityPolicy::new(CapabilityTier::Safe, None);
        assert_eq!(
            policy.evaluate_tool("mcp__some_server__do_thing", None),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn paths_outside_the_workspace_are_denied() {
        let root = workspace();
        let outside = workspace();
        let outside_file = outside.path().join("secret.txt");
        std::fs::write(&outside_file, "secret").unwrap();

        let policy =
            CapabilityPolicy::new(CapabilityTier::Autonomous, Some(root.path().to_path_buf()));
        assert_eq!(
            policy.evaluate_tool("read", Some(&outside_file)),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn sibling_prefix_escape_is_denied() {
        let parent = workspace();
        let root = parent.path().join("Project");
        let sibling = parent.path().join("Project2");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();

        let policy = CapabilityPolicy::new(CapabilityTier::Autonomous, Some(root.clone()));
        assert_eq!(
            policy.evaluate_tool("write", Some(&sibling)),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn workspace_build_commands_are_recognised() {
        let classes = classify_shell_command("cargo build --release");
        assert!(classes.contains(&ShellCommandClass::WorkspaceBuild));

        let classes = classify_shell_command("git status --porcelain");
        assert!(classes.contains(&ShellCommandClass::ReadOnlyInspection));

        let classes = classify_shell_command("git commit -m 'x'");
        assert!(classes.contains(&ShellCommandClass::SourceControl));
    }

    #[test]
    fn registry_and_disk_operations_are_denied_in_every_tier() {
        for tier in [
            CapabilityTier::Safe,
            CapabilityTier::Edit,
            CapabilityTier::Autonomous,
        ] {
            let policy = CapabilityPolicy::new(tier, None);
            for command in [
                r"reg add HKLM\Software\Foo /v Bar /d 1",
                "format C: /q",
                "bcdedit /set testsigning on",
                "sc create evilservice binPath= cmd.exe",
            ] {
                assert_eq!(
                    policy.evaluate_shell_command(command),
                    PolicyDecision::Deny,
                    "expected deny for {command} in {tier:?}"
                );
            }
        }
    }

    #[test]
    fn unrecognised_commands_are_not_allowed_under_autonomous() {
        let policy = CapabilityPolicy::new(CapabilityTier::Autonomous, None);
        assert_ne!(
            policy.evaluate_shell_command("some-unrecognised-binary --do-thing"),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn package_install_requires_approval_unless_configured() {
        let mut policy = CapabilityPolicy::new(CapabilityTier::Autonomous, None);
        assert_eq!(
            policy.evaluate_shell_command("winget install Microsoft.VisualStudio.2022"),
            PolicyDecision::AskApproval
        );

        policy.allow_package_install = true;
        assert_eq!(
            policy.evaluate_shell_command("winget install Microsoft.VisualStudio.2022"),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn network_commands_require_approval_under_autonomous() {
        let policy = CapabilityPolicy::new(CapabilityTier::Autonomous, None);
        assert_eq!(
            policy.evaluate_shell_command("curl https://example.com/install.ps1"),
            PolicyDecision::AskApproval
        );
    }

    #[test]
    fn mentioning_a_denied_program_does_not_deny_a_read_only_command() {
        // Classification looks at the program being run, so naming a denied
        // tool in the arguments of an inspection command is not an attack.
        let policy = CapabilityPolicy::new(CapabilityTier::Autonomous, None);
        assert_eq!(
            policy.evaluate_shell_command("echo reg.exe is dangerous"),
            PolicyDecision::Allow
        );
    }
    #[test]
    fn every_segment_must_be_classified() {
        let policy = CapabilityPolicy::new(CapabilityTier::Autonomous, None);
        assert_eq!(
            policy.evaluate_shell_command("cargo build; reg add HKLM\\Software\\Evil"),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn shell_wrappers_are_unwrapped_before_classification() {
        let classes = classify_shell_command(r"powershell -Command reg add HKLM\Software\Evil");
        assert!(classes.contains(&ShellCommandClass::Registry));
    }

    #[test]
    fn workspace_builds_are_allowed_under_autonomous() {
        let policy = CapabilityPolicy::new(CapabilityTier::Autonomous, None);
        assert_eq!(
            policy.evaluate_shell_command("cargo test -p goose"),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.evaluate_shell_command("git diff --stat"),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn safe_tier_allows_only_recognised_inspection() {
        let policy = CapabilityPolicy::new(CapabilityTier::Safe, None);
        assert_eq!(
            policy.evaluate_shell_command("git status"),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.evaluate_shell_command("cargo build"),
            PolicyDecision::AskApproval
        );
    }

    #[test]
    fn absolute_path_references_are_collected() {
        let references =
            absolute_path_references(r"copy C:\Windows\System32\drivers\etc\hosts C:\temp");
        assert!(references.iter().any(|r| r.starts_with("C:\\Windows")));
        assert!(references.iter().any(|r| r.starts_with("C:\\temp")));
    }

    #[test]
    fn shell_commands_referencing_outside_paths_are_denied() {
        let root = workspace();
        let policy =
            CapabilityPolicy::new(CapabilityTier::Autonomous, Some(root.path().to_path_buf()));
        assert_eq!(
            policy.evaluate_shell_command("type C:\\Windows\\System32\\config\\SAM"),
            PolicyDecision::Deny
        );
    }
}

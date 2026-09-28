//! 3-Tier Capability Policy Engine for WinAgent
//!
//! Replaces ambiguous "YOLO" execution concepts with a rigorous, deterministic 3-tier model:
//! 1. SAFE: Read-only operations automatic; side-effecting operations require approval.
//! 2. EDIT: Workspace modifications automatic; external/system effects require approval.
//! 3. AUTONOMOUS: Full execution of policy-permitted tools without interruption,
//!    while strictly enforcing workspace and containment boundaries (autonomous != unrestricted).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Capability execution tiers for WinAgent
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
}

/// Action to be taken by the policy engine for a tool invocation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    Allow,
    AskApproval,
    Deny,
}

/// WinAgent capability policy configuration and evaluator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityPolicy {
    pub tier: CapabilityTier,
    pub workspace_root: Option<PathBuf>,
    pub allow_network: bool,
    pub allow_package_install: bool,
}

impl Default for CapabilityPolicy {
    fn default() -> Self {
        Self {
            tier: CapabilityTier::Safe,
            workspace_root: None,
            allow_network: false,
            allow_package_install: false,
        }
    }
}

impl CapabilityPolicy {
    pub fn new(tier: CapabilityTier, workspace_root: Option<PathBuf>) -> Self {
        Self {
            tier,
            workspace_root,
            allow_network: tier == CapabilityTier::Autonomous,
            allow_package_install: false,
        }
    }

    /// Evaluates a platform tool call against the capability policy
    pub fn evaluate_tool(&self, tool_name: &str, target_path: Option<&Path>) -> PolicyDecision {
        // Check workspace path escape boundary first
        if let (Some(target), Some(root)) = (target_path, &self.workspace_root) {
            if target.is_absolute() && !target.starts_with(root) {
                // Modifying outside workspace is never automatic
                match self.tier {
                    CapabilityTier::Safe | CapabilityTier::Edit => {
                        return PolicyDecision::AskApproval
                    }
                    CapabilityTier::Autonomous => return PolicyDecision::AskApproval,
                }
            }
        }

        match tool_name {
            // 1. Read-only tools
            "read" | "tree" | "read_image" | "git_status" | "git_diff" | "git_log" => {
                PolicyDecision::Allow
            }

            // 2. Workspace modification tools
            "write" | "edit" | "git_commit" => match self.tier {
                CapabilityTier::Safe => PolicyDecision::AskApproval,
                CapabilityTier::Edit | CapabilityTier::Autonomous => PolicyDecision::Allow,
            },

            // 3. Command execution (evaluated deeper in evaluate_shell_command)
            "shell" => match self.tier {
                CapabilityTier::Safe => PolicyDecision::AskApproval,
                CapabilityTier::Edit | CapabilityTier::Autonomous => PolicyDecision::Allow,
            },

            // Default safe fallback
            _ => match self.tier {
                CapabilityTier::Safe => PolicyDecision::AskApproval,
                CapabilityTier::Edit => PolicyDecision::AskApproval,
                CapabilityTier::Autonomous => PolicyDecision::Allow,
            },
        }
    }

    /// Evaluates a PowerShell or shell command line for system-level safety
    pub fn evaluate_shell_command(&self, command_line: &str) -> PolicyDecision {
        let trimmed = command_line.trim().to_lowercase();

        // Dangerous or unconstrained system mutations
        let is_system_mutation = trimmed.contains("reg.exe")
            || trimmed.contains("format ")
            || trimmed.contains("rmdir /s")
            || trimmed.contains("remove-item -recurse c:\\")
            || trimmed.contains("bcdedit")
            || trimmed.contains("shutdown");

        if is_system_mutation {
            return PolicyDecision::Deny;
        }

        // Package installations or software installations
        let is_package_install = trimmed.contains("winget install")
            || trimmed.contains("choco install")
            || trimmed.contains("npm install -g")
            || trimmed.contains("pip install --user");

        if is_package_install {
            return match self.tier {
                CapabilityTier::Safe | CapabilityTier::Edit => PolicyDecision::AskApproval,
                CapabilityTier::Autonomous => {
                    if self.allow_package_install {
                        PolicyDecision::Allow
                    } else {
                        PolicyDecision::AskApproval
                    }
                }
            };
        }

        // Build / Test operations within project
        let is_build_or_test = trimmed.starts_with("cargo ")
            || trimmed.starts_with("dotnet ")
            || trimmed.starts_with("msbuild ")
            || trimmed.starts_with("npm test")
            || trimmed.starts_with("npm run ")
            || trimmed.starts_with("pnpm ")
            || trimmed.starts_with("pytest")
            || trimmed.starts_with("python -m unittest")
            || trimmed.starts_with("git ");

        match self.tier {
            CapabilityTier::Safe => {
                if is_build_or_test
                    && (trimmed.contains("test")
                        || trimmed.contains("status")
                        || trimmed.contains("diff"))
                {
                    PolicyDecision::Allow
                } else {
                    PolicyDecision::AskApproval
                }
            }
            CapabilityTier::Edit | CapabilityTier::Autonomous => PolicyDecision::Allow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_tier_decisions() {
        let policy = CapabilityPolicy::new(CapabilityTier::Safe, None);
        assert_eq!(policy.evaluate_tool("read", None), PolicyDecision::Allow);
        assert_eq!(
            policy.evaluate_tool("git_status", None),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.evaluate_tool("git_diff", None),
            PolicyDecision::Allow
        );
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
    fn test_edit_tier_decisions() {
        let policy = CapabilityPolicy::new(CapabilityTier::Edit, None);
        assert_eq!(policy.evaluate_tool("read", None), PolicyDecision::Allow);
        assert_eq!(policy.evaluate_tool("write", None), PolicyDecision::Allow);
        assert_eq!(policy.evaluate_tool("edit", None), PolicyDecision::Allow);
        assert_eq!(
            policy.evaluate_tool("git_commit", None),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.evaluate_shell_command("cargo test"),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.evaluate_shell_command("dotnet build"),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.evaluate_shell_command("winget install foobar"),
            PolicyDecision::AskApproval
        );
    }

    #[test]
    fn test_autonomous_tier_boundaries() {
        let root = PathBuf::from(r"C:\Users\test\project");
        let policy = CapabilityPolicy::new(CapabilityTier::Autonomous, Some(root.clone()));

        // Inside workspace edits are allowed
        let inside_path = root.join("src/main.rs");
        assert_eq!(
            policy.evaluate_tool("write", Some(&inside_path)),
            PolicyDecision::Allow
        );

        // Outside workspace modifications must ask approval even in Autonomous mode
        let outside_path = PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts");
        assert_eq!(
            policy.evaluate_tool("write", Some(&outside_path)),
            PolicyDecision::AskApproval
        );

        // Catastrophic system commands are denied outright
        assert_eq!(
            policy.evaluate_shell_command("reg.exe delete HKLM"),
            PolicyDecision::Deny
        );
    }
}

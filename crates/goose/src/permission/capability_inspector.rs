//! Capability policy enforcement at tool-dispatch time.
//!
//! Registered as a [`ToolInspector`], so it runs in *both* agent loops (the
//! legacy loop and the `GOOSE_STATE_MACHINE` path) because both call
//! `ToolInspectionManager::inspect_tools` before any tool is dispatched.
//!
//! The policy is a ceiling, not a replacement: it can deny a call or push it
//! back to the user, but an `Allow` never overrides a stricter decision made by
//! the session's approval mode.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::GooseMode;
use crate::conversation::message::{Message, ToolRequest};
use crate::permission::policy::{
    is_winagent_tool, CapabilityPolicy, PolicyDecision, PATH_ARGUMENT_NAMES,
};
use crate::tool_inspection::{InspectionAction, InspectionResult, ToolInspector};

const INSPECTOR_NAME: &str = "winagent_capability";

pub struct CapabilityInspector {
    session_manager: Arc<crate::session::SessionManager>,
}

impl CapabilityInspector {
    pub fn new(session_manager: Arc<crate::session::SessionManager>) -> Self {
        Self { session_manager }
    }

    /// The workspace root is the session's working directory, resolved per
    /// request so concurrent sessions do not share a boundary.
    async fn policy_for(&self, session_id: &str, goose_mode: GooseMode) -> CapabilityPolicy {
        let workspace_root = self
            .session_manager
            .get_session(session_id, false)
            .await
            .ok()
            .map(|session| session.working_dir);
        CapabilityPolicy::for_goose_mode(goose_mode, workspace_root)
    }
}

fn string_argument(arguments: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    match arguments.get(key) {
        Some(Value::String(value)) => Some(value.clone()),
        _ => None,
    }
}

/// Collect filesystem path arguments from a tool call.
///
/// Only arguments the tools actually accept as paths are considered, and the
/// image tool's `source` is skipped when it is a URL.
fn path_arguments(tool_name: &str, arguments: &serde_json::Map<String, Value>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for key in PATH_ARGUMENT_NAMES {
        if let Some(value) = string_argument(arguments, key) {
            if !value.is_empty() {
                paths.push(PathBuf::from(value));
            }
        }
    }
    if let Some(Value::Array(files)) = arguments.get("files") {
        for file in files {
            if let Value::String(value) = file {
                if !value.is_empty() {
                    paths.push(PathBuf::from(value));
                }
            }
        }
    }
    if tool_name == "read_image" {
        paths.retain(|path| {
            let value = path.to_string_lossy();
            !value.starts_with("http://") && !value.starts_with("https://")
        });
    }
    paths
}

fn shell_command(arguments: &serde_json::Map<String, Value>) -> Option<String> {
    string_argument(arguments, "command")
}

/// Result of evaluating one tool request against the capability policy.
///
/// The policy is a ceiling over the session's approval mode, so it only
/// constrains the WinAgent execution surface. A tool name the policy does not
/// recognise cannot execute at all: no extension advertises it, so dispatch
/// fails before any side effect. Prompting for those instead would stall
/// unattended runs without adding a guarantee.
fn evaluate_request(
    policy: &CapabilityPolicy,
    tool_name: &str,
    arguments: &serde_json::Map<String, Value>,
) -> Option<PolicyDecision> {
    if !is_winagent_tool(tool_name) {
        // Third-party and internal tools keep the session's approval mode, but
        // they are still not allowed to reach outside the workspace.
        for path in path_arguments(tool_name, arguments) {
            if policy.workspace_root.is_some()
                && policy.evaluate_path(&path) == PolicyDecision::Deny
            {
                return Some(PolicyDecision::Deny);
            }
        }
        return None;
    }

    if tool_name == "shell" {
        let command = shell_command(arguments).unwrap_or_default();
        return Some(policy.evaluate_shell_command(&command));
    }

    let paths = path_arguments(tool_name, arguments);
    let target = paths.first().map(PathBuf::as_path);
    Some(policy.evaluate_tool(tool_name, target))
}

#[async_trait]
impl ToolInspector for CapabilityInspector {
    fn name(&self) -> &'static str {
        INSPECTOR_NAME
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn inspect(
        &self,
        session_id: &str,
        tool_requests: &[ToolRequest],
        _messages: &[Message],
        goose_mode: GooseMode,
    ) -> Result<Vec<InspectionResult>> {
        let policy = self.policy_for(session_id, goose_mode).await;

        let mut results = Vec::new();
        for request in tool_requests {
            let Ok(tool_call) = &request.tool_call else {
                continue;
            };
            let tool_name = tool_call.name.as_ref();
            let empty = serde_json::Map::new();
            let arguments = tool_call.arguments.as_ref().unwrap_or(&empty);

            let Some(decision) = evaluate_request(&policy, tool_name, arguments) else {
                continue;
            };

            let action = match decision {
                PolicyDecision::Allow => continue,
                PolicyDecision::Deny => InspectionAction::Deny,
                PolicyDecision::AskApproval => InspectionAction::RequireApproval(Some(format!(
                    "WinAgent capability policy ({}) requires approval for {tool_name}",
                    policy.tier.display_name()
                ))),
            };

            let reason = match action {
                InspectionAction::Deny => format!(
                    "WinAgent capability policy ({}) denied {tool_name}",
                    policy.tier.display_name()
                ),
                _ => format!(
                    "WinAgent capability policy ({}) restricted {tool_name}",
                    policy.tier.display_name()
                ),
            };

            results.push(InspectionResult {
                tool_request_id: request.id.clone(),
                action,
                reason,
                confidence: 1.0,
                inspector_name: self.name().to_string(),
                finding_id: None,
            });
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionType;
    use rmcp::model::CallToolRequestParams;
    use rmcp::object;
    use std::path::Path;
    use tempfile::TempDir;

    fn workspace() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    async fn fixture(working_dir: &Path) -> (CapabilityInspector, String) {
        let (manager, session_id) = harness(working_dir).await;
        (CapabilityInspector::new(manager), session_id)
    }

    async fn harness(working_dir: &Path) -> (Arc<crate::session::SessionManager>, String) {
        let manager = Arc::new(crate::session::SessionManager::new(
            tempfile::tempdir().unwrap().keep(),
        ));
        let session = manager
            .create_session(
                working_dir.to_path_buf(),
                "capability-test".to_string(),
                SessionType::User,
                GooseMode::Auto,
            )
            .await
            .unwrap();
        let session_id = session.id.clone();
        (manager, session_id)
    }

    async fn inspect(
        inspector: &CapabilityInspector,
        session_id: &str,
        tool_name: &str,
        arguments: serde_json::Map<String, Value>,
        mode: GooseMode,
    ) -> Vec<InspectionResult> {
        let request = ToolRequest {
            id: "req-1".to_string(),
            tool_call: Ok(
                CallToolRequestParams::new(tool_name.to_string()).with_arguments(arguments)
            ),
            metadata: None,
            tool_meta: None,
        };
        inspector
            .inspect(session_id, &[request], &[], mode)
            .await
            .unwrap()
    }

    fn decision(results: &[InspectionResult]) -> Option<&InspectionAction> {
        results.first().map(|result| &result.action)
    }

    #[tokio::test]
    async fn read_only_tool_produces_no_restriction() {
        let root = workspace();
        let (inspector, session_id) = fixture(root.path()).await;
        let results = inspect(
            &inspector,
            &session_id,
            "read",
            object!({ "path": "src/main.rs" }),
            GooseMode::Auto,
        )
        .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn workspace_write_is_restricted_in_approve_mode() {
        let root = workspace();
        let (inspector, session_id) = fixture(root.path()).await;
        let results = inspect(
            &inspector,
            &session_id,
            "write",
            object!({ "path": "src/main.rs" }),
            GooseMode::Approve,
        )
        .await;
        assert!(matches!(
            decision(&results),
            Some(InspectionAction::RequireApproval(_))
        ));
    }

    #[tokio::test]
    async fn writing_outside_the_workspace_is_denied_in_auto_mode() {
        let root = workspace();
        let outside = workspace();
        let outside_file = outside.path().join("secret.txt");
        std::fs::write(&outside_file, "secret").unwrap();

        let (inspector, session_id) = fixture(root.path()).await;
        let results = inspect(
            &inspector,
            &session_id,
            "write",
            object!({ "path": outside_file.to_string_lossy() }),
            GooseMode::Auto,
        )
        .await;
        assert_eq!(decision(&results), Some(&InspectionAction::Deny));
    }

    #[tokio::test]
    async fn sibling_prefix_escape_is_denied() {
        let parent = workspace();
        let root = parent.path().join("Project");
        let sibling = parent.path().join("Project2");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();

        let (inspector, session_id) = fixture(&root).await;
        let results = inspect(
            &inspector,
            &session_id,
            "edit",
            object!({ "path": sibling.to_string_lossy() }),
            GooseMode::Auto,
        )
        .await;
        assert_eq!(decision(&results), Some(&InspectionAction::Deny));
    }

    #[tokio::test]
    async fn system_mutation_shell_command_is_denied_in_auto_mode() {
        let root = workspace();
        let (inspector, session_id) = fixture(root.path()).await;
        let results = inspect(
            &inspector,
            &session_id,
            "shell",
            object!({ "command": r"reg add HKLM\Software\Evil /v A /d 1" }),
            GooseMode::Auto,
        )
        .await;
        assert_eq!(decision(&results), Some(&InspectionAction::Deny));
    }

    #[tokio::test]
    async fn an_unrecognised_shell_command_is_refused_when_no_one_can_approve() {
        let root = workspace();
        let (inspector, session_id) = fixture(root.path()).await;
        let results = inspect(
            &inspector,
            &session_id,
            "shell",
            object!({ "command": "some-unknown-binary --flag" }),
            GooseMode::Auto,
        )
        .await;
        assert_eq!(decision(&results), Some(&InspectionAction::Deny));
    }

    #[tokio::test]
    async fn an_unrecognised_shell_command_asks_in_an_interactive_mode() {
        let root = workspace();
        let (inspector, session_id) = fixture(root.path()).await;
        let results = inspect(
            &inspector,
            &session_id,
            "shell",
            object!({ "command": "some-unknown-binary --flag" }),
            GooseMode::SmartApprove,
        )
        .await;
        assert!(matches!(
            decision(&results),
            Some(InspectionAction::RequireApproval(_))
        ));
    }

    #[tokio::test]
    async fn workspace_build_is_not_restricted_in_auto_mode() {
        let root = workspace();
        let (inspector, session_id) = fixture(root.path()).await;
        let results = inspect(
            &inspector,
            &session_id,
            "shell",
            object!({ "command": "cargo test -p goose" }),
            GooseMode::Auto,
        )
        .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn third_party_tool_writing_outside_workspace_is_denied() {
        let root = workspace();
        let outside = workspace();
        let outside_file = outside.path().join("secret.txt");
        std::fs::write(&outside_file, "secret").unwrap();

        let (inspector, session_id) = fixture(root.path()).await;
        let results = inspect(
            &inspector,
            &session_id,
            "mcp__files__write",
            object!({ "path": outside_file.to_string_lossy() }),
            GooseMode::Auto,
        )
        .await;
        assert_eq!(decision(&results), Some(&InspectionAction::Deny));
    }

    #[tokio::test]
    async fn third_party_tool_inside_workspace_defers_to_goose_mode() {
        let root = workspace();
        let (inspector, session_id) = fixture(root.path()).await;
        let results = inspect(
            &inspector,
            &session_id,
            "mcp__files__write",
            object!({ "path": "inside.txt" }),
            GooseMode::Auto,
        )
        .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn image_url_is_not_treated_as_a_path() {
        let root = workspace();
        let (inspector, session_id) = fixture(root.path()).await;
        let results = inspect(
            &inspector,
            &session_id,
            "read_image",
            object!({ "source": "https://example.com/a.png" }),
            GooseMode::Auto,
        )
        .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn missing_session_disables_path_enforcement() {
        let root = workspace();
        let (manager, _) = harness(root.path()).await;
        let inspector = CapabilityInspector::new(manager);
        let results = inspect(
            &inspector,
            "no-such-session",
            "write",
            object!({ "path": "C:\\Windows\\System32\\drivers\\etc\\hosts" }),
            GooseMode::Auto,
        )
        .await;
        assert!(results.is_empty());
    }
}

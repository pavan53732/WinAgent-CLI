//! Git Developer Tools for WinAgent
//!
//! Exposes structured git status, diff inspection, commit generation, and commit logs
//! as native first-class MCP tools for the agent.

use crate::git::{
    commit_everything, commit_paths, get_diff, get_recent_log, get_repo_state, plan_commit,
    reset_session_baseline, session_baseline,
};
use rmcp::model::{Annotations, CallToolResult, ContentBlock, TextContent};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

fn visible_text(text: impl Into<String>) -> ContentBlock {
    ContentBlock::Text(
        TextContent::new(text).with_annotations(Annotations::default().with_priority(0.0)),
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GitStatusParams {
    #[schemars(
        description = "Optional path within the repository. Defaults to current working directory."
    )]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GitDiffParams {
    #[schemars(
        description = "If true, show staged changes (--staged). Default is false (unstaged changes)."
    )]
    pub staged: Option<bool>,
    #[schemars(description = "Optional file path to limit the diff to.")]
    pub file_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GitCommitParams {
    #[schemars(description = "The commit message describing the changes and evidence.")]
    pub message: String,
    #[schemars(
        description = "Stage the entire repository and commit everything, including work that \
                       predates this session. Only use this when the user explicitly asks for it; \
                       it will consume unrelated staged changes."
    )]
    pub stage_all: Option<bool>,
    #[schemars(
        description = "Optional explicit list of files to commit. When omitted, the files this \
                       session changed are derived from the session baseline."
    )]
    pub files: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GitLogParams {
    #[schemars(description = "Number of commits to retrieve. Default is 10.")]
    pub count: Option<usize>,
}

pub struct GitTool;

impl GitTool {
    pub fn new() -> Self {
        Self
    }

    fn resolve_dir(&self, explicit_path: Option<&str>, working_dir: Option<&Path>) -> PathBuf {
        if let Some(p) = explicit_path {
            PathBuf::from(p)
        } else if let Some(cwd) = working_dir {
            cwd.to_path_buf()
        } else {
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        }
    }

    pub async fn status(
        &self,
        params: GitStatusParams,
        working_dir: Option<&Path>,
    ) -> CallToolResult {
        let dir = self.resolve_dir(params.path.as_deref(), working_dir);
        match get_repo_state(&dir).await {
            Ok(state) => {
                if !state.is_repo {
                    return CallToolResult::error(vec![visible_text(
                        "Directory is not inside a Git repository.",
                    )]);
                }

                let mut out = format!("{}\n\n", state.summary);
                if !state.staged_files.is_empty() {
                    out.push_str("Staged Changes:\n");
                    for f in &state.staged_files {
                        out.push_str(&format!("  {} {}\n", f.status, f.path));
                    }
                    out.push('\n');
                }
                if !state.unstaged_files.is_empty() {
                    out.push_str("Unstaged Changes:\n");
                    for f in &state.unstaged_files {
                        out.push_str(&format!("  {} {}\n", f.status, f.path));
                    }
                    out.push('\n');
                }
                if !state.untracked_files.is_empty() {
                    out.push_str("Untracked Files:\n");
                    for f in &state.untracked_files {
                        out.push_str(&format!("  ?? {}\n", f));
                    }
                    out.push('\n');
                }
                if !state.conflicted_files.is_empty() {
                    out.push_str("CONFLICTED Files:\n");
                    for f in &state.conflicted_files {
                        out.push_str(&format!("  UU {}\n", f));
                    }
                    out.push('\n');
                }
                if state.is_clean {
                    out.push_str("Working tree clean — nothing to commit.\n");
                }
                CallToolResult::success(vec![visible_text(out)])
            }
            Err(e) => CallToolResult::error(vec![visible_text(format!(
                "Failed to read git status: {e}"
            ))]),
        }
    }

    pub async fn diff(&self, params: GitDiffParams, working_dir: Option<&Path>) -> CallToolResult {
        let dir = self.resolve_dir(None, working_dir);
        let staged = params.staged.unwrap_or(false);
        match get_diff(&dir, staged, params.file_path.as_deref()).await {
            Ok(diff) => CallToolResult::success(vec![visible_text(diff)]),
            Err(e) => CallToolResult::error(vec![visible_text(format!(
                "Failed to retrieve git diff: {e}"
            ))]),
        }
    }

    pub async fn commit(
        &self,
        params: GitCommitParams,
        working_dir: Option<&Path>,
        session_id: &str,
    ) -> CallToolResult {
        let dir = self.resolve_dir(None, working_dir);

        if let Some(files) = &params.files {
            let mut selected = Vec::new();
            for file in files {
                match self.validate_commit_path(file, working_dir, &dir) {
                    Ok(path) => selected.push(path),
                    Err(e) => {
                        return CallToolResult::error(vec![visible_text(format!(
                            "Refusing to commit {file}: {e}"
                        ))])
                    }
                }
            }
            return Self::finish_commit(commit_paths(&dir, &params.message, &selected).await, &dir);
        }

        if params.stage_all.unwrap_or(false) {
            let output = commit_everything(&dir, &params.message).await;
            if output.is_ok() {
                reset_session_baseline(session_id);
            }
            return Self::finish_commit(output, &dir);
        }

        let baseline = match session_baseline(session_id, &dir).await {
            Ok(baseline) => baseline,
            Err(e) => {
                return CallToolResult::error(vec![visible_text(format!(
                    "No session baseline is available for this repository: {e}. Pass an explicit \
                     `files` list, or set stage_all only if the whole repository should be committed."
                ))])
            }
        };

        let plan = match plan_commit(&dir, &baseline).await {
            Ok(plan) => plan,
            Err(e) => {
                return CallToolResult::error(vec![visible_text(format!(
                    "Failed to plan the commit: {e}"
                ))])
            }
        };

        if plan.is_empty() {
            return CallToolResult::error(vec![visible_text(format!(
                "Nothing to commit: no file changed since the session baseline.\n{}",
                plan.describe()
            ))]);
        }

        let output = commit_paths(&dir, &params.message, &plan.agent_owned).await;
        if output.is_ok() {
            reset_session_baseline(session_id);
        }
        Self::finish_commit_with_context(output, &dir, Some(plan.describe()))
    }

    /// A commit target must resolve inside the workspace, and inside the
    /// repository the session is operating on.
    fn validate_commit_path(
        &self,
        file: &str,
        working_dir: Option<&Path>,
        repo_dir: &Path,
    ) -> Result<String, String> {
        let candidate = Path::new(file);
        if let Some(root) = working_dir {
            crate::permission::path_security::resolve_and_validate_workspace_path(candidate, root)
                .map_err(|e| e.to_string())?;
        }
        let resolved = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            repo_dir.join(candidate)
        };
        if !resolved.starts_with(repo_dir) {
            return Err(format!(
                "{} is outside the repository at {}",
                resolved.display(),
                repo_dir.display()
            ));
        }
        Ok(resolved
            .strip_prefix(repo_dir)
            .unwrap_or(&resolved)
            .to_string_lossy()
            .replace('\\', "/"))
    }

    fn finish_commit(output: Result<String, anyhow::Error>, _dir: &Path) -> CallToolResult {
        Self::finish_commit_with_context(output, _dir, None)
    }

    fn finish_commit_with_context(
        output: Result<String, anyhow::Error>,
        _dir: &Path,
        context: Option<String>,
    ) -> CallToolResult {
        match output {
            Ok(commit_output) => {
                let mut message = format!("Commit successful:\n{commit_output}");
                if let Some(context) = context {
                    message.push_str(&format!("\n\n{context}"));
                }
                CallToolResult::success(vec![visible_text(message)])
            }
            Err(e) => {
                CallToolResult::error(vec![visible_text(format!("Failed to create commit: {e}"))])
            }
        }
    }

    pub async fn log(&self, params: GitLogParams, working_dir: Option<&Path>) -> CallToolResult {
        let dir = self.resolve_dir(None, working_dir);
        let count = params.count.unwrap_or(10);
        match get_recent_log(&dir, count).await {
            Ok(log) => CallToolResult::success(vec![visible_text(log)]),
            Err(e) => CallToolResult::error(vec![visible_text(format!(
                "Failed to retrieve git log: {e}"
            ))]),
        }
    }
}

impl Default for GitTool {
    fn default() -> Self {
        Self::new()
    }
}

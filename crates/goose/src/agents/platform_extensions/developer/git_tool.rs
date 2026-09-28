//! Git Developer Tools for WinAgent
//!
//! Exposes structured git status, diff inspection, commit generation, and commit logs
//! as native first-class MCP tools for the agent.

use crate::git::{commit_changes, get_diff, get_recent_log, get_repo_state, stage_files};
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
        description = "If true, stage all modified and untracked files (git add -A) before committing. Default is false."
    )]
    pub stage_all: Option<bool>,
    #[schemars(description = "Optional specific files to stage before committing.")]
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
    ) -> CallToolResult {
        let dir = self.resolve_dir(None, working_dir);
        let stage_all = params.stage_all.unwrap_or(false);

        if let Some(files) = &params.files {
            let file_refs: Vec<&str> = files.iter().map(|s| s.as_str()).collect();
            if let Err(e) = stage_files(&dir, &file_refs).await {
                return CallToolResult::error(vec![visible_text(format!(
                    "Failed staging files: {e}"
                ))]);
            }
        }

        match commit_changes(&dir, &params.message, stage_all).await {
            Ok(output) => {
                CallToolResult::success(vec![visible_text(format!("Commit successful:\n{output}"))])
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

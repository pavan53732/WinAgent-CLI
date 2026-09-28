//! First-class Git & Repository State Engine for WinAgent
//!
//! Provides deterministic inspection of repository state, branch information,
//! working tree status, staged/unstaged changes, untracked files, and conflicts.
//! Enables capturing repository snapshots and computing working tree deltas for
//! bounded autonomous repair loops and verifiable evidence generation.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;

#[cfg(windows)]
use crate::subprocess::SubprocessExt;

/// File change status in working tree or index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitFileChange {
    pub path: String,
    pub status: String,
    pub is_staged: bool,
}

/// Comprehensive structured snapshot of repository state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitRepoState {
    pub is_repo: bool,
    pub root_dir: Option<PathBuf>,
    pub branch: Option<String>,
    pub head_sha: Option<String>,
    pub head_commit_message: Option<String>,
    pub is_detached: bool,
    pub is_clean: bool,
    pub staged_files: Vec<GitFileChange>,
    pub unstaged_files: Vec<GitFileChange>,
    pub untracked_files: Vec<String>,
    pub conflicted_files: Vec<String>,
    pub ahead_count: usize,
    pub behind_count: usize,
    pub summary: String,
}

/// Point-in-time snapshot of the working tree used for bounded repair verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositorySnapshot {
    pub timestamp: DateTime<Utc>,
    pub head_sha: String,
    pub branch: String,
    pub dirty_files: Vec<String>,
    pub diff_stat: String,
}

/// Evidence delta between a baseline snapshot and current working tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkingTreeDelta {
    pub baseline_head: String,
    pub current_head: String,
    pub files_modified: Vec<String>,
    pub files_added: Vec<String>,
    pub files_deleted: Vec<String>,
    pub has_new_evidence: bool,
    pub patch_stat: String,
    pub evidence_summary: String,
}

/// Execute a git command within a repository directory with timeout and no-window containment.
pub async fn run_git_cmd(repo_dir: &Path, args: &[&str]) -> Result<String> {
    let mut cmd = Command::new("git");
    cmd.args(args);
    cmd.current_dir(repo_dir);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    #[cfg(windows)]
    {
        cmd.set_no_window();
    }

    let child = cmd
        .spawn()
        .map_err(|e| anyhow!("Failed to spawn git command: {e}"))?;

    let output = tokio::time::timeout(Duration::from_secs(15), child.wait_with_output())
        .await
        .map_err(|_| anyhow!("Git command timed out after 15 seconds"))?
        .map_err(|e| anyhow!("Failed waiting for git output: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(anyhow!(
            "Git command failed (exit code {:?}): {stderr}",
            output.status.code()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Discover the root directory of the current git repository.
pub async fn find_repo_root(start_dir: &Path) -> Result<PathBuf> {
    let out = run_git_cmd(start_dir, &["rev-parse", "--show-toplevel"]).await?;
    let path = PathBuf::from(out);
    if path.is_dir() {
        Ok(path)
    } else {
        Err(anyhow!(
            "Resolved git root is not a valid directory: {}",
            path.display()
        ))
    }
}

/// Query complete repository state deterministically.
pub async fn get_repo_state(dir: &Path) -> Result<GitRepoState> {
    let root_dir = match find_repo_root(dir).await {
        Ok(root) => root,
        Err(_) => {
            return Ok(GitRepoState {
                is_repo: false,
                root_dir: None,
                branch: None,
                head_sha: None,
                head_commit_message: None,
                is_detached: false,
                is_clean: true,
                staged_files: Vec::new(),
                unstaged_files: Vec::new(),
                untracked_files: Vec::new(),
                conflicted_files: Vec::new(),
                ahead_count: 0,
                behind_count: 0,
                summary: "Directory is not inside a Git repository".to_string(),
            });
        }
    };

    // 1. Branch name & detached state
    let branch_out = run_git_cmd(&root_dir, &["branch", "--show-current"])
        .await
        .unwrap_or_default();
    let is_detached = branch_out.is_empty();
    let branch = if is_detached {
        run_git_cmd(&root_dir, &["rev-parse", "--short", "HEAD"])
            .await
            .ok()
    } else {
        Some(branch_out)
    };

    // 2. HEAD commit info
    let head_sha = run_git_cmd(&root_dir, &["rev-parse", "HEAD"]).await.ok();
    let head_commit_message = run_git_cmd(&root_dir, &["log", "-1", "--format=%s"])
        .await
        .ok();

    // 3. Status porcelain v1 inspection
    let porcelain = run_git_cmd(&root_dir, &["status", "--porcelain=v1"])
        .await
        .unwrap_or_default();

    let mut staged_files = Vec::new();
    let mut unstaged_files = Vec::new();
    let mut untracked_files = Vec::new();
    let mut conflicted_files = Vec::new();

    for line in porcelain.lines() {
        if line.len() < 3 {
            continue;
        }
        let index_char = &line[0..1];
        let work_char = &line[1..2];
        let file_path = line[3..].trim().to_string();

        if index_char == "U"
            || work_char == "U"
            || (index_char == "A" && work_char == "A")
            || (index_char == "D" && work_char == "D")
        {
            conflicted_files.push(file_path.clone());
            continue;
        }

        if index_char == "?" && work_char == "?" {
            untracked_files.push(file_path);
            continue;
        }

        if index_char != " " && index_char != "?" {
            staged_files.push(GitFileChange {
                path: file_path.clone(),
                status: index_char.to_string(),
                is_staged: true,
            });
        }

        if work_char != " " && work_char != "?" {
            unstaged_files.push(GitFileChange {
                path: file_path,
                status: work_char.to_string(),
                is_staged: false,
            });
        }
    }

    let is_clean = staged_files.is_empty()
        && unstaged_files.is_empty()
        && untracked_files.is_empty()
        && conflicted_files.is_empty();

    // 4. Ahead / behind counts relative to upstream
    let mut ahead_count = 0;
    let mut behind_count = 0;
    if let Ok(rev_list) = run_git_cmd(
        &root_dir,
        &["rev-list", "--left-right", "--count", "HEAD...@{upstream}"],
    )
    .await
    {
        let parts: Vec<&str> = rev_list.split_whitespace().collect();
        if parts.len() == 2 {
            ahead_count = parts[0].parse().unwrap_or(0);
            behind_count = parts[1].parse().unwrap_or(0);
        }
    }

    // Build human-readable summary
    let mut summary = format!(
        "Branch: {} | HEAD: {} | State: {}",
        branch.as_deref().unwrap_or("unknown"),
        head_sha
            .as_deref()
            .and_then(|s| s.get(0..7))
            .unwrap_or("none"),
        if is_clean { "Clean" } else { "Dirty" }
    );
    if ahead_count > 0 || behind_count > 0 {
        summary.push_str(&format!(
            " (Ahead: {}, Behind: {})",
            ahead_count, behind_count
        ));
    }
    if !staged_files.is_empty() {
        summary.push_str(&format!(" | Staged: {}", staged_files.len()));
    }
    if !unstaged_files.is_empty() {
        summary.push_str(&format!(" | Unstaged: {}", unstaged_files.len()));
    }
    if !untracked_files.is_empty() {
        summary.push_str(&format!(" | Untracked: {}", untracked_files.len()));
    }
    if !conflicted_files.is_empty() {
        summary.push_str(&format!(" | CONFLICTS: {}", conflicted_files.len()));
    }

    Ok(GitRepoState {
        is_repo: true,
        root_dir: Some(root_dir),
        branch,
        head_sha,
        head_commit_message,
        is_detached,
        is_clean,
        staged_files,
        unstaged_files,
        untracked_files,
        conflicted_files,
        ahead_count,
        behind_count,
        summary,
    })
}

/// Capture snapshot of working tree for bounded repair enforcement.
pub async fn capture_snapshot(repo_dir: &Path) -> Result<RepositorySnapshot> {
    let state = get_repo_state(repo_dir).await?;
    if !state.is_repo {
        return Err(anyhow!(
            "Cannot capture snapshot outside of a git repository"
        ));
    }

    let head_sha = state.head_sha.unwrap_or_else(|| "HEAD".to_string());
    let branch = state.branch.unwrap_or_else(|| "detached".to_string());

    let mut dirty_files = Vec::new();
    for s in &state.staged_files {
        if !dirty_files.contains(&s.path) {
            dirty_files.push(s.path.clone());
        }
    }
    for u in &state.unstaged_files {
        if !dirty_files.contains(&u.path) {
            dirty_files.push(u.path.clone());
        }
    }
    for t in &state.untracked_files {
        if !dirty_files.contains(t) {
            dirty_files.push(t.clone());
        }
    }

    let diff_stat = run_git_cmd(repo_dir, &["diff", "--stat"])
        .await
        .unwrap_or_default();

    Ok(RepositorySnapshot {
        timestamp: Utc::now(),
        head_sha,
        branch,
        dirty_files,
        diff_stat,
    })
}

/// Compute evidence delta between baseline snapshot and current state.
pub async fn compute_delta(
    baseline: &RepositorySnapshot,
    repo_dir: &Path,
) -> Result<WorkingTreeDelta> {
    let current = capture_snapshot(repo_dir).await?;

    let mut files_modified = Vec::new();
    let mut files_added = Vec::new();
    let mut files_deleted = Vec::new();

    // Check newly dirty or altered files
    for file in &current.dirty_files {
        if !baseline.dirty_files.contains(file) {
            files_added.push(file.clone());
        } else {
            files_modified.push(file.clone());
        }
    }

    for file in &baseline.dirty_files {
        if !current.dirty_files.contains(file) {
            files_deleted.push(file.clone());
        }
    }

    let patch_stat = run_git_cmd(repo_dir, &["diff", "--stat"])
        .await
        .unwrap_or_default();
    let head_changed = baseline.head_sha != current.head_sha;
    let diff_stat_changed = baseline.diff_stat != current.diff_stat;
    let files_changed = !files_added.is_empty() || !files_deleted.is_empty();

    let has_new_evidence = head_changed || diff_stat_changed || files_changed;

    let evidence_summary = if !has_new_evidence {
        "NO NEW EVIDENCE: Working tree and HEAD are identical to the baseline snapshot.".to_string()
    } else {
        format!(
            "Evidence generated: {} modified, {} added, {} deleted files. Patch stat:\n{}",
            files_modified.len(),
            files_added.len(),
            files_deleted.len(),
            patch_stat
        )
    };

    Ok(WorkingTreeDelta {
        baseline_head: baseline.head_sha.clone(),
        current_head: current.head_sha,
        files_modified,
        files_added,
        files_deleted,
        has_new_evidence,
        patch_stat,
        evidence_summary,
    })
}

/// Retrieve working tree or staged diff, optionally constrained to a single file.
pub async fn get_diff(repo_dir: &Path, staged: bool, file_path: Option<&str>) -> Result<String> {
    let mut args = vec!["diff"];
    if staged {
        args.push("--staged");
    }
    if let Some(path) = file_path {
        args.push("--");
        args.push(path);
    }

    let diff = run_git_cmd(repo_dir, &args).await?;
    if diff.is_empty() {
        Ok(if staged {
            "No staged changes"
        } else {
            "No working tree changes"
        }
        .to_string())
    } else {
        Ok(diff)
    }
}

/// Stage files into git index.
pub async fn stage_files(repo_dir: &Path, paths: &[&str]) -> Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    let mut args = vec!["add", "--"];
    args.extend_from_slice(paths);
    run_git_cmd(repo_dir, &args).await?;
    Ok(())
}

/// Create a git commit with the specified message.
pub async fn commit_changes(repo_dir: &Path, message: &str, stage_all: bool) -> Result<String> {
    if stage_all {
        run_git_cmd(repo_dir, &["add", "-A"]).await?;
    }
    run_git_cmd(repo_dir, &["commit", "-m", message]).await
}

/// Retrieve recent commit history.
pub async fn get_recent_log(repo_dir: &Path, count: usize) -> Result<String> {
    let n = format!("-n{}", count);
    run_git_cmd(repo_dir, &["log", &n, "--oneline", "--decorate"]).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_git_repo_state_detection() {
        let current_dir = std::env::current_dir().expect("must get current dir");
        let state = get_repo_state(&current_dir)
            .await
            .expect("must get repo state");
        assert!(state.is_repo, "Current workspace must be a git repository");
        assert!(state.branch.is_some(), "Must detect current branch");
        assert!(state.head_sha.is_some(), "Must detect HEAD sha");
        assert!(!state.summary.is_empty(), "Must provide state summary");
    }

    #[tokio::test]
    async fn test_repository_snapshot_and_delta() {
        let current_dir = std::env::current_dir().expect("must get current dir");
        let baseline = capture_snapshot(&current_dir)
            .await
            .expect("snapshot must succeed");
        assert!(!baseline.head_sha.is_empty());

        let delta = compute_delta(&baseline, &current_dir)
            .await
            .expect("delta must succeed");
        assert_eq!(delta.baseline_head, delta.current_head);
    }
}

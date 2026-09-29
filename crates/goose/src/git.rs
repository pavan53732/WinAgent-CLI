//! First-class Git and repository state engine for WinAgent.
//!
//! Repository state is described by *content identity*, not by line counts or
//! diff statistics: two different patches routinely share an identical
//! `--stat` summary, and an untracked file can change without its path set
//! changing. Every snapshot therefore carries a fingerprint that changes
//! whenever the repository's actual content changes, and that fingerprint is
//! what bounded repair decisions are based on.

use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

const GIT_TIMEOUT: Duration = Duration::from_secs(15);

/// Upper bound on the bytes hashed when fingerprinting untracked content.
///
/// Beyond this, fingerprinting stops and the partial result is mixed with the
/// full sorted path list, so the fingerprint stays deterministic without
/// reading an unbounded amount of disk.
const MAX_FINGERPRINT_BYTES: u64 = 64 * 1024 * 1024;

const ABSENT: &str = "<absent>";
const TRUNCATED: &str = "<truncated>";

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

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

/// Content identity of a single path that is not clean.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileFingerprint {
    pub path: String,
    /// Porcelain `XY` status code, e.g. `" M"`, `"M "`, `"??"`.
    pub status: String,
    /// Git blob id of the current index entry, empty when the path is untracked.
    pub index_blob: String,
    /// Hash of the working tree bytes, or [`ABSENT`] when the file is gone.
    pub content_hash: String,
}

/// Deterministic fingerprint of everything that can constitute evidence.
///
/// `fingerprint()` is the authoritative "did anything actually change?" signal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepositoryEvidence {
    pub head_sha: String,
    /// `git write-tree` output: identity of the staged index.
    pub index_tree: String,
    /// Hash of `git diff HEAD --binary --full-index`: exact tracked content.
    pub tracked_diff_hash: String,
    /// Size of that diff in bytes, used to bound repair patch size.
    pub tracked_diff_size: u64,
    /// Hash of `git status --porcelain=v1 -z -uall`: which paths are non-clean.
    pub status_fingerprint: String,
    /// Hash over the path and content hash of every non-clean path.
    pub path_content_hash: String,
}

impl RepositoryEvidence {
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        for part in [
            &self.head_sha,
            &self.index_tree,
            &self.tracked_diff_hash,
            &self.status_fingerprint,
            &self.path_content_hash,
        ] {
            hasher.update(part.as_bytes());
            hasher.update([0u8]);
        }
        hex(&hasher.finalize())
    }
}

/// Point-in-time snapshot of the working tree used for bounded repair verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositorySnapshot {
    pub timestamp: DateTime<Utc>,
    pub head_sha: String,
    pub branch: String,
    pub dirty_files: Vec<String>,
    pub diff_stat: String,
    pub evidence: RepositoryEvidence,
    pub fingerprints: Vec<FileFingerprint>,
}

impl RepositorySnapshot {
    pub fn fingerprint(&self) -> String {
        self.evidence.fingerprint()
    }

    fn fingerprint_of(&self, path: &str) -> Option<&FileFingerprint> {
        self.fingerprints.iter().find(|f| f.path == path)
    }
}

/// Evidence delta between a baseline snapshot and the current working tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkingTreeDelta {
    pub baseline_head: String,
    pub current_head: String,
    pub files_modified: Vec<String>,
    pub files_added: Vec<String>,
    pub files_deleted: Vec<String>,
    /// Paths that were already dirty at baseline and are unchanged.
    pub files_unchanged: Vec<String>,
    pub has_new_evidence: bool,
    pub patch_stat: String,
    pub current_fingerprint: String,
    pub patch_size_bytes: u64,
    pub evidence_summary: String,
}

/// What a commit would touch, relative to a baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitPlan {
    /// Paths whose content or index entry changed since the baseline.
    pub agent_owned: Vec<String>,
    /// Paths that were already dirty at baseline and are still unchanged.
    pub pre_existing_dirty: Vec<String>,
    /// Paths already staged at baseline; a commit must not consume these.
    pub pre_existing_staged: Vec<String>,
}

impl CommitPlan {
    pub fn is_empty(&self) -> bool {
        self.agent_owned.is_empty()
    }

    pub fn describe(&self) -> String {
        let mut lines = vec![format!(
            "Agent-owned changes: {}",
            if self.agent_owned.is_empty() {
                "none".to_string()
            } else {
                self.agent_owned.join(", ")
            }
        )];
        if !self.pre_existing_dirty.is_empty() {
            lines.push(format!(
                "Pre-existing uncommitted changes (left untouched): {}",
                self.pre_existing_dirty.join(", ")
            ));
        }
        if !self.pre_existing_staged.is_empty() {
            lines.push(format!(
                "Pre-existing staged changes (not included): {}",
                self.pre_existing_staged.join(", ")
            ));
        }
        lines.join("\n")
    }
}

async fn run_git_output(repo_dir: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let mut cmd = Command::new("git");
    cmd.args([
        "-c",
        "safe.bareRepository=explicit",
        "-c",
        "core.fsmonitor=false",
    ]);
    cmd.args(args);
    cmd.current_dir(repo_dir);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.stdin(Stdio::null());
    crate::subprocess::configure_subprocess(&mut cmd);

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("failed to spawn git: {e}"))?;

    #[cfg(windows)]
    if let Some(pid) = child.id() {
        if let Err(e) = crate::subprocess::assign_to_global_job(pid) {
            tracing::warn!("failed to assign git process {pid} to the Job Object: {e}");
        }
    }

    let mut stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to capture git stdout"))?;
    let mut stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("failed to capture git stderr"))?;

    let stdout_task = tokio::spawn(async move {
        let mut buffer = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buffer).await;
        buffer
    });
    let stderr_task = tokio::spawn(async move {
        let mut buffer = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buffer).await;
        buffer
    });

    let status = match tokio::time::timeout(GIT_TIMEOUT, child.wait()).await {
        Ok(result) => result.map_err(|e| anyhow!("failed waiting for git: {e}"))?,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            bail!(
                "git command timed out after {} seconds",
                GIT_TIMEOUT.as_secs()
            );
        }
    };

    let stdout = stdout_task.await.unwrap_or_default();
    let stderr = stderr_task.await.unwrap_or_default();

    if !status.success() {
        bail!(
            "git command failed (exit code {:?}): {}",
            status.code(),
            String::from_utf8_lossy(&stderr).trim()
        );
    }

    Ok(stdout)
}

/// Execute a git command within a repository directory.
pub async fn run_git_cmd(repo_dir: &Path, args: &[&str]) -> Result<String> {
    let stdout = run_git_output(repo_dir, args).await?;
    Ok(String::from_utf8_lossy(&stdout).trim().to_string())
}

/// Discover the root directory of the current git repository.
pub async fn find_repo_root(start_dir: &Path) -> Result<PathBuf> {
    let out = run_git_cmd(start_dir, &["rev-parse", "--show-toplevel"]).await?;
    let path = PathBuf::from(out);
    if path.is_dir() {
        Ok(path)
    } else {
        Err(anyhow!(
            "resolved git root is not a valid directory: {}",
            path.display()
        ))
    }
}

/// Parse `git status --porcelain=v1 -z -uall` into `(xy, path)` pairs.
fn parse_porcelain_z(bytes: &[u8]) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let mut fields: Vec<&[u8]> = bytes.split(|byte| *byte == 0).collect();
    fields.retain(|field| !field.is_empty());

    let mut index = 0;
    while index < fields.len() {
        let field = fields[index];
        if field.len() < 4 {
            index += 1;
            continue;
        }
        let status = String::from_utf8_lossy(&field[0..2]).to_string();
        let path = String::from_utf8_lossy(&field[3..]).to_string();
        // Renames and copies emit the original path in the following field.
        if field[0] == b'R' || field[0] == b'C' || field[1] == b'R' || field[1] == b'C' {
            index += 1;
        }
        entries.push((status, path));
        index += 1;
    }
    entries
}

/// Parse `git ls-files -s -z` into `path -> index blob`.
fn parse_index_entries(bytes: &[u8]) -> BTreeMap<String, String> {
    let mut entries = BTreeMap::new();
    for field in bytes.split(|byte| *byte == 0) {
        if field.is_empty() {
            continue;
        }
        let text = String::from_utf8_lossy(field);
        // "<mode> <blob> <stage>\t<path>"
        let Some((meta, path)) = text.split_once('\t') else {
            continue;
        };
        let Some(blob) = meta.split_whitespace().nth(1) else {
            continue;
        };
        entries.insert(path.to_string(), blob.to_string());
    }
    entries
}

fn hash_file(path: &Path, budget: &mut u64) -> String {
    let Ok(metadata) = std::fs::metadata(path) else {
        return ABSENT.to_string();
    };
    if *budget < metadata.len() {
        return TRUNCATED.to_string();
    }
    *budget -= metadata.len();

    let mut hasher = Sha256::new();
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return ABSENT.to_string(),
    };
    let mut buffer = [0u8; 8192];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(_) => return ABSENT.to_string(),
        }
    }
    hex(&hasher.finalize())
}

async fn capture_evidence(repo_dir: &Path) -> Result<RepositoryEvidence> {
    let head_sha = run_git_cmd(repo_dir, &["rev-parse", "HEAD"])
        .await
        .unwrap_or_default();
    let index_tree = run_git_cmd(repo_dir, &["write-tree"])
        .await
        .unwrap_or_default();
    let tracked_diff = run_git_output(
        repo_dir,
        &["diff", "HEAD", "--binary", "--full-index", "--no-color"],
    )
    .await
    .unwrap_or_default();
    let status = run_git_output(repo_dir, &["status", "--porcelain=v1", "-z", "-uall"])
        .await
        .unwrap_or_default();

    let tracked_diff_hash = hex(&Sha256::digest(&tracked_diff));
    let status_fingerprint = hex(&Sha256::digest(&status));

    let mut budget = MAX_FINGERPRINT_BYTES;
    let mut path_hasher = Sha256::new();
    let mut paths: Vec<String> = parse_porcelain_z(&status)
        .into_iter()
        .map(|(_, path)| path)
        .collect();
    paths.sort();
    for path in &paths {
        path_hasher.update(path.as_bytes());
        path_hasher.update([0u8]);
        path_hasher.update(hash_file(&repo_dir.join(path), &mut budget).as_bytes());
        path_hasher.update([0u8]);
    }

    Ok(RepositoryEvidence {
        head_sha,
        index_tree,
        tracked_diff_hash,
        tracked_diff_size: tracked_diff.len() as u64,
        status_fingerprint,
        path_content_hash: hex(&path_hasher.finalize()),
    })
}

async fn capture_fingerprints(repo_dir: &Path) -> Result<Vec<FileFingerprint>> {
    let status = run_git_output(repo_dir, &["status", "--porcelain=v1", "-z", "-uall"]).await?;
    let index = parse_index_entries(
        &run_git_output(repo_dir, &["ls-files", "-s", "-z"])
            .await
            .unwrap_or_default(),
    );

    let mut budget = MAX_FINGERPRINT_BYTES;
    let mut fingerprints: Vec<FileFingerprint> = parse_porcelain_z(&status)
        .into_iter()
        .map(|(status, path)| FileFingerprint {
            content_hash: hash_file(&repo_dir.join(&path), &mut budget),
            index_blob: index.get(&path).cloned().unwrap_or_default(),
            path,
            status,
        })
        .collect();
    fingerprints.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(fingerprints)
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

    let head_sha = run_git_cmd(&root_dir, &["rev-parse", "HEAD"]).await.ok();
    let head_commit_message = run_git_cmd(&root_dir, &["log", "-1", "--format=%s"])
        .await
        .ok();

    let porcelain = run_git_cmd(&root_dir, &["status", "--porcelain=v1"])
        .await
        .unwrap_or_default();

    let mut staged_files = Vec::new();
    let mut unstaged_files = Vec::new();
    let mut untracked_files = Vec::new();
    let mut conflicted_files = Vec::new();

    for line in porcelain.lines() {
        // Porcelain v1 is "XY <path>"; the status codes are ASCII, so read them
        // as bytes rather than slicing a UTF-8 string at arbitrary offsets.
        let bytes = line.as_bytes();
        if bytes.len() < 4 {
            continue;
        }
        let index_char = bytes[0] as char;
        let work_char = bytes[1] as char;
        // The two status characters and the space are ASCII, so byte 3 is
        // always a character boundary; `get` keeps it panic-free regardless.
        let file_path = line.get(3..).unwrap_or_default().trim().to_string();

        if index_char == 'U'
            || work_char == 'U'
            || (index_char == 'A' && work_char == 'A')
            || (index_char == 'D' && work_char == 'D')
        {
            conflicted_files.push(file_path.clone());
            continue;
        }

        if index_char == '?' && work_char == '?' {
            untracked_files.push(file_path);
            continue;
        }

        if index_char != ' ' && index_char != '?' {
            staged_files.push(GitFileChange {
                path: file_path.clone(),
                status: index_char.to_string(),
                is_staged: true,
            });
        }

        if work_char != ' ' && work_char != '?' {
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

/// Capture a snapshot of the working tree for bounded repair verification.
pub async fn capture_snapshot(repo_dir: &Path) -> Result<RepositorySnapshot> {
    let state = get_repo_state(repo_dir).await?;
    if !state.is_repo {
        bail!("cannot capture a snapshot outside a git repository");
    }

    let head_sha = state.head_sha.clone().unwrap_or_else(|| "HEAD".to_string());
    let branch = state
        .branch
        .clone()
        .unwrap_or_else(|| "detached".to_string());
    let fingerprints = capture_fingerprints(repo_dir).await?;
    let dirty_files = fingerprints
        .iter()
        .map(|fingerprint| fingerprint.path.clone())
        .collect();
    let diff_stat = run_git_cmd(repo_dir, &["diff", "--stat"])
        .await
        .unwrap_or_default();

    Ok(RepositorySnapshot {
        timestamp: Utc::now(),
        head_sha,
        branch,
        dirty_files,
        diff_stat,
        evidence: capture_evidence(repo_dir).await?,
        fingerprints,
    })
}

/// Compute the evidence delta between a baseline snapshot and the current tree.
pub async fn compute_delta(
    baseline: &RepositorySnapshot,
    repo_dir: &Path,
) -> Result<WorkingTreeDelta> {
    let current = capture_snapshot(repo_dir).await?;

    let mut files_modified = Vec::new();
    let mut files_added = Vec::new();
    let mut files_deleted = Vec::new();
    let mut files_unchanged = Vec::new();

    for fingerprint in &current.fingerprints {
        let previous = baseline.fingerprint_of(&fingerprint.path);
        let exists = repo_dir.join(&fingerprint.path).exists();

        let change = match previous {
            Some(previous)
                if previous.content_hash == fingerprint.content_hash
                    && previous.index_blob == fingerprint.index_blob =>
            {
                "unchanged"
            }
            Some(_) => "modified",
            // A path absent from the baseline is a new untracked file, a
            // tracked file that was clean and is now dirty, or a deletion.
            None if fingerprint.status.starts_with('?') && exists => "added",
            None if exists => "modified",
            None => "deleted",
        };

        match change {
            "unchanged" => files_unchanged.push(fingerprint.path.clone()),
            "added" => files_added.push(fingerprint.path.clone()),
            "modified" => files_modified.push(fingerprint.path.clone()),
            _ => files_deleted.push(fingerprint.path.clone()),
        }
    }

    for previous in &baseline.fingerprints {
        if current
            .fingerprints
            .iter()
            .any(|fingerprint| fingerprint.path == previous.path)
        {
            continue;
        }
        // The path is no longer reported as non-clean: it was either deleted or
        // restored to its committed state.
        if repo_dir.join(&previous.path).exists() {
            files_modified.push(previous.path.clone());
        } else {
            files_deleted.push(previous.path.clone());
        }
    }

    let patch_stat = current.diff_stat.clone();
    let current_fingerprint = current.fingerprint();
    let patch_size_bytes = current.evidence.tracked_diff_size;
    let has_new_evidence = baseline.fingerprint() != current_fingerprint;

    let evidence_summary = if !has_new_evidence {
        "NO NEW EVIDENCE: the repository fingerprint is identical to the baseline.".to_string()
    } else {
        format!(
            "Evidence generated: {} modified, {} added, {} deleted, {} unchanged. Patch stat:\n{}",
            files_modified.len(),
            files_added.len(),
            files_deleted.len(),
            files_unchanged.len(),
            patch_stat
        )
    };

    Ok(WorkingTreeDelta {
        baseline_head: baseline.head_sha.clone(),
        current_head: current.head_sha.clone(),
        files_modified,
        files_added,
        files_deleted,
        files_unchanged,
        has_new_evidence,
        patch_stat,
        current_fingerprint,
        patch_size_bytes,
        evidence_summary,
    })
}

/// Work out what a commit would touch relative to a baseline.
pub async fn plan_commit(repo_dir: &Path, baseline: &RepositorySnapshot) -> Result<CommitPlan> {
    let current = capture_snapshot(repo_dir).await?;

    let mut agent_owned = Vec::new();
    let mut pre_existing_dirty = Vec::new();
    let mut pre_existing_staged = Vec::new();

    for fingerprint in &current.fingerprints {
        let previous = baseline.fingerprint_of(&fingerprint.path);
        let changed = match previous {
            None => true,
            Some(previous) => {
                previous.content_hash != fingerprint.content_hash
                    || previous.index_blob != fingerprint.index_blob
            }
        };

        if changed {
            agent_owned.push(fingerprint.path.clone());
            continue;
        }

        pre_existing_dirty.push(fingerprint.path.clone());
        if !fingerprint.index_blob.is_empty() {
            pre_existing_staged.push(fingerprint.path.clone());
        }
    }

    for previous in &baseline.fingerprints {
        if !current
            .fingerprints
            .iter()
            .any(|fingerprint| fingerprint.path == previous.path)
        {
            agent_owned.push(previous.path.clone());
        }
    }

    agent_owned.sort();
    agent_owned.dedup();
    pre_existing_dirty.sort();
    pre_existing_dirty.dedup();
    pre_existing_staged.sort();
    pre_existing_staged.dedup();

    Ok(CommitPlan {
        agent_owned,
        pre_existing_dirty,
        pre_existing_staged,
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

/// Stage files into the git index.
pub async fn stage_files(repo_dir: &Path, paths: &[String]) -> Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    let mut args = vec!["add", "--"];
    args.extend(paths.iter().map(String::as_str));
    run_git_cmd(repo_dir, &args).await?;
    Ok(())
}

/// Commit only the given paths, leaving unrelated staged content in the index.
///
/// `git commit --only` builds the commit from `HEAD` plus the named paths, so
/// entries that were staged before the session are not consumed by the commit.
pub async fn commit_paths(repo_dir: &Path, message: &str, paths: &[String]) -> Result<String> {
    if paths.is_empty() {
        bail!("no changes to commit");
    }
    stage_files(repo_dir, paths).await?;

    let mut args = vec!["commit", "--only", "-m", message, "--"];
    args.extend(paths.iter().map(String::as_str));
    run_git_cmd(repo_dir, &args).await
}

/// Stage the entire repository and commit it.
///
/// This consumes unrelated pre-existing work, so it is only reachable through an
/// explicit opt-in.
pub async fn commit_everything(repo_dir: &Path, message: &str) -> Result<String> {
    run_git_cmd(repo_dir, &["add", "-A"]).await?;
    run_git_cmd(repo_dir, &["commit", "-m", message]).await
}

/// Retrieve recent commit history.
pub async fn get_recent_log(repo_dir: &Path, count: usize) -> Result<String> {
    let n = format!("-n{count}");
    run_git_cmd(repo_dir, &["log", &n, "--oneline", "--decorate"]).await
}

type SessionBaselines = std::sync::Mutex<BTreeMap<String, RepositorySnapshot>>;

fn session_baselines() -> &'static SessionBaselines {
    static BASELINES: std::sync::OnceLock<SessionBaselines> = std::sync::OnceLock::new();
    BASELINES.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

/// The snapshot representing "the repository before this session touched it".
///
/// Captured on first use so later commits can tell the agent's own edits apart
/// from work the user had already in the tree.
pub async fn session_baseline(session_id: &str, repo_dir: &Path) -> Result<RepositorySnapshot> {
    if let Ok(baselines) = session_baselines().lock() {
        if let Some(baseline) = baselines.get(session_id) {
            return Ok(baseline.clone());
        }
    }

    let baseline = capture_snapshot(repo_dir).await?;
    if let Ok(mut baselines) = session_baselines().lock() {
        baselines.insert(session_id.to_string(), baseline.clone());
    }
    Ok(baseline)
}

pub fn reset_session_baseline(session_id: &str) {
    if let Ok(mut baselines) = session_baselines().lock() {
        baselines.remove(session_id);
    }
}

/// Commit on behalf of a session, using the same rules in every agent loop.
///
/// Without `stage_all` only the files that changed since the session baseline
/// are committed, so unrelated staged work is never consumed.
pub async fn commit_for_session(
    repo_dir: &Path,
    session_id: &str,
    message: &str,
    stage_all: bool,
) -> Result<String> {
    if stage_all {
        let output = commit_everything(repo_dir, message).await?;
        reset_session_baseline(session_id);
        return Ok(format!(
            "Commit created:\n{output}\n\nThis committed the entire repository, including work \
             that predates this session."
        ));
    }

    let baseline = session_baseline(session_id, repo_dir).await?;
    let plan = plan_commit(repo_dir, &baseline).await?;
    if plan.is_empty() {
        bail!(
            "nothing to commit: no file changed since the session baseline.\n{}",
            plan.describe()
        );
    }

    let output = commit_paths(repo_dir, message, &plan.agent_owned).await?;
    reset_session_baseline(session_id);
    Ok(format!("Commit created:\n{output}\n\n{}", plan.describe()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command as StdCommand;

    struct TestRepo {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    fn git(repo: &TestRepo, args: &[&str]) {
        let status = StdCommand::new("git")
            .args(args)
            .current_dir(&repo.path)
            .output()
            .expect("git must be available for these tests");
        assert!(
            status.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
    }

    fn test_repo() -> TestRepo {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().to_path_buf();
        let repo = TestRepo { _dir: dir, path };
        git(&repo, &["init", "--initial-branch=main"]);
        git(&repo, &["config", "user.email", "test@example.com"]);
        git(&repo, &["config", "user.name", "Test"]);
        repo
    }

    fn write(repo: &TestRepo, name: &str, contents: &str) {
        let path = repo.path.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    #[tokio::test]
    async fn captures_repository_state() {
        let repo = test_repo();
        write(&repo, "a.txt", "one\n");
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-m", "initial"]);

        let state = get_repo_state(&repo.path).await.unwrap();
        assert!(state.is_repo);
        assert_eq!(state.branch.as_deref(), Some("main"));
        assert!(
            state.is_clean,
            "a committed tree must be clean: {}",
            state.summary
        );
    }

    #[tokio::test]
    async fn identical_content_produces_an_identical_fingerprint() {
        let repo = test_repo();
        write(&repo, "a.txt", "one\n");
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-m", "initial"]);

        let first = capture_snapshot(&repo.path).await.unwrap();
        let second = capture_snapshot(&repo.path).await.unwrap();
        assert_eq!(first.fingerprint(), second.fingerprint());
    }

    #[tokio::test]
    async fn unchanged_content_with_identical_line_counts_is_evidence() {
        let repo = test_repo();
        write(&repo, "a.txt", "one\n");
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-m", "initial"]);

        write(&repo, "a.txt", "dirty\n");
        let baseline = capture_snapshot(&repo.path).await.unwrap();
        let before = run_git_cmd(&repo.path, &["diff", "--numstat"])
            .await
            .unwrap();

        // Same path, same insertion and deletion counts, different content.
        write(&repo, "a.txt", "other\n");
        let after = run_git_cmd(&repo.path, &["diff", "--numstat"])
            .await
            .unwrap();
        assert_eq!(
            before, after,
            "numstat must be identical for this test to be meaningful"
        );

        let delta = compute_delta(&baseline, &repo.path).await.unwrap();
        assert!(
            delta.has_new_evidence,
            "content changed, so there is evidence"
        );
        assert_eq!(delta.files_modified, vec!["a.txt".to_string()]);
    }

    #[tokio::test]
    async fn identical_numstat_with_different_content_is_evidence() {
        let repo = test_repo();
        write(&repo, "a.txt", "aaaa\nbbbb\ncccc\n");
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-m", "initial"]);

        let baseline = capture_snapshot(&repo.path).await.unwrap();

        write(&repo, "a.txt", "dddd\neeee\nffff\n");
        let numstat = run_git_cmd(&repo.path, &["diff", "--numstat"])
            .await
            .unwrap();
        assert_eq!(
            numstat, "3\t3\ta.txt",
            "numstat must be identical for this test to be meaningful"
        );

        let delta = compute_delta(&baseline, &repo.path).await.unwrap();
        assert!(delta.has_new_evidence);
        assert_eq!(delta.files_modified, vec!["a.txt".to_string()]);
    }

    #[tokio::test]
    async fn a_file_that_was_already_dirty_and_untouched_is_not_modified() {
        let repo = test_repo();
        write(&repo, "a.txt", "one\n");
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-m", "initial"]);

        write(&repo, "a.txt", "dirty\n");
        let baseline = capture_snapshot(&repo.path).await.unwrap();

        let delta = compute_delta(&baseline, &repo.path).await.unwrap();
        assert!(delta.files_modified.is_empty());
        assert_eq!(delta.files_unchanged, vec!["a.txt".to_string()]);
        assert!(
            !delta.has_new_evidence,
            "an untouched dirty file is not new evidence"
        );
    }

    #[tokio::test]
    async fn changed_untracked_file_is_evidence() {
        let repo = test_repo();
        write(&repo, "a.txt", "one\n");
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-m", "initial"]);

        write(&repo, "scratch.txt", "first\n");
        let baseline = capture_snapshot(&repo.path).await.unwrap();

        write(&repo, "scratch.txt", "second\n");
        let delta = compute_delta(&baseline, &repo.path).await.unwrap();

        assert!(delta.has_new_evidence);
        assert_eq!(delta.files_modified, vec!["scratch.txt".to_string()]);
    }

    #[tokio::test]
    async fn deleted_and_added_files_are_classified() {
        let repo = test_repo();
        write(&repo, "a.txt", "one\n");
        write(&repo, "b.txt", "two\n");
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-m", "initial"]);

        let baseline = capture_snapshot(&repo.path).await.unwrap();
        std::fs::remove_file(repo.path.join("b.txt")).unwrap();
        write(&repo, "c.txt", "three\n");

        let delta = compute_delta(&baseline, &repo.path).await.unwrap();
        assert_eq!(delta.files_added, vec!["c.txt".to_string()]);
        assert_eq!(delta.files_deleted, vec!["b.txt".to_string()]);
    }

    #[tokio::test]
    async fn commit_plan_separates_agent_owned_from_pre_existing_work() {
        let repo = test_repo();
        write(&repo, "a.txt", "one\n");
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-m", "initial"]);

        write(&repo, "user.txt", "user work\n");
        git(&repo, &["add", "user.txt"]);

        let baseline = capture_snapshot(&repo.path).await.unwrap();
        write(&repo, "agent.txt", "agent work\n");

        let plan = plan_commit(&repo.path, &baseline).await.unwrap();
        assert_eq!(plan.agent_owned, vec!["agent.txt".to_string()]);
        assert!(plan.pre_existing_staged.contains(&"user.txt".to_string()));
    }

    #[tokio::test]
    async fn committing_agent_owned_paths_leaves_pre_existing_staged_content() {
        let repo = test_repo();
        write(&repo, "a.txt", "one\n");
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-m", "initial"]);

        write(&repo, "user.txt", "user work\n");
        git(&repo, &["add", "user.txt"]);

        let baseline = capture_snapshot(&repo.path).await.unwrap();
        write(&repo, "agent.txt", "agent work\n");

        let plan = plan_commit(&repo.path, &baseline).await.unwrap();
        commit_paths(&repo.path, "agent change", &plan.agent_owned)
            .await
            .unwrap();

        let state = get_repo_state(&repo.path).await.unwrap();
        assert!(
            state
                .staged_files
                .iter()
                .any(|file| file.path == "user.txt"),
            "the user's staged file must stay staged"
        );

        let committed = run_git_cmd(&repo.path, &["show", "--name-only", "--format=", "HEAD"])
            .await
            .unwrap();
        assert!(committed.contains("agent.txt"));
        assert!(
            !committed.contains("user.txt"),
            "the commit must not consume unrelated staged work"
        );
    }
}

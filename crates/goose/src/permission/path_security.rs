//! Workspace path containment.
//!
//! A single authoritative answer to "is this path inside the workspace", shared
//! by every tool that touches the filesystem. Lexical `Path::starts_with` is not
//! usable for this: `C:\Project2` has `C:\Project` as a string prefix, relative
//! paths are not absolute at all, and a junction can point anywhere.
//!
//! The check canonicalizes both sides, so symlinks and reparse points are
//! resolved before comparison, and compares whole path components rather than
//! string prefixes.

use anyhow::{bail, Context, Result};
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

#[cfg(windows)]
fn components_eq(left: &OsStr, right: &OsStr) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

#[cfg(not(windows))]
fn components_eq(left: &OsStr, right: &OsStr) -> bool {
    left == right
}

fn is_within(root: &Path, candidate: &Path) -> bool {
    let mut root_components = root.components();
    for candidate_component in candidate.components() {
        let Some(root_component) = root_components.next() else {
            // The root is exhausted and the rest of the candidate is deeper.
            return true;
        };
        if !components_eq(root_component.as_os_str(), candidate_component.as_os_str()) {
            return false;
        }
    }
    // The candidate is a strict prefix of the root, so it is above it.
    root_components.next().is_none()
}

/// Remove `.` and resolve `..` textually, without touching the filesystem.
///
/// On an absolute path a leading `..` is dropped rather than escaping the root.
fn lexically_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(
                    normalized.components().next_back(),
                    Some(Component::Normal(_))
                ) {
                    normalized.pop();
                } else if !normalized.has_root() {
                    normalized.push(component.as_os_str());
                }
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

/// Canonicalize the nearest existing ancestor and keep the missing tail intact.
///
/// `git` and the developer tools routinely address files that do not exist yet,
/// so canonicalizing the whole path is not an option.
fn canonicalize_with_missing_tail(path: &Path) -> Result<PathBuf> {
    let mut existing = path.to_path_buf();
    let mut missing_tail: Vec<OsString> = Vec::new();

    while !existing.exists() {
        let Some(name) = existing.file_name().map(|name| name.to_os_string()) else {
            bail!("{} has no existing ancestor directory", path.display());
        };
        let Some(parent) = existing.parent().map(Path::to_path_buf) else {
            bail!("{} has no existing ancestor directory", path.display());
        };
        missing_tail.push(name);
        existing = parent;
    }

    let mut resolved = std::fs::canonicalize(&existing)
        .with_context(|| format!("failed to resolve {}", existing.display()))?;
    for component in missing_tail.iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

/// Resolve `input` to a canonical path and verify it is inside `workspace_root`.
///
/// The returned path is the one callers must use for the actual operation: it
/// is the path that was validated, not a separate string that merely looked safe.
pub fn resolve_and_validate_workspace_path(input: &Path, workspace_root: &Path) -> Result<PathBuf> {
    let canonical_root = std::fs::canonicalize(workspace_root)
        .with_context(|| format!("workspace root {} does not exist", workspace_root.display()))?;

    let joined = if input.is_absolute() {
        input.to_path_buf()
    } else {
        canonical_root.join(input)
    };

    let resolved = canonicalize_with_missing_tail(&lexically_normalize(&joined))?;

    if !is_within(&canonical_root, &resolved) {
        bail!(
            "path {} resolves outside the workspace {}",
            resolved.display(),
            canonical_root.display()
        );
    }

    Ok(resolved)
}

/// Validate a path that must already exist.
pub fn validate_existing_workspace_path(input: &Path, workspace_root: &Path) -> Result<PathBuf> {
    let resolved = resolve_and_validate_workspace_path(input, workspace_root)?;
    if !resolved.exists() {
        bail!("{} does not exist", resolved.display());
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_workspace() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn accepts_path_inside_workspace() {
        let root = temp_workspace();
        let file = root.path().join("src/main.rs");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "fn main() {}").unwrap();

        let resolved =
            resolve_and_validate_workspace_path(Path::new("src/main.rs"), root.path()).unwrap();
        assert!(resolved.ends_with("main.rs"));
    }

    #[test]
    fn accepts_missing_file_inside_workspace() {
        let root = temp_workspace();
        let resolved =
            resolve_and_validate_workspace_path(Path::new("does/not/exist/yet.rs"), root.path())
                .unwrap();
        assert!(resolved.ends_with("yet.rs"));
    }

    #[test]
    fn rejects_sibling_directory_with_shared_prefix() {
        let parent = temp_workspace();
        let root = parent.path().join("Project");
        let sibling = parent.path().join("Project2");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();

        let escape = sibling.join("secret.txt");
        std::fs::write(&escape, "secret").unwrap();

        // `starts_with` on the raw paths does not reject this, because
        // "C:\Project2\secret.txt" starts with the string "C:\Project".
        let error = resolve_and_validate_workspace_path(&escape, &root).unwrap_err();
        assert!(error.to_string().contains("outside the workspace"));
    }

    #[test]
    fn rejects_parent_directory_traversal() {
        let parent = temp_workspace();
        let root = parent.path().join("Project");
        std::fs::create_dir_all(&root).unwrap();

        let error = resolve_and_validate_workspace_path(Path::new("../Project/../../etc"), &root)
            .unwrap_err();
        assert!(error.to_string().contains("outside the workspace"));
    }

    #[test]
    fn resolves_relative_paths_against_the_workspace_root() {
        let root = temp_workspace();
        std::fs::create_dir_all(root.path().join("nested")).unwrap();

        let resolved = resolve_and_validate_workspace_path(
            Path::new("nested/../nested/file.txt"),
            root.path(),
        )
        .unwrap();
        assert!(resolved.starts_with(std::fs::canonicalize(root.path()).unwrap()));
        assert!(resolved.ends_with("file.txt"));
    }

    #[test]
    fn rejects_absolute_path_outside_workspace() {
        let root = temp_workspace();
        let other = temp_workspace();
        let outside = other.path().join("file.txt");
        std::fs::write(&outside, "x").unwrap();

        assert!(resolve_and_validate_workspace_path(&outside, root.path()).is_err());
    }

    #[test]
    fn workspace_root_itself_is_allowed() {
        let root = temp_workspace();
        let resolved = resolve_and_validate_workspace_path(root.path(), root.path()).unwrap();
        assert!(resolved.is_dir());
    }

    #[test]
    fn missing_workspace_root_is_an_error() {
        let root = temp_workspace();
        let missing = root.path().join("nope");
        assert!(resolve_and_validate_workspace_path(Path::new("a.txt"), &missing).is_err());
    }

    #[test]
    fn existing_path_validation_rejects_absent_files() {
        let root = temp_workspace();
        assert!(validate_existing_workspace_path(Path::new("absent.txt"), root.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_that_escapes_the_workspace() {
        let root = temp_workspace();
        let outside = temp_workspace();
        let outside_file = outside.path().join("secret.txt");
        std::fs::write(&outside_file, "secret").unwrap();

        let link = root.path().join("escape");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();

        let error =
            resolve_and_validate_workspace_path(&link.join("secret.txt"), root.path()).unwrap_err();
        assert!(error.to_string().contains("outside the workspace"));
    }

    #[test]
    fn lexically_normalize_collapses_relative_segments() {
        assert_eq!(
            lexically_normalize(Path::new("a/./b/../c")),
            PathBuf::from("a").join("c")
        );
    }
}

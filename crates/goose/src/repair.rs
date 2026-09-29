//! Bounded autonomous repair.
//!
//! A repair attempt that produces no new evidence and repeats the same failure
//! is not progress, so the loop must stop rather than let the model keep
//! producing speculative patches against identical state.
//!
//! The budget is deliberately evidence-based: [`RepairDecision::Stop`] is the
//! interesting outcome, and every stop reason is derived from an observation
//! the caller can print and a human can verify.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, Instant};

/// Limits applied to a repair loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairBudgetConfig {
    pub max_attempts: u32,
    pub max_elapsed_seconds: u64,
    pub max_changed_files: usize,
    pub max_patch_size_bytes: u64,
    pub max_identical_error_repetitions: u32,
    pub max_unrelated_changes: usize,
}

impl Default for RepairBudgetConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            max_elapsed_seconds: 900,
            max_changed_files: 20,
            max_patch_size_bytes: 256 * 1024,
            max_identical_error_repetitions: 2,
            max_unrelated_changes: 0,
        }
    }
}

/// Why the repair loop stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    AttemptsExhausted { attempts: u32, limit: u32 },
    ElapsedTimeExceeded { limit_seconds: u64 },
    TooManyChangedFiles { changed: usize, limit: usize },
    PatchTooLarge { size_bytes: u64, limit: u64 },
    RepeatedIdenticalError { error: String, repetitions: u32 },
    TooManyUnrelatedChanges { unrelated: usize, limit: usize },
    NoNewEvidenceWithSameError { error: String },
}

impl std::fmt::Display for StopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StopReason::AttemptsExhausted { attempts, limit } => {
                write!(f, "repair attempt budget exhausted ({attempts} of {limit})")
            }
            StopReason::ElapsedTimeExceeded { limit_seconds } => {
                write!(f, "repair time budget exceeded ({limit_seconds}s)")
            }
            StopReason::TooManyChangedFiles { changed, limit } => {
                write!(f, "repair changed {changed} files, limit is {limit}")
            }
            StopReason::PatchTooLarge { size_bytes, limit } => {
                write!(f, "repair patch is {size_bytes} bytes, limit is {limit}")
            }
            StopReason::RepeatedIdenticalError { error, repetitions } => {
                write!(f, "the same failure repeated {repetitions} times: {error}")
            }
            StopReason::TooManyUnrelatedChanges { unrelated, limit } => {
                write!(
                    f,
                    "repair touched {unrelated} unrelated changes, limit is {limit}"
                )
            }
            StopReason::NoNewEvidenceWithSameError { error } => {
                write!(f, "no new evidence and the same failure: {error}")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairDecision {
    Continue,
    Stop(StopReason),
}

impl RepairDecision {
    pub fn should_stop(&self) -> bool {
        matches!(self, RepairDecision::Stop(_))
    }
}

/// What was observed after one attempt.
#[derive(Debug, Clone, Default)]
pub struct AttemptReport {
    /// The failure that ended the attempt, if any.
    pub error: Option<String>,
    /// Fingerprint of the repository before and after the attempt. `None` when
    /// the attempt ran outside a repository.
    pub evidence_before: Option<String>,
    pub evidence_after: Option<String>,
    pub changed_files: usize,
    pub patch_size_bytes: u64,
    pub unrelated_changes: usize,
}

impl AttemptReport {
    pub fn evidence_changed(&self) -> bool {
        match (&self.evidence_before, &self.evidence_after) {
            (Some(before), Some(after)) => before != after,
            // Without comparable fingerprints, assume there is evidence rather
            // than silently treating an unmeasured attempt as progress.
            (None, None) => true,
            _ => true,
        }
    }
}

/// Normalize an error so the same failure is recognised across attempts.
///
/// Line numbers, addresses, and quoted values change between runs of the same
/// underlying problem, so they are removed before comparison. Digits that belong
/// to an identifier (`CS1002`, `error E0433`) are kept, because they distinguish
/// different errors.
pub fn error_signature(error: &str) -> String {
    error
        .split_whitespace()
        .map(|token| {
            let lowered = token.to_lowercase();
            let characters: Vec<char> = lowered.chars().collect();
            let mut normalized = String::with_capacity(lowered.len());
            let mut index = 0;
            while index < characters.len() {
                if !characters[index].is_ascii_digit() {
                    normalized.push(characters[index]);
                    index += 1;
                    continue;
                }
                let preceded_by_letter = index > 0 && characters[index - 1].is_ascii_alphabetic();
                let start = index;
                while index < characters.len() && characters[index].is_ascii_digit() {
                    index += 1;
                }
                if preceded_by_letter {
                    normalized.extend(characters[start..index].iter());
                } else {
                    normalized.push('#');
                }
            }
            normalized
        })
        .collect::<Vec<String>>()
        .join(" ")
}

#[derive(Debug)]
pub struct RepairBudget {
    config: RepairBudgetConfig,
    started_at: Instant,
    attempts: u32,
    last_error: Option<String>,
    identical_error_repetitions: u32,
    last_evidence: Option<String>,
}

impl Default for RepairBudget {
    fn default() -> Self {
        Self::new(RepairBudgetConfig::default())
    }
}

impl RepairBudget {
    pub fn new(config: RepairBudgetConfig) -> Self {
        Self {
            config,
            started_at: Instant::now(),
            attempts: 0,
            last_error: None,
            identical_error_repetitions: 0,
            last_evidence: None,
        }
    }

    pub fn config(&self) -> &RepairBudgetConfig {
        &self.config
    }

    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// Open an attempt, returning a stop reason if the loop must not continue.
    pub fn begin_attempt(&mut self) -> RepairDecision {
        if self.attempts >= self.config.max_attempts {
            return RepairDecision::Stop(StopReason::AttemptsExhausted {
                attempts: self.attempts,
                limit: self.config.max_attempts,
            });
        }
        if self.started_at.elapsed() > Duration::from_secs(self.config.max_elapsed_seconds) {
            return RepairDecision::Stop(StopReason::ElapsedTimeExceeded {
                limit_seconds: self.config.max_elapsed_seconds,
            });
        }
        RepairDecision::Continue
    }

    /// Close an attempt and decide whether the loop may run another one.
    pub fn record(&mut self, report: AttemptReport) -> RepairDecision {
        self.attempts += 1;

        if report.unrelated_changes > self.config.max_unrelated_changes {
            return RepairDecision::Stop(StopReason::TooManyUnrelatedChanges {
                unrelated: report.unrelated_changes,
                limit: self.config.max_unrelated_changes,
            });
        }
        if report.changed_files > self.config.max_changed_files {
            return RepairDecision::Stop(StopReason::TooManyChangedFiles {
                changed: report.changed_files,
                limit: self.config.max_changed_files,
            });
        }
        if report.patch_size_bytes > self.config.max_patch_size_bytes {
            return RepairDecision::Stop(StopReason::PatchTooLarge {
                size_bytes: report.patch_size_bytes,
                limit: self.config.max_patch_size_bytes,
            });
        }

        let signature = report.error.as_deref().map(error_signature);

        if signature.is_none() {
            // A successful attempt clears the failure history.
            self.last_error = None;
            self.identical_error_repetitions = 0;
            self.last_evidence = report.evidence_after.clone();
            return self.begin_attempt();
        }

        let signature = signature.expect("checked above");
        let same_error = self.last_error.as_deref() == Some(signature.as_str());
        self.identical_error_repetitions = if same_error {
            self.identical_error_repetitions + 1
        } else {
            1
        };
        self.last_error = Some(signature.clone());

        if self.identical_error_repetitions > self.config.max_identical_error_repetitions {
            return RepairDecision::Stop(StopReason::RepeatedIdenticalError {
                error: signature,
                repetitions: self.identical_error_repetitions,
            });
        }

        let produced_evidence = match (&self.last_evidence, &report.evidence_after) {
            (Some(previous), Some(current)) => previous != current,
            _ => report.evidence_changed(),
        };
        self.last_evidence = report.evidence_after.clone();

        if same_error && !produced_evidence {
            return RepairDecision::Stop(StopReason::NoNewEvidenceWithSameError {
                error: signature,
            });
        }

        self.begin_attempt()
    }
}

/// Build an attempt report by comparing a repository against a baseline.
pub async fn report_from_repository(
    repo_dir: &Path,
    baseline: &crate::git::RepositorySnapshot,
) -> Result<AttemptReport> {
    let delta = crate::git::compute_delta(baseline, repo_dir).await?;
    Ok(AttemptReport {
        error: None,
        evidence_before: Some(baseline.fingerprint()),
        evidence_after: Some(delta.current_fingerprint.clone()),
        changed_files: delta.files_modified.len()
            + delta.files_added.len()
            + delta.files_deleted.len(),
        patch_size_bytes: delta.patch_size_bytes,
        unrelated_changes: delta.files_unchanged.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget() -> RepairBudget {
        RepairBudget::new(RepairBudgetConfig {
            max_attempts: 3,
            max_elapsed_seconds: 3600,
            max_changed_files: 5,
            max_patch_size_bytes: 1024,
            max_identical_error_repetitions: 2,
            max_unrelated_changes: 0,
        })
    }

    fn failure(error: &str) -> AttemptReport {
        AttemptReport {
            error: Some(error.to_string()),
            evidence_before: Some("before".into()),
            evidence_after: Some("before".into()),
            ..Default::default()
        }
    }

    #[test]
    fn identical_failure_without_new_evidence_stops_the_loop() {
        let mut budget = budget();
        // The first failure has nothing to repeat, so the loop may run once more.
        assert_eq!(
            budget.record(failure("error CS1002 line 42")),
            RepairDecision::Continue
        );
        assert_eq!(
            budget.record(failure("error CS1002 line 97")),
            RepairDecision::Stop(StopReason::NoNewEvidenceWithSameError {
                error: "error cs1002 line #".to_string()
            })
        );
    }

    #[test]
    fn the_same_failure_with_new_evidence_may_continue() {
        let mut budget = budget();
        let mut first = failure("boom");
        first.evidence_after = Some("after-1".into());
        assert_eq!(budget.record(first), RepairDecision::Continue);

        let mut second = failure("boom");
        second.evidence_after = Some("after-2".into());
        assert_eq!(budget.record(second), RepairDecision::Continue);
    }

    #[test]
    fn a_different_failure_resets_the_repetition_count() {
        let mut budget = budget();
        let mut first = failure("boom");
        first.evidence_after = Some("a".into());
        budget.record(first);
        let mut second = failure("other");
        second.evidence_after = Some("b".into());
        assert_eq!(budget.record(second), RepairDecision::Continue);
    }

    #[test]
    fn repeating_a_failure_with_new_evidence_stops_at_the_repetition_limit() {
        let mut budget = budget();
        for (index, evidence) in ["a", "b", "c"].iter().enumerate() {
            let mut report = failure("boom");
            report.evidence_after = Some((*evidence).into());
            let decision = budget.record(report);
            if index < 2 {
                assert_eq!(decision, RepairDecision::Continue);
            } else {
                assert_eq!(
                    decision,
                    RepairDecision::Stop(StopReason::RepeatedIdenticalError {
                        error: "boom".into(),
                        repetitions: 3
                    })
                );
            }
        }
    }

    #[test]
    fn the_attempt_limit_is_enforced() {
        let mut budget = budget();
        for (index, error) in ["alpha", "beta", "gamma"].iter().enumerate() {
            let mut report = failure(error);
            report.evidence_after = Some(index.to_string());
            let decision = budget.record(report);
            if index < 2 {
                assert_eq!(decision, RepairDecision::Continue);
            } else {
                assert_eq!(
                    decision,
                    RepairDecision::Stop(StopReason::AttemptsExhausted {
                        attempts: 3,
                        limit: 3
                    })
                );
            }
        }
        assert!(budget.begin_attempt().should_stop());
    }

    #[test]
    fn too_many_changed_files_stops() {
        let mut budget = budget();
        let mut report = failure("boom");
        report.changed_files = 9;
        assert_eq!(
            budget.record(report),
            RepairDecision::Stop(StopReason::TooManyChangedFiles {
                changed: 9,
                limit: 5
            })
        );
    }

    #[test]
    fn an_oversized_patch_stops() {
        let mut budget = budget();
        let mut report = failure("boom");
        report.patch_size_bytes = 4096;
        assert_eq!(
            budget.record(report),
            RepairDecision::Stop(StopReason::PatchTooLarge {
                size_bytes: 4096,
                limit: 1024
            })
        );
    }

    #[test]
    fn unrelated_changes_stop_the_loop() {
        let mut budget = budget();
        let mut report = failure("boom");
        report.unrelated_changes = 3;
        assert_eq!(
            budget.record(report),
            RepairDecision::Stop(StopReason::TooManyUnrelatedChanges {
                unrelated: 3,
                limit: 0
            })
        );
    }

    #[test]
    fn a_successful_attempt_clears_the_failure_history() {
        let mut budget = budget();
        let mut failing = failure("boom");
        failing.evidence_after = Some("a".into());
        budget.record(failing);
        assert_eq!(
            budget.record(AttemptReport::default()),
            RepairDecision::Continue
        );
        assert!(budget.last_error().is_none());
    }

    #[test]
    fn error_signatures_ignore_line_numbers_but_keep_error_codes() {
        assert_eq!(
            error_signature("error CS1002 at line 42"),
            error_signature("Error CS1002 at line 91")
        );
        assert_ne!(error_signature("CS1002"), error_signature("CS1003"));
    }

    #[test]
    fn an_unmeasured_attempt_is_treated_as_producing_evidence() {
        let report = AttemptReport {
            error: Some("boom".into()),
            evidence_before: None,
            evidence_after: None,
            ..Default::default()
        };
        assert!(report.evidence_changed());
    }
}

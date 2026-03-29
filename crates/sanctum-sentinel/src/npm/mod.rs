//! npm supply chain security scanning.
//!
//! This module provides lockfile change detection and delegates to the
//! [`scanner`] submodule for deep package content analysis.

pub mod scanner;

/// Check whether a lockfile change is expected given the current context.
///
/// **Known limitation:** This is currently a conservative stub that always
/// returns `false`, causing lockfile changes to generate alerts. A full
/// implementation would verify that the parent process is a known package
/// manager (`npm`, `yarn`, `pnpm`, `bun`) by inspecting process lineage
/// via `/proc` or `sysctl`. Since process lineage tracing is platform-specific
/// and the sentinel watcher may not have the originating PID readily
/// available at call time, we err on the side of caution by treating all
/// lockfile changes as unexpected until the lineage infrastructure is wired
/// through.
///
/// Consumers should treat a `false` return as "generate an informational
/// alert" rather than "block the operation".
#[must_use]
pub const fn is_lockfile_change_expected() -> bool {
    // Conservative: always alert on lockfile changes.
    // See doc comment above for rationale and future work.
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockfile_change_is_conservatively_unexpected() {
        // The stub should return false (conservative — alert on all changes)
        assert!(
            !is_lockfile_change_expected(),
            "stub should be conservative and return false"
        );
    }
}

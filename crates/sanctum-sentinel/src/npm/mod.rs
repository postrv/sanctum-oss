//! npm supply chain security scanning.
//!
//! This module provides lockfile change detection and delegates to the
//! [`scanner`] submodule for deep package content analysis.

pub mod scanner;
pub mod watcher;

use crate::pth::lineage::{ProcessLineage, ProcSource, SystemProcSource};

/// Check whether a lockfile change is expected given the current context.
///
/// Inspects the process lineage of the given PID (if provided) to determine
/// whether the lockfile change was initiated by a known package manager
/// (`npm`, `yarn`, `pnpm`, `bun`, `node`, or any Python package manager).
///
/// Returns `true` if a known package manager is found in the process ancestry.
/// Returns `false` (conservative) if:
/// - No PID is provided
/// - Process lineage cannot be determined (process exited, permission denied)
/// - No known package manager is found in the lineage
///
/// Consumers should treat a `false` return as "generate an informational
/// alert" rather than "block the operation".
#[must_use]
pub fn is_lockfile_change_expected(pid: Option<u32>) -> bool {
    is_lockfile_change_expected_with_source(pid, &SystemProcSource)
}

/// Inner implementation that accepts a `ProcSource` for testability.
fn is_lockfile_change_expected_with_source(pid: Option<u32>, source: &dyn ProcSource) -> bool {
    let Some(pid) = pid else {
        return false;
    };

    match ProcessLineage::trace(pid, source) {
        Ok(lineage) => lineage.has_known_package_manager(),
        Err(e) => {
            tracing::debug!(
                pid,
                %e,
                "failed to trace process lineage for lockfile check"
            );
            false
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::pth::lineage::MockProcFs;

    #[test]
    fn lockfile_change_expected_when_npm_in_lineage() {
        let mock = MockProcFs::new()
            .process(1, "init", None)
            .process(50, "npm", Some(1))
            .process(100, "node", Some(50));

        assert!(
            is_lockfile_change_expected_with_source(Some(100), &mock),
            "lockfile change with npm in lineage should be expected"
        );
    }

    #[test]
    fn lockfile_change_expected_when_yarn_in_lineage() {
        let mock = MockProcFs::new()
            .process(1, "init", None)
            .process(50, "yarn", Some(1))
            .process(100, "node", Some(50));

        assert!(
            is_lockfile_change_expected_with_source(Some(100), &mock),
            "lockfile change with yarn in lineage should be expected"
        );
    }

    #[test]
    fn lockfile_change_expected_when_pnpm_in_lineage() {
        let mock = MockProcFs::new()
            .process(1, "init", None)
            .process(50, "pnpm", Some(1))
            .process(100, "node", Some(50));

        assert!(
            is_lockfile_change_expected_with_source(Some(100), &mock),
            "lockfile change with pnpm in lineage should be expected"
        );
    }

    #[test]
    fn lockfile_change_expected_when_bun_in_lineage() {
        let mock = MockProcFs::new()
            .process(1, "init", None)
            .process(50, "bun", Some(1));

        assert!(
            is_lockfile_change_expected_with_source(Some(50), &mock),
            "lockfile change with bun in lineage should be expected"
        );
    }

    #[test]
    fn lockfile_change_expected_when_node_in_lineage() {
        let mock = MockProcFs::new()
            .process(1, "init", None)
            .process(50, "node", Some(1));

        assert!(
            is_lockfile_change_expected_with_source(Some(50), &mock),
            "lockfile change with node in lineage should be expected"
        );
    }

    #[test]
    fn lockfile_change_unexpected_for_unknown_process() {
        let mock = MockProcFs::new()
            .process(1, "init", None)
            .process(50, "bash", Some(1))
            .process(100, "curl", Some(50));

        assert!(
            !is_lockfile_change_expected_with_source(Some(100), &mock),
            "lockfile change from unknown process should be unexpected"
        );
    }

    #[test]
    fn lockfile_change_unexpected_when_lineage_unavailable() {
        let mock = MockProcFs::new(); // empty -- no processes

        assert!(
            !is_lockfile_change_expected_with_source(Some(99999), &mock),
            "lockfile change with unavailable lineage should be unexpected"
        );
    }

    #[test]
    fn lockfile_change_unexpected_when_no_pid() {
        assert!(
            !is_lockfile_change_expected(None),
            "lockfile change with no PID should be unexpected"
        );
    }

    #[test]
    fn each_npm_manager_recognised() {
        for manager_name in &["npm", "node", "yarn", "pnpm", "bun"] {
            let mock = MockProcFs::new().process(42, manager_name, None);

            assert!(
                is_lockfile_change_expected_with_source(Some(42), &mock),
                "{manager_name} should be recognised as a known package manager"
            );
        }
    }

    #[test]
    fn pip_also_recognised_as_package_manager() {
        let mock = MockProcFs::new()
            .process(1, "init", None)
            .process(50, "pip", Some(1))
            .process(100, "python3", Some(50));

        assert!(
            is_lockfile_change_expected_with_source(Some(100), &mock),
            "pip should still be recognised"
        );
    }
}

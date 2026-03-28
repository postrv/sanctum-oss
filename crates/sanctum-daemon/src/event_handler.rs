//! Event handlers for filesystem and credential events.
//!
//! Extracted from `main.rs` to reduce its size and improve testability.
//! Each handler receives a [`VerdictContext`] that bundles the common parameters.

use std::io::Read;
use std::path::Path;

use sanctum_sentinel::pth::analyser::{
    analyse_pth_file_with_custom_allowlist, content_hash, FileAnalysis, FileVerdict,
};
use sanctum_sentinel::pth::lineage::{LineageAssessment, ProcessLineage, SystemProcSource};
use sanctum_sentinel::pth::quarantine::{Quarantine, QuarantineMetadata};
use sanctum_sentinel::watcher::{WatchEvent, WatchEventKind};
use sanctum_types::config::SanctumConfig;

use crate::audit;
use crate::context::VerdictContext;

// ── Filesystem (.pth) event handling ────────────────────────────────────────

/// Maximum size for a .pth file to be read for analysis (1 MB).
const MAX_PTH_READ_SIZE: u64 = 1_048_576;

/// Read a file with a bounded size limit, avoiding TOCTOU races.
///
/// Opens the file and reads up to `max_size + 1` bytes via `Read::take()`.
/// Returns `Ok(None)` if the file exceeds `max_size` bytes, `Ok(Some(content))`
/// on success, or `Err` on I/O failure.
fn bounded_read_file(path: &Path, max_size: u64) -> Result<Option<String>, std::io::Error> {
    let file = std::fs::File::open(path)?;
    let mut reader = file.take(max_size + 1);
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    if buf.len() as u64 > max_size {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

/// Handle a filesystem watch event for a `.pth` file.
///
/// Reads the file, analyses its content, traces process lineage, and dispatches
/// to the appropriate verdict handler based on the analysis result.
pub fn handle_watch_event(
    event: &WatchEvent,
    quarantine: &Quarantine,
    config: &SanctumConfig,
    audit_path: &Path,
) {
    match event.kind {
        WatchEventKind::Created | WatchEventKind::Modified => {
            tracing::info!(path = %event.path.display(), "detected .pth file change");

            // Perform a single bounded read to avoid TOCTOU: instead of checking
            // metadata then reading, we open the file and use `Read::take()` to
            // limit the number of bytes consumed in one atomic operation.
            let content = match bounded_read_file(&event.path, MAX_PTH_READ_SIZE) {
                Ok(Some(c)) => c,
                Ok(None) => {
                    tracing::warn!(
                        path = %event.path.display(),
                        "file too large to analyse (max {MAX_PTH_READ_SIZE} bytes)"
                    );
                    return;
                }
                Err(e) => {
                    tracing::warn!(path = %event.path.display(), %e, "failed to read file");
                    return;
                }
            };

            // Extract package name from the .pth file stem (e.g. "setuptools.pth" -> "setuptools")
            let package_name = event
                .path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown");

            let hash = content_hash(content.as_bytes());
            // Merge user-configured pth_allowlist with the built-in defaults
            let custom_allowlist = if config.sentinel.pth_allowlist.is_empty() {
                None
            } else {
                Some(config.sentinel.pth_allowlist.as_slice())
            };
            let analysis = analyse_pth_file_with_custom_allowlist(
                &content,
                package_name,
                &hash,
                custom_allowlist,
            );

            // Attempt to determine the creator process (best-effort)
            let (creator_pid, creator_exe, lineage_assessment) = try_find_creator_pid(&event.path)
                .map_or(
                    (None, None, LineageAssessment::Undetermined),
                    trace_creator_lineage,
                );

            // Determine the effective threat level, escalating if lineage is suspicious
            let escalate_for_lineage =
                lineage_assessment == LineageAssessment::SuspiciousPythonStartup;

            let ctx = VerdictContext {
                event,
                creator_pid,
                creator_exe,
                audit_path,
            };

            match analysis.verdict {
                FileVerdict::Safe | FileVerdict::AllowlistedKnownPackage => {
                    handle_safe_verdict(&ctx, escalate_for_lineage);
                }
                FileVerdict::Warning => {
                    handle_warning_verdict(&ctx, &analysis, escalate_for_lineage);
                }
                FileVerdict::Critical => {
                    handle_critical_verdict(&ctx, &analysis, &hash, config, quarantine);
                }
            }
        }
        WatchEventKind::Deleted => {
            tracing::info!(path = %event.path.display(), "watched file deleted");
        }
    }
}

// ── Credential event handling ───────────────────────────────────────────────

/// Handle a credential file event by creating a threat event and sending notification.
pub fn handle_credential_event(
    event: &sanctum_sentinel::credentials::CredentialEvent,
    audit_path: &Path,
) {
    match event {
        sanctum_sentinel::credentials::CredentialEvent::AccessDetected {
            path,
            accessor_pid,
            accessor_name,
            allowed,
        } => {
            if *allowed {
                tracing::debug!(
                    path = %path.display(),
                    accessor = accessor_name.as_deref().unwrap_or("unknown"),
                    "credential file accessed by allowed process"
                );
                return;
            }

            let accessor_desc = match (accessor_pid, accessor_name.as_deref()) {
                (Some(pid), Some(name)) => format!("{name} (PID {pid})"),
                (Some(pid), None) => format!("unknown (PID {pid})"),
                (None, Some(name)) => name.to_string(),
                (None, None) => "unknown process".to_string(),
            };

            tracing::warn!(
                path = %path.display(),
                accessor = %accessor_desc,
                "credential file accessed by unexpected process"
            );

            let threat_event = sanctum_types::threat::ThreatEvent {
                timestamp: chrono::Utc::now(),
                level: sanctum_types::threat::ThreatLevel::Warning,
                category: sanctum_types::threat::ThreatCategory::CredentialAccess,
                description: format!(
                    "Credential file {} accessed by {}",
                    path.display(),
                    accessor_desc,
                ),
                source_path: path.clone(),
                creator_pid: *accessor_pid,
                creator_exe: None,
                action_taken: sanctum_types::threat::Action::Alerted,
            };
            sanctum_notify::notify_threat(&threat_event);
            audit::append_audit_event(&threat_event, audit_path);
        }
        sanctum_sentinel::credentials::CredentialEvent::Modified { path } => {
            tracing::info!(
                path = %path.display(),
                "credential file modified"
            );
        }
    }
}

// ── Network event handling ─────────────────────────────────────────────────

/// Handle a network anomaly event by creating a threat event and sending notification.
pub fn handle_network_event(event: &sanctum_sentinel::network::NetworkEvent, audit_path: &Path) {
    match event {
        sanctum_sentinel::network::NetworkEvent::AnomalousConnection {
            pid,
            process_name,
            remote_addr,
            anomaly,
            ..
        } => {
            let process_desc = match (pid, process_name.as_deref()) {
                (Some(p), Some(name)) => format!("{name} (PID {p})"),
                (Some(p), None) => format!("unknown (PID {p})"),
                (None, Some(name)) => name.to_string(),
                (None, None) => "unknown process".to_string(),
            };

            tracing::warn!(
                %remote_addr,
                process = %process_desc,
                anomaly = ?anomaly,
                "network anomaly detected"
            );

            let threat_event = sanctum_types::threat::ThreatEvent {
                timestamp: chrono::Utc::now(),
                level: sanctum_types::threat::ThreatLevel::Warning,
                category: sanctum_types::threat::ThreatCategory::NetworkAnomaly,
                description: format!(
                    "Anomalous connection to {remote_addr} by {process_desc}: {anomaly:?}"
                ),
                source_path: pid
                    .map(|p| std::path::PathBuf::from(format!("pid:{p}")))
                    .unwrap_or_default(),
                creator_pid: *pid,
                creator_exe: None,
                action_taken: sanctum_types::threat::Action::Alerted,
            };
            sanctum_notify::notify_threat(&threat_event);
            crate::audit::append_audit_event(&threat_event, audit_path);
        }
        sanctum_sentinel::network::NetworkEvent::BlocklistedDestination {
            pid,
            process_name,
            remote_addr,
            reason,
        } => {
            let process_desc = match (pid, process_name.as_deref()) {
                (Some(p), Some(name)) => format!("{name} (PID {p})"),
                (Some(p), None) => format!("unknown (PID {p})"),
                (None, Some(name)) => name.to_string(),
                (None, None) => "unknown process".to_string(),
            };

            tracing::error!(
                %remote_addr,
                process = %process_desc,
                reason = %reason,
                "blocklisted destination detected"
            );

            let threat_event = sanctum_types::threat::ThreatEvent {
                timestamp: chrono::Utc::now(),
                level: sanctum_types::threat::ThreatLevel::Critical,
                category: sanctum_types::threat::ThreatCategory::NetworkAnomaly,
                description: format!(
                    "Connection to blocklisted destination {remote_addr} by {process_desc}: {reason}"
                ),
                source_path: pid
                    .map(|p| std::path::PathBuf::from(format!("pid:{p}")))
                    .unwrap_or_default(),
                creator_pid: *pid,
                creator_exe: None,
                action_taken: sanctum_types::threat::Action::Alerted,
            };
            sanctum_notify::notify_threat(&threat_event);
            crate::audit::append_audit_event(&threat_event, audit_path);
        }
    }
}

// ── Verdict handlers ────────────────────────────────────────────────────────

/// Handle a safe or allowlisted .pth file verdict, escalating if lineage is suspicious.
fn handle_safe_verdict(ctx: &VerdictContext<'_>, escalate_for_lineage: bool) {
    if escalate_for_lineage {
        // File content looks safe but was created by Python startup --
        // this is unusual and worth alerting on.
        tracing::warn!(
            path = %ctx.event.path.display(),
            creator_pid = ?ctx.creator_pid,
            "safe .pth file created during suspicious Python startup"
        );
        let threat_event = sanctum_types::threat::ThreatEvent {
            timestamp: chrono::Utc::now(),
            level: sanctum_types::threat::ThreatLevel::Warning,
            category: sanctum_types::threat::ThreatCategory::PthInjection,
            description: format!(
                "Safe .pth file created during suspicious Python startup: {}",
                ctx.event.path.display()
            ),
            source_path: ctx.event.path.clone(),
            creator_pid: ctx.creator_pid,
            creator_exe: ctx.creator_exe.clone(),
            action_taken: sanctum_types::threat::Action::Alerted,
        };
        sanctum_notify::notify_threat(&threat_event);
        audit::append_audit_event(&threat_event, ctx.audit_path);
    } else {
        tracing::debug!(path = %ctx.event.path.display(), "file is safe");
    }
}

/// Handle a warning-level .pth file verdict, escalating if lineage is suspicious.
fn handle_warning_verdict(
    ctx: &VerdictContext<'_>,
    analysis: &FileAnalysis,
    escalate_for_lineage: bool,
) {
    // Escalate to Critical if the lineage is suspicious
    let level = if escalate_for_lineage {
        sanctum_types::threat::ThreatLevel::Critical
    } else {
        sanctum_types::threat::ThreatLevel::Warning
    };

    tracing::warn!(
        path = %ctx.event.path.display(),
        warnings = analysis.warning_lines.len(),
        ?level,
        "file contains suspicious imports"
    );
    // For warning-level findings, notify but don't quarantine
    let threat_event = sanctum_types::threat::ThreatEvent {
        timestamp: chrono::Utc::now(),
        level,
        category: sanctum_types::threat::ThreatCategory::PthInjection,
        description: format!("Suspicious import found in {}", ctx.event.path.display()),
        source_path: ctx.event.path.clone(),
        creator_pid: ctx.creator_pid,
        creator_exe: ctx.creator_exe.clone(),
        action_taken: sanctum_types::threat::Action::Alerted,
    };
    sanctum_notify::notify_threat(&threat_event);
    audit::append_audit_event(&threat_event, ctx.audit_path);
}

/// Handle a critical .pth file verdict by quarantining, alerting, or logging based on config.
#[allow(clippy::too_many_lines)]
fn handle_critical_verdict(
    ctx: &VerdictContext<'_>,
    analysis: &FileAnalysis,
    hash: &str,
    config: &SanctumConfig,
    quarantine: &Quarantine,
) {
    tracing::error!(
        path = %ctx.event.path.display(),
        critical_lines = analysis.critical_lines.len(),
        creator_pid = ?ctx.creator_pid,
        "CRITICAL: malicious .pth file detected"
    );

    match config.sentinel.pth_response {
        sanctum_types::config::PthResponse::Quarantine => {
            let metadata = QuarantineMetadata {
                original_path: ctx.event.path.clone(),
                content_hash: hash.to_string(),
                creator_pid: ctx.creator_pid,
                reason: analysis
                    .critical_lines
                    .iter()
                    .flat_map(|l| l.reasons.iter())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
                quarantined_at: chrono::Utc::now(),
            };

            let (action_taken, description) =
                match quarantine.quarantine_file(&ctx.event.path, &metadata) {
                    Ok(entry) => {
                        tracing::info!(
                            id = entry.id,
                            path = %ctx.event.path.display(),
                            "file quarantined"
                        );
                        (
                            sanctum_types::threat::Action::Quarantined,
                            format!(
                                "Malicious .pth file quarantined: {}",
                                ctx.event.path.display()
                            ),
                        )
                    }
                    Err(e) => {
                        tracing::error!(
                            path = %ctx.event.path.display(),
                            %e,
                            "failed to quarantine file"
                        );
                        (
                            sanctum_types::threat::Action::Logged,
                            format!(
                                "Malicious .pth file detected (quarantine failed: {e}): {}",
                                ctx.event.path.display()
                            ),
                        )
                    }
                };

            let threat_event = sanctum_types::threat::ThreatEvent {
                timestamp: chrono::Utc::now(),
                level: sanctum_types::threat::ThreatLevel::Critical,
                category: sanctum_types::threat::ThreatCategory::PthInjection,
                description,
                source_path: ctx.event.path.clone(),
                creator_pid: ctx.creator_pid,
                creator_exe: ctx.creator_exe.clone(),
                action_taken,
            };
            sanctum_notify::notify_threat(&threat_event);
            audit::append_audit_event(&threat_event, ctx.audit_path);
        }
        sanctum_types::config::PthResponse::Alert => {
            let threat_event = sanctum_types::threat::ThreatEvent {
                timestamp: chrono::Utc::now(),
                level: sanctum_types::threat::ThreatLevel::Critical,
                category: sanctum_types::threat::ThreatCategory::PthInjection,
                description: format!("Malicious .pth file detected: {}", ctx.event.path.display()),
                source_path: ctx.event.path.clone(),
                creator_pid: ctx.creator_pid,
                creator_exe: ctx.creator_exe.clone(),
                action_taken: sanctum_types::threat::Action::Alerted,
            };
            sanctum_notify::notify_threat(&threat_event);
            audit::append_audit_event(&threat_event, ctx.audit_path);
        }
        sanctum_types::config::PthResponse::Log => {
            tracing::error!(
                path = %ctx.event.path.display(),
                creator_pid = ?ctx.creator_pid,
                "malicious .pth detected (log-only mode)"
            );
            let threat_event = sanctum_types::threat::ThreatEvent {
                timestamp: chrono::Utc::now(),
                level: sanctum_types::threat::ThreatLevel::Critical,
                category: sanctum_types::threat::ThreatCategory::PthInjection,
                description: format!(
                    "Malicious .pth file detected (log-only): {}",
                    ctx.event.path.display()
                ),
                source_path: ctx.event.path.clone(),
                creator_pid: ctx.creator_pid,
                creator_exe: ctx.creator_exe.clone(),
                action_taken: sanctum_types::threat::Action::Logged,
            };
            sanctum_notify::notify_threat(&threat_event);
            audit::append_audit_event(&threat_event, ctx.audit_path);
        }
    }
}

// ── Process lineage helpers ─────────────────────────────────────────────────

/// Best-effort attempt to find the PID of the process that created or modified a file.
///
/// On Linux, scans `/proc/*/fd/` for open file descriptors pointing to the given path.
/// On macOS, this is extremely difficult without elevated privileges, so we skip it.
///
/// This is inherently racy: the creating process may have already closed the file
/// descriptor by the time we scan. The result is best-effort and may return `None`.
const fn try_find_creator_pid(_path: &Path) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        linux_find_creator_pid(_path)
    }

    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Linux-specific: scan `/proc/*/fd/` to find a process with the given file open.
#[cfg(target_os = "linux")]
fn linux_find_creator_pid(path: &Path) -> Option<u32> {
    use std::fs;

    let proc_entries = fs::read_dir("/proc").ok()?;

    for entry in proc_entries.flatten() {
        let pid_str = entry.file_name();
        let pid_str = pid_str.to_str()?;
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };

        for fd_entry in fds.flatten() {
            if let Ok(link_target) = fs::read_link(fd_entry.path()) {
                if link_target == path {
                    return Some(pid);
                }
            }
        }
    }

    None
}

/// Trace process lineage for a given PID and return the assessment,
/// creator PID, and creator executable path.
///
/// Returns `(creator_pid, creator_exe, assessment)`. If lineage tracing
/// fails (process already exited, etc.), returns the PID with `None` exe
/// and `Undetermined` assessment.
fn trace_creator_lineage(pid: u32) -> (Option<u32>, Option<std::path::PathBuf>, LineageAssessment) {
    match ProcessLineage::trace(pid, &SystemProcSource) {
        Ok(lineage) => {
            let assessment = lineage.assess_pth_creation();
            let creator_exe = lineage.root_ancestor().and_then(|p| p.exe.clone());
            tracing::info!(
                pid,
                assessment = ?assessment,
                "process lineage traced"
            );
            (Some(pid), creator_exe, assessment)
        }
        Err(e) => {
            tracing::debug!(
                pid,
                %e,
                "failed to trace process lineage (process may have exited)"
            );
            (Some(pid), None, LineageAssessment::Undetermined)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Helper: create a temp file with the given content and return (dir, path).
    /// Returns `None` if file creation fails (test will be skipped).
    fn create_temp_file(
        name: &str,
        data: &[u8],
    ) -> Option<(tempfile::TempDir, std::path::PathBuf)> {
        let dir = tempfile::tempdir().ok()?;
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).ok()?;
        f.write_all(data).ok()?;
        drop(f);
        Some((dir, path))
    }

    #[test]
    fn bounded_read_returns_content_for_small_file() {
        let Some((_dir, path)) = create_temp_file("small.txt", b"hello world") else {
            return;
        };
        let result = bounded_read_file(&path, 1024);
        assert!(result.is_ok());
        let inner = result.ok();
        assert!(inner.is_some());
        let content = inner.and_then(|o| o);
        assert_eq!(content.as_deref(), Some("hello world"));
    }

    #[test]
    fn bounded_read_returns_none_for_oversized_file() {
        let Some((_dir, path)) = create_temp_file("big.txt", &[b'x'; 11]) else {
            return;
        };
        // Limit is 10 bytes, file is 11 bytes — should return Ok(None)
        let result = bounded_read_file(&path, 10);
        assert!(result.is_ok());
        let inner = result.ok();
        // Ok(None) means file too large
        assert_eq!(inner, Some(None));
    }

    #[test]
    fn bounded_read_returns_content_at_exact_limit() {
        let Some((_dir, path)) = create_temp_file("exact.txt", &[b'a'; 10]) else {
            return;
        };
        // Limit is 10 bytes, file is exactly 10 bytes — should succeed
        let result = bounded_read_file(&path, 10);
        assert!(result.is_ok());
        let content = result.ok().and_then(|o| o);
        assert!(content.is_some());
        assert_eq!(content.as_ref().map(String::len), Some(10));
    }

    #[test]
    fn bounded_read_returns_error_for_nonexistent_file() {
        let result = bounded_read_file(Path::new("/nonexistent/file.txt"), 1024);
        assert!(result.is_err(), "expected error for nonexistent file");
    }

    // ============================================================
    // W4: PthResponse::Log generates audit events
    // ============================================================

    #[test]
    fn pth_response_log_generates_audit_event() {
        use sanctum_types::config::PthResponse;

        let Some((dir, pth_path)) =
            create_temp_file("evil.pth", b"import base64;exec(base64.b64decode('...'))")
        else {
            return;
        };
        let audit_path = dir.path().join("audit.log");

        let mut config = SanctumConfig::default();
        config.sentinel.pth_response = PthResponse::Log;

        let quarantine =
            sanctum_sentinel::pth::quarantine::Quarantine::new(dir.path().join("quarantine"));

        let event = WatchEvent {
            path: pth_path,
            kind: sanctum_sentinel::watcher::WatchEventKind::Created,
        };

        handle_watch_event(&event, &quarantine, &config, &audit_path);

        // The audit log should now contain an entry for the detected threat
        let audit_contents = std::fs::read_to_string(&audit_path).unwrap_or_default();
        assert!(
            audit_contents.contains("PthInjection"),
            "audit log should contain a PthInjection entry for log-mode events, got: {audit_contents}"
        );
        assert!(
            audit_contents.contains("Logged"),
            "audit log should record action as Logged, got: {audit_contents}"
        );
    }

    // ============================================================
    // H3: Quarantine failure records Action::Logged, not Action::Quarantined
    // ============================================================

    #[test]
    fn quarantine_failure_records_logged_action() {
        use sanctum_types::config::PthResponse;

        let Some((dir, pth_path)) =
            create_temp_file("evil.pth", b"import base64;exec(base64.b64decode('...'))")
        else {
            return;
        };
        let audit_path = dir.path().join("audit.log");

        let mut config = SanctumConfig::default();
        config.sentinel.pth_response = PthResponse::Quarantine;

        // Use a quarantine directory that is not writable (nonexistent parent
        // with a long path that cannot be created to provoke failure).
        let quarantine = sanctum_sentinel::pth::quarantine::Quarantine::new(
            std::path::PathBuf::from("/dev/null/impossible/quarantine"),
        );

        let event = WatchEvent {
            path: pth_path,
            kind: sanctum_sentinel::watcher::WatchEventKind::Created,
        };

        handle_watch_event(&event, &quarantine, &config, &audit_path);

        let audit_contents = std::fs::read_to_string(&audit_path).unwrap_or_default();
        assert!(
            audit_contents.contains("PthInjection"),
            "audit log should contain a PthInjection entry, got: {audit_contents}"
        );
        // When quarantine fails, the action should be Logged, NOT Quarantined
        assert!(
            audit_contents.contains("Logged"),
            "audit log should record action as Logged on quarantine failure, got: {audit_contents}"
        );
        assert!(
            !audit_contents.contains("Quarantined"),
            "audit log must NOT record action as Quarantined on quarantine failure, got: {audit_contents}"
        );
        assert!(
            audit_contents.contains("quarantine failed"),
            "audit log description should mention quarantine failure, got: {audit_contents}"
        );
    }

    // ============================================================
    // H3: Successful quarantine records Action::Quarantined
    // ============================================================

    #[test]
    fn quarantine_success_records_quarantined_action() {
        use sanctum_types::config::PthResponse;

        let Some((dir, pth_path)) =
            create_temp_file("evil.pth", b"import base64;exec(base64.b64decode('...'))")
        else {
            return;
        };
        let audit_path = dir.path().join("audit.log");

        let mut config = SanctumConfig::default();
        config.sentinel.pth_response = PthResponse::Quarantine;

        // Use a valid, writable quarantine directory
        let quarantine =
            sanctum_sentinel::pth::quarantine::Quarantine::new(dir.path().join("quarantine"));

        let event = WatchEvent {
            path: pth_path,
            kind: sanctum_sentinel::watcher::WatchEventKind::Created,
        };

        handle_watch_event(&event, &quarantine, &config, &audit_path);

        let audit_contents = std::fs::read_to_string(&audit_path).unwrap_or_default();
        assert!(
            audit_contents.contains("Quarantined"),
            "audit log should record action as Quarantined on success, got: {audit_contents}"
        );
    }
}

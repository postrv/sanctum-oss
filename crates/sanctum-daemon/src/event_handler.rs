//! Event handlers for filesystem and credential events.
//!
//! Extracted from `main.rs` to reduce its size and improve testability.
//! Each handler receives a [`VerdictContext`] that bundles the common parameters.

use std::path::Path;

use sanctum_sentinel::pth::analyser::{analyse_pth_file_with_context, content_hash, FileAnalysis, FileVerdict};
use sanctum_sentinel::pth::lineage::{LineageAssessment, ProcessLineage, SystemProcSource};
use sanctum_sentinel::pth::quarantine::{Quarantine, QuarantineMetadata};
use sanctum_sentinel::watcher::{WatchEvent, WatchEventKind};
use sanctum_types::config::SanctumConfig;

use crate::audit;
use crate::context::VerdictContext;

// ── Filesystem (.pth) event handling ────────────────────────────────────────

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

            // Read the file content (use read + from_utf8_lossy so non-UTF-8
            // bytes are replaced with U+FFFD rather than silently skipping the file)
            let content = match std::fs::read(&event.path) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
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
            let analysis = analyse_pth_file_with_context(&content, package_name, &hash);

            // Attempt to determine the creator process (best-effort)
            let (creator_pid, creator_exe, lineage_assessment) =
                try_find_creator_pid(&event.path).map_or(
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
pub fn handle_network_event(
    event: &sanctum_sentinel::network::NetworkEvent,
    audit_path: &Path,
) {
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
        description: format!(
            "Suspicious import found in {}",
            ctx.event.path.display()
        ),
        source_path: ctx.event.path.clone(),
        creator_pid: ctx.creator_pid,
        creator_exe: ctx.creator_exe.clone(),
        action_taken: sanctum_types::threat::Action::Alerted,
    };
    sanctum_notify::notify_threat(&threat_event);
    audit::append_audit_event(&threat_event, ctx.audit_path);
}

/// Handle a critical .pth file verdict by quarantining, alerting, or logging based on config.
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

            match quarantine.quarantine_file(&ctx.event.path, &metadata) {
                Ok(entry) => {
                    tracing::info!(
                        id = entry.id,
                        path = %ctx.event.path.display(),
                        "file quarantined"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        path = %ctx.event.path.display(),
                        %e,
                        "failed to quarantine file"
                    );
                }
            }

            let threat_event = sanctum_types::threat::ThreatEvent {
                timestamp: chrono::Utc::now(),
                level: sanctum_types::threat::ThreatLevel::Critical,
                category: sanctum_types::threat::ThreatCategory::PthInjection,
                description: format!(
                    "Malicious .pth file quarantined: {}",
                    ctx.event.path.display()
                ),
                source_path: ctx.event.path.clone(),
                creator_pid: ctx.creator_pid,
                creator_exe: ctx.creator_exe.clone(),
                action_taken: sanctum_types::threat::Action::Quarantined,
            };
            sanctum_notify::notify_threat(&threat_event);
            audit::append_audit_event(&threat_event, ctx.audit_path);
        }
        sanctum_types::config::PthResponse::Alert => {
            let threat_event = sanctum_types::threat::ThreatEvent {
                timestamp: chrono::Utc::now(),
                level: sanctum_types::threat::ThreatLevel::Critical,
                category: sanctum_types::threat::ThreatCategory::PthInjection,
                description: format!(
                    "Malicious .pth file detected: {}",
                    ctx.event.path.display()
                ),
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
fn trace_creator_lineage(
    pid: u32,
) -> (Option<u32>, Option<std::path::PathBuf>, LineageAssessment) {
    match ProcessLineage::trace(pid, &SystemProcSource) {
        Ok(lineage) => {
            let assessment = lineage.assess_pth_creation();
            let creator_exe = lineage
                .root_ancestor()
                .exe
                .clone();
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

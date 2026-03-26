//! Threat classification types.
//!
//! These types represent the core threat model: every security event is
//! classified by level, category, and the action taken in response.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Severity level for a detected threat.
///
/// Ordered from least to most severe. The `Ord` derivation ensures
/// `Info < Warning < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ThreatLevel {
    /// Informational — logged but no action taken.
    Info,
    /// Warning — potentially suspicious, may require review.
    Warning,
    /// Critical — active threat detected, immediate action taken.
    Critical,
}

/// Category of threat detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatCategory {
    /// Malicious or suspicious `.pth` file injection.
    PthInjection,
    /// Suspicious `sitecustomize.py` or `usercustomize.py` modification.
    SiteCustomize,
    /// Unexpected access to credential files (SSH keys, cloud creds, etc.).
    CredentialAccess,
    /// Anomalous network activity from a developer process.
    NetworkAnomaly,
}

/// Action taken in response to a detected threat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    /// Event logged, no further action.
    Logged,
    /// Desktop notification sent to developer.
    Alerted,
    /// File moved to quarantine, replaced with empty stub.
    Quarantined,
    /// Process or network connection blocked.
    Blocked,
}

/// A complete threat event record, suitable for audit logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    /// When the threat was detected.
    pub timestamp: DateTime<Utc>,
    /// Severity classification.
    pub level: ThreatLevel,
    /// Category of the threat.
    pub category: ThreatCategory,
    /// Human-readable description of what was detected.
    pub description: String,
    /// Filesystem path that triggered the event.
    pub source_path: PathBuf,
    /// PID of the process that created/modified the file, if known.
    pub creator_pid: Option<u32>,
    /// Executable path of the creating process, if known.
    pub creator_exe: Option<PathBuf>,
    /// What action Sanctum took in response.
    pub action_taken: Action,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_level_has_correct_ordering() {
        assert!(ThreatLevel::Info < ThreatLevel::Warning);
        assert!(ThreatLevel::Warning < ThreatLevel::Critical);
        assert!(ThreatLevel::Info < ThreatLevel::Critical);
    }

    #[test]
    fn threat_event_serialises_to_json_for_audit_log() {
        let event = ThreatEvent {
            timestamp: Utc::now(),
            level: ThreatLevel::Critical,
            category: ThreatCategory::PthInjection,
            description: "Executable .pth with base64".into(),
            source_path: PathBuf::from("/usr/lib/python3.12/site-packages/evil.pth"),
            creator_pid: Some(12345),
            creator_exe: Some(PathBuf::from("/usr/bin/python3.12")),
            action_taken: Action::Quarantined,
        };
        let json = serde_json::to_string(&event).expect("serialisation should succeed");
        assert!(json.contains("PthInjection"));
        assert!(json.contains("Quarantined"));
    }
}

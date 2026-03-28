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
    /// MCP tool policy violation.
    McpViolation,
    /// LLM spend budget exceeded.
    BudgetOverrun,
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

impl ThreatEvent {
    /// Compute a short content-addressed ID for this event.
    ///
    /// Format: first 32 hex chars (128-bit) of SHA-256(timestamp || category || `source_path`).
    #[must_use]
    pub fn threat_id(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(format!("{:?}", self.category).as_bytes());
        hasher.update(self.source_path.to_string_lossy().as_bytes());
        let hash = hasher.finalize();
        hex::encode(&hash[..16])
    }
}

/// A record that a threat has been resolved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatResolution {
    /// The threat ID that was resolved.
    pub threat_id: String,
    /// When the resolution was applied.
    pub resolved_at: DateTime<Utc>,
    /// What action was taken.
    pub resolution: ResolutionAction,
    /// Human-readable note.
    pub note: String,
}

/// Actions that can resolve a threat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolutionAction {
    /// Quarantined file was restored.
    Restored,
    /// Quarantined file was permanently deleted.
    Deleted,
    /// Threat was acknowledged without action.
    Dismissed,
    /// Process was added to credential access allowlist.
    Allowlisted,
    /// MCP policy rules were updated.
    PolicyUpdated,
    /// Budget limits were adjusted.
    BudgetAdjusted,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use chrono::TimeZone;

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

    #[test]
    fn threat_id_is_deterministic() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let event = ThreatEvent {
            timestamp: ts,
            level: ThreatLevel::Critical,
            category: ThreatCategory::PthInjection,
            description: "test".into(),
            source_path: PathBuf::from("/tmp/evil.pth"),
            creator_pid: None,
            creator_exe: None,
            action_taken: Action::Quarantined,
        };
        let id1 = event.threat_id();
        let id2 = event.threat_id();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn threat_id_differs_for_different_events() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let event_a = ThreatEvent {
            timestamp: ts,
            level: ThreatLevel::Critical,
            category: ThreatCategory::PthInjection,
            description: "a".into(),
            source_path: PathBuf::from("/tmp/evil.pth"),
            creator_pid: None,
            creator_exe: None,
            action_taken: Action::Quarantined,
        };
        let event_b = ThreatEvent {
            timestamp: ts,
            level: ThreatLevel::Warning,
            category: ThreatCategory::CredentialAccess,
            description: "b".into(),
            source_path: PathBuf::from("/home/user/.ssh/id_rsa"),
            creator_pid: None,
            creator_exe: None,
            action_taken: Action::Alerted,
        };
        assert_ne!(event_a.threat_id(), event_b.threat_id());
    }

    #[test]
    fn threat_resolution_serialises_roundtrip() {
        let resolution = ThreatResolution {
            threat_id: "abcdef012345".to_string(),
            resolved_at: Utc::now(),
            resolution: ResolutionAction::Restored,
            note: "File verified safe by developer".to_string(),
        };
        let json = serde_json::to_string(&resolution).expect("serialise");
        let roundtripped: ThreatResolution =
            serde_json::from_str(&json).expect("deserialise");
        assert_eq!(roundtripped.threat_id, "abcdef012345");
        assert_eq!(roundtripped.resolution, ResolutionAction::Restored);
        assert_eq!(roundtripped.note, "File verified safe by developer");
    }

    #[test]
    fn new_threat_categories_serialise() {
        // McpViolation
        let json = serde_json::to_string(&ThreatCategory::McpViolation)
            .expect("serialise McpViolation");
        assert_eq!(json, "\"McpViolation\"");
        let roundtripped: ThreatCategory =
            serde_json::from_str(&json).expect("deserialise McpViolation");
        assert_eq!(roundtripped, ThreatCategory::McpViolation);

        // BudgetOverrun
        let json = serde_json::to_string(&ThreatCategory::BudgetOverrun)
            .expect("serialise BudgetOverrun");
        assert_eq!(json, "\"BudgetOverrun\"");
        let roundtripped: ThreatCategory =
            serde_json::from_str(&json).expect("deserialise BudgetOverrun");
        assert_eq!(roundtripped, ThreatCategory::BudgetOverrun);
    }
}

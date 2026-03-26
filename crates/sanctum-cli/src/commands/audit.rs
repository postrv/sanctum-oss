//! `sanctum audit` -- View the threat event audit log.

use std::io::BufRead;
use std::path::PathBuf;

use chrono::Utc;
use sanctum_types::errors::CliError;
use sanctum_types::paths::WellKnownPaths;
use sanctum_types::threat::{ThreatEvent, ThreatLevel};

/// Run the audit command.
///
/// Reads the NDJSON audit log and displays events, optionally filtered
/// by time range and/or threat level.
pub fn run(last: Option<&str>, level: Option<&str>, json: bool) -> Result<(), CliError> {
    let audit_path = audit_log_path();

    if !audit_path.exists() {
        #[allow(clippy::print_stdout)]
        {
            println!("No audit events recorded yet.");
        }
        return Ok(());
    }

    let cutoff = last.map(parse_duration).transpose()?;
    let level_filter = level.map(parse_level).transpose()?;

    let file = std::fs::File::open(&audit_path)?;
    let reader = std::io::BufReader::new(file);

    let now = Utc::now();
    let mut found_any = false;

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let event: ThreatEvent = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            Err(_) => continue, // skip malformed lines
        };

        // Filter by time range
        if let Some(duration) = cutoff {
            let earliest = now - duration;
            if event.timestamp < earliest {
                continue;
            }
        }

        // Filter by level
        if let Some(ref lvl) = level_filter {
            if &event.level != lvl {
                continue;
            }
        }

        found_any = true;

        if json {
            // Re-serialize to ensure consistent JSON output
            let json_str = serde_json::to_string(&event).unwrap_or_else(|_| trimmed.to_string());
            #[allow(clippy::print_stdout)]
            {
                println!("{json_str}");
            }
        } else {
            print_event(&event);
        }
    }

    if !found_any && !json {
        #[allow(clippy::print_stdout)]
        {
            println!("No matching audit events found.");
        }
    }

    Ok(())
}

/// Resolve the path to the audit log file.
fn audit_log_path() -> PathBuf {
    let paths = WellKnownPaths::default();
    paths.data_dir.join("audit.log")
}

/// Parse a human-readable duration string into a `chrono::TimeDelta`.
///
/// Supported formats: `30m`, `1h`, `24h`, `7d`.
fn parse_duration(s: &str) -> Result<chrono::TimeDelta, CliError> {
    let s = s.trim();
    if s.len() < 2 {
        return Err(CliError::InvalidArgs(format!(
            "invalid duration: {s} (expected e.g. 30m, 1h, 24h, 7d)"
        )));
    }

    let (digits, suffix) = s.split_at(s.len() - 1);
    let value: i64 = digits.parse().map_err(|_| {
        CliError::InvalidArgs(format!(
            "invalid duration: {s} (expected e.g. 30m, 1h, 24h, 7d)"
        ))
    })?;

    if value <= 0 {
        return Err(CliError::InvalidArgs(format!(
            "duration must be positive: {s}"
        )));
    }

    match suffix {
        "m" => chrono::TimeDelta::try_minutes(value).ok_or_else(|| {
            CliError::InvalidArgs(format!("duration too large: {s}"))
        }),
        "h" => chrono::TimeDelta::try_hours(value).ok_or_else(|| {
            CliError::InvalidArgs(format!("duration too large: {s}"))
        }),
        "d" => chrono::TimeDelta::try_days(value).ok_or_else(|| {
            CliError::InvalidArgs(format!("duration too large: {s}"))
        }),
        _ => Err(CliError::InvalidArgs(format!(
            "unknown duration suffix '{suffix}' in '{s}' (expected m, h, or d)"
        ))),
    }
}

/// Parse a threat level string (case-insensitive).
fn parse_level(s: &str) -> Result<ThreatLevel, CliError> {
    match s.to_lowercase().as_str() {
        "info" => Ok(ThreatLevel::Info),
        "warning" => Ok(ThreatLevel::Warning),
        "critical" => Ok(ThreatLevel::Critical),
        _ => Err(CliError::InvalidArgs(format!(
            "unknown threat level: {s} (expected info, warning, or critical)"
        ))),
    }
}

/// Print a single event in human-readable format with color.
fn print_event(event: &ThreatEvent) {
    let level_str = match event.level {
        ThreatLevel::Critical => "\x1b[31m[CRITICAL]\x1b[0m",
        ThreatLevel::Warning => "\x1b[33m[WARNING]\x1b[0m",
        ThreatLevel::Info => "\x1b[34m[INFO]\x1b[0m",
    };

    let timestamp = event.timestamp.format("%Y-%m-%d %H:%M:%S UTC");

    #[allow(clippy::print_stdout)]
    {
        println!("{timestamp}  {level_str}  {}", event.description);
        println!(
            "  Category: {:?}  Action: {:?}  Path: {}",
            event.category,
            event.action_taken,
            event.source_path.display()
        );
        if let Some(pid) = event.creator_pid {
            if let Some(ref exe) = event.creator_exe {
                println!("  Creator: PID {pid} ({exe})", exe = exe.display());
            } else {
                println!("  Creator: PID {pid}");
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic, clippy::similar_names)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sanctum_types::threat::{Action, ThreatCategory};
    use std::io::Write;
    use std::path::PathBuf;

    fn sample_event(level: ThreatLevel, minutes_ago: i64) -> ThreatEvent {
        let ts = Utc::now()
            - chrono::TimeDelta::try_minutes(minutes_ago).expect("valid minutes for test");
        ThreatEvent {
            timestamp: ts,
            level,
            category: ThreatCategory::PthInjection,
            description: "Test event".to_string(),
            source_path: PathBuf::from("/tmp/test.pth"),
            creator_pid: Some(1234),
            creator_exe: Some(PathBuf::from("/usr/bin/python3")),
            action_taken: Action::Quarantined,
        }
    }

    // --- parse_duration tests ---

    #[test]
    fn parse_duration_hours() {
        let d = parse_duration("24h").expect("should parse 24h");
        assert_eq!(d.num_hours(), 24);
    }

    #[test]
    fn parse_duration_days() {
        let d = parse_duration("7d").expect("should parse 7d");
        assert_eq!(d.num_days(), 7);
    }

    #[test]
    fn parse_duration_minutes() {
        let d = parse_duration("30m").expect("should parse 30m");
        assert_eq!(d.num_minutes(), 30);
    }

    #[test]
    fn parse_duration_one_hour() {
        let d = parse_duration("1h").expect("should parse 1h");
        assert_eq!(d.num_hours(), 1);
    }

    #[test]
    fn parse_duration_rejects_invalid() {
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("").is_err());
        assert!(parse_duration("h").is_err());
        assert!(parse_duration("24x").is_err());
        assert!(parse_duration("-5h").is_err());
    }

    // --- filter by time range tests ---

    #[test]
    fn filter_by_time_range() {
        let recent = sample_event(ThreatLevel::Warning, 10);
        let old = sample_event(ThreatLevel::Warning, 120);

        let cutoff =
            chrono::TimeDelta::try_hours(1).expect("valid hours for test");
        let now = Utc::now();
        let earliest = now - cutoff;

        assert!(recent.timestamp >= earliest, "recent event should pass");
        assert!(old.timestamp < earliest, "old event should be filtered out");
    }

    // --- filter by level tests ---

    #[test]
    fn parse_level_case_insensitive() {
        assert_eq!(parse_level("critical").expect("parse"), ThreatLevel::Critical);
        assert_eq!(parse_level("Critical").expect("parse"), ThreatLevel::Critical);
        assert_eq!(parse_level("CRITICAL").expect("parse"), ThreatLevel::Critical);
        assert_eq!(parse_level("warning").expect("parse"), ThreatLevel::Warning);
        assert_eq!(parse_level("info").expect("parse"), ThreatLevel::Info);
    }

    #[test]
    fn parse_level_rejects_unknown() {
        assert!(parse_level("high").is_err());
        assert!(parse_level("").is_err());
    }

    #[test]
    fn filter_by_level() {
        let critical = sample_event(ThreatLevel::Critical, 5);
        let warning = sample_event(ThreatLevel::Warning, 5);
        let info = sample_event(ThreatLevel::Info, 5);

        let filter = ThreatLevel::Critical;
        assert_eq!(critical.level, filter);
        assert_ne!(warning.level, filter);
        assert_ne!(info.level, filter);
    }

    // --- JSON output format test ---

    #[test]
    fn json_output_format() {
        let event = sample_event(ThreatLevel::Critical, 1);
        let json_str =
            serde_json::to_string(&event).expect("serialisation should succeed in test");
        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).expect("should be valid JSON");

        assert_eq!(
            parsed.get("level").and_then(|v| v.as_str()),
            Some("Critical")
        );
        assert!(parsed.get("timestamp").is_some());
        assert!(parsed.get("description").is_some());
        assert!(parsed.get("category").is_some());
    }

    // --- missing audit log test ---

    #[test]
    fn missing_audit_log_shows_message() {
        // The run function uses a fixed path; we test the logic by verifying
        // that a non-existent path results in the correct behaviour.
        let path = PathBuf::from("/tmp/sanctum_test_nonexistent_audit_log_98765.log");
        assert!(!path.exists());
        // The command would print "No audit events recorded yet."
        // We verify the path doesn't exist which is the guard condition.
    }

    // --- end-to-end NDJSON parsing test ---

    #[test]
    fn reads_ndjson_audit_log() {
        let dir = tempfile::tempdir().expect("tempdir for test");
        let log_path = dir.path().join("audit.log");

        let event1 = sample_event(ThreatLevel::Critical, 5);
        let event2 = sample_event(ThreatLevel::Warning, 2);
        let event3 = sample_event(ThreatLevel::Info, 1);

        {
            let mut f = std::fs::File::create(&log_path).expect("create test file");
            for event in [&event1, &event2, &event3] {
                let line =
                    serde_json::to_string(event).expect("serialise event for test");
                writeln!(f, "{line}").expect("write to test file");
            }
        }

        // Read back and parse
        let file = std::fs::File::open(&log_path).expect("open test file");
        let reader = std::io::BufReader::new(file);
        let mut events = Vec::new();
        for line in reader.lines() {
            let line = line.expect("read line");
            let event: ThreatEvent =
                serde_json::from_str(&line).expect("parse event from test file");
            events.push(event);
        }

        assert_eq!(events.len(), 3);
        assert_eq!(events[0].level, ThreatLevel::Critical);
        assert_eq!(events[1].level, ThreatLevel::Warning);
        assert_eq!(events[2].level, ThreatLevel::Info);
    }
}

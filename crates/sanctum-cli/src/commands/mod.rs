pub mod audit;
pub mod budget;
pub mod config;
pub mod daemon;
pub mod doctor;
pub mod fix;
pub mod hook;
pub mod hooks;
pub mod init;
pub mod proxy;
pub mod review;
pub mod run;
pub mod scan;
pub mod status;

use std::io::IsTerminal;

/// Return `true` if colored output should be used.
///
/// Respects the `NO_COLOR` environment variable (<https://no-color.org/>)
/// and checks whether stderr is attached to a terminal.
pub fn use_color() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stderr().is_terminal()
}

/// Return a coloured (or plain) level label for human-readable output.
pub fn colorize_level(level: &str) -> String {
    if use_color() {
        match level {
            "Critical" => "\x1b[31m[CRITICAL]\x1b[0m".to_string(),
            "Warning" => "\x1b[33m[WARNING]\x1b[0m".to_string(),
            "Info" => "\x1b[34m[INFO]\x1b[0m".to_string(),
            other => format!("[{other}]"),
        }
    } else {
        match level {
            "Critical" => "[CRITICAL]".to_string(),
            "Warning" => "[WARNING]".to_string(),
            "Info" => "[INFO]".to_string(),
            other => format!("[{other}]"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn colorize_level_no_ansi_when_color_disabled() {
        // Force NO_COLOR to disable color
        std::env::set_var("NO_COLOR", "1");
        let critical = colorize_level("Critical");
        let warning = colorize_level("Warning");
        let info = colorize_level("Info");
        let other = colorize_level("Debug");
        std::env::remove_var("NO_COLOR");

        // Verify no ANSI escape sequences
        assert!(
            !critical.contains("\x1b["),
            "Critical should have no ANSI escapes"
        );
        assert!(
            !warning.contains("\x1b["),
            "Warning should have no ANSI escapes"
        );
        assert!(!info.contains("\x1b["), "Info should have no ANSI escapes");
        assert!(
            !other.contains("\x1b["),
            "Other should have no ANSI escapes"
        );

        // Verify text content
        assert_eq!(critical, "[CRITICAL]");
        assert_eq!(warning, "[WARNING]");
        assert_eq!(info, "[INFO]");
        assert_eq!(other, "[Debug]");
    }
}

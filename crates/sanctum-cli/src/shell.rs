//! Shell hook generation for auto-starting the daemon.
//!
//! Generates shell-specific hooks for bash, zsh, and fish that:
//! - Auto-start the daemon on first prompt
//! - Set `SANCTUM_ACTIVE=1` for prompt integrations (Starship, etc.)
//! - Provide shell completion

/// Supported shells.
#[derive(Debug, Clone, Copy)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    #[allow(clippy::enum_variant_names)]
    PowerShell,
}

/// Generate the shell hook for the given shell.
#[must_use]
pub fn generate_shell_hook(shell: Shell) -> String {
    match shell {
        Shell::Zsh => generate_zsh_hook(),
        Shell::Bash => generate_bash_hook(),
        Shell::Fish => generate_fish_hook(),
        Shell::PowerShell => generate_powershell_hook(),
    }
}

fn generate_zsh_hook() -> String {
    r#"# Sanctum shell hook — add to ~/.zshrc:
#   eval "$(sanctum init --shell zsh)"

_sanctum_hook() {
    # Auto-start daemon if not running
    if ! sanctum daemon status >/dev/null 2>&1; then
        sanctum daemon start >/dev/null 2>&1 &!
    fi
    export SANCTUM_ACTIVE=1
}

# Run on first prompt
if [[ -z "$SANCTUM_ACTIVE" ]]; then
    _sanctum_hook
fi
"#
    .to_string()
}

fn generate_bash_hook() -> String {
    r#"# Sanctum shell hook — add to ~/.bashrc:
#   eval "$(sanctum init --shell bash)"

_sanctum_hook() {
    # Auto-start daemon if not running
    if ! sanctum daemon status >/dev/null 2>&1; then
        sanctum daemon start >/dev/null 2>&1 &
        disown
    fi
    export SANCTUM_ACTIVE=1
}

# Run on first prompt
if [[ -z "$SANCTUM_ACTIVE" ]]; then
    _sanctum_hook
fi
"#
    .to_string()
}

fn generate_fish_hook() -> String {
    r"# Sanctum shell hook — add to ~/.config/fish/config.fish:
#   sanctum init --shell fish | source

if not set -q SANCTUM_ACTIVE
    if not sanctum daemon status >/dev/null 2>&1
        sanctum daemon start >/dev/null 2>&1 &
        disown
    end
    set -gx SANCTUM_ACTIVE 1
end
"
    .to_string()
}

fn generate_powershell_hook() -> String {
    r"# Sanctum PowerShell hook — add to $PROFILE:
#   sanctum init --shell powershell | Invoke-Expression

if (-not $env:SANCTUM_ACTIVE) {
    $null = sanctum daemon status 2>$null
    if ($LASTEXITCODE -ne 0) {
        Start-Process -WindowStyle Hidden sanctum -ArgumentList @('daemon', 'start') | Out-Null
    }
    $env:SANCTUM_ACTIVE = '1'
}
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_hook_contains_daemon_auto_start() {
        let hook = generate_shell_hook(Shell::Zsh);
        assert!(hook.contains("sanctum daemon start"));
    }

    #[test]
    fn shell_hook_contains_prompt_integration() {
        let hook = generate_shell_hook(Shell::Zsh);
        assert!(hook.contains("SANCTUM_ACTIVE"));
    }

    #[test]
    fn bash_hook_contains_daemon_auto_start() {
        let hook = generate_shell_hook(Shell::Bash);
        assert!(hook.contains("sanctum daemon start"));
    }

    #[test]
    fn fish_hook_contains_daemon_auto_start() {
        let hook = generate_shell_hook(Shell::Fish);
        assert!(hook.contains("sanctum daemon start"));
    }

    #[test]
    fn powershell_hook_contains_daemon_auto_start() {
        let hook = generate_shell_hook(Shell::PowerShell);
        assert!(hook.contains("sanctum daemon status"));
        assert!(hook.contains("Start-Process"));
        assert!(hook.contains("SANCTUM_ACTIVE"));
    }
}

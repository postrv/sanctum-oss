#!/usr/bin/env zsh
# Sanctum shell hook for zsh
# Add to ~/.zshrc:
#   source "$(sanctum --shell-hook-path zsh)" 2>/dev/null || true
# Or:
#   eval "$(sanctum init zsh)"

_sanctum_hook() {
    # Auto-start daemon if not running
    if command -v sanctum >/dev/null 2>&1; then
        if ! sanctum daemon status >/dev/null 2>&1; then
            sanctum daemon start >/dev/null 2>&1 &!
        fi
    fi
    export SANCTUM_ACTIVE=1
}

# Run once on shell startup
if [[ -z "$SANCTUM_ACTIVE" ]]; then
    _sanctum_hook
fi

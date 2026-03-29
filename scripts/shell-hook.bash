#!/usr/bin/env bash
# Sanctum shell hook for bash
# Add to ~/.bashrc:
#   source "$(sanctum --shell-hook-path bash)" 2>/dev/null || true
# Or:
#   eval "$(sanctum init bash)"

_sanctum_hook() {
    if command -v sanctum >/dev/null 2>&1; then
        if ! sanctum daemon status >/dev/null 2>&1; then
            sanctum daemon start >/dev/null 2>&1 &
            disown
        fi
    fi
    export SANCTUM_ACTIVE=1
}

if [[ -z "$SANCTUM_ACTIVE" ]]; then
    _sanctum_hook
fi

# Sanctum shell hook for fish
# Add to ~/.config/fish/config.fish:
#   sanctum init fish | source

if not set -q SANCTUM_ACTIVE
    if command -q sanctum
        if not sanctum daemon status >/dev/null 2>&1
            sanctum daemon start >/dev/null 2>&1 &
            disown
        end
    end
    set -gx SANCTUM_ACTIVE 1
end

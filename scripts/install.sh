#!/bin/sh
# Sanctum installer
# Usage: curl -fsSL https://sanctum.dev/install | sh
#
# This script downloads the latest Sanctum binary for your platform,
# verifies its Sigstore signature, and installs it to /usr/local/bin.

set -e

REPO="postrv/sanctum"
INSTALL_DIR="${SANCTUM_INSTALL_DIR:-/usr/local/bin}"

main() {
    need_cmd curl

    local _arch
    _arch="$(uname -m)"
    local _os
    _os="$(uname -s)"

    case "$_os" in
        Linux)  _os="unknown-linux-gnu" ;;
        Darwin) _os="apple-darwin" ;;
        *)
            err "unsupported OS: $_os"
            ;;
    esac

    case "$_arch" in
        x86_64|amd64) _arch="x86_64" ;;
        aarch64|arm64) _arch="aarch64" ;;
        *)
            err "unsupported architecture: $_arch"
            ;;
    esac

    local _target="${_arch}-${_os}"
    local _latest
    _latest="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | cut -d'"' -f4)"

    if [ -z "$_latest" ]; then
        err "could not determine latest version"
    fi

    echo "Installing sanctum ${_latest} for ${_target}..."

    local _base_url="https://github.com/${REPO}/releases/download/${_latest}"
    local _url="${_base_url}/sanctum-${_target}"
    local _url_daemon="${_base_url}/sanctum-daemon-${_target}"
    local _tmpdir
    _tmpdir="$(mktemp -d)"

    curl -fsSL "${_url}" -o "${_tmpdir}/sanctum"
    curl -fsSL "${_url_daemon}" -o "${_tmpdir}/sanctum-daemon"
    chmod +x "${_tmpdir}/sanctum" "${_tmpdir}/sanctum-daemon"

    # Download signature and certificate for Sigstore verification
    local _sig_url="${_base_url}/sanctum-${_target}.sig"
    local _cert_url="${_base_url}/sanctum-${_target}.cert"

    curl -fsSL "$_sig_url" -o "${_tmpdir}/sanctum.sig" 2>/dev/null || true
    curl -fsSL "$_cert_url" -o "${_tmpdir}/sanctum.cert" 2>/dev/null || true

    # Verify Sigstore signature if cosign is available
    if command -v cosign > /dev/null 2>&1; then
        if [ -f "${_tmpdir}/sanctum.sig" ] && [ -f "${_tmpdir}/sanctum.cert" ]; then
            echo "Verifying Sigstore signature..."
            if cosign verify-blob \
                --signature "${_tmpdir}/sanctum.sig" \
                --certificate "${_tmpdir}/sanctum.cert" \
                --certificate-identity-regexp "^https://github\\.com/postrv/sanctum/" \
                --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
                "${_tmpdir}/sanctum"; then
                echo "Signature verified."
            else
                err "signature verification failed -- binary may be tampered with"
            fi
        else
            echo "warning: signature files not found in release, skipping verification" >&2
        fi
    else
        echo "warning: cosign not installed, skipping signature verification" >&2
        echo "  Install cosign: https://docs.sigstore.dev/cosign/system_config/installation/" >&2
    fi

    install -m 755 "${_tmpdir}/sanctum" "${INSTALL_DIR}/sanctum"
    install -m 755 "${_tmpdir}/sanctum-daemon" "${INSTALL_DIR}/sanctum-daemon"
    rm -rf "$_tmpdir"

    echo ""
    echo "Sanctum ${_latest} installed to ${INSTALL_DIR}/"
    echo ""
    echo "Next steps:"
    echo "  sanctum init      # initialise in current directory"
    echo "  sanctum status    # check daemon status"
    echo ""
}

need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1; then
        err "need '$1' (command not found)"
    fi
}

err() {
    echo "error: $1" >&2
    exit 1
}

main "$@"

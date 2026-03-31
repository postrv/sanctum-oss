#!/bin/sh
# Sanctum installer
# Usage: curl -fsSL https://raw.githubusercontent.com/postrv/sanctum-oss/main/scripts/install.sh | sh
#
# This script downloads the latest Sanctum binary for your platform,
# verifies its Sigstore signature, and installs it to /usr/local/bin.

# SECURITY MODEL
# ==============
# This installer uses a two-layer verification approach:
#
# Layer 1 (mandatory): SHA-256 checksum verification
#   - Downloads SHA256SUMS from the release artifacts
#   - Verifies each binary against its expected hash
#   - Protects against: download corruption, CDN tampering
#
# Layer 2 (optional): Sigstore signature verification
#   - Uses cosign to verify keyless OIDC signatures
#   - Certificate identity is bound to the GitHub Actions release workflow
#   - Signatures are logged to the Rekor transparency log
#   - Protects against: compromised release artifacts
#   - Requires: cosign (https://docs.sigstore.dev/cosign/system_config/installation/)
#
# If cosign is not installed, the installer warns and continues with
# checksum-only verification. This is sufficient for most threat models
# but does not protect against a fully compromised GitHub release.

set -e

REPO="postrv/sanctum-oss"
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
    _latest="$(curl --proto '=https' --tlsv1.2 -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | cut -d'"' -f4)"

    if [ -z "$_latest" ]; then
        err "could not determine latest version"
    fi

    echo "Installing sanctum ${_latest} for ${_target}..."

    local _base_url="https://github.com/${REPO}/releases/download/${_latest}"
    local _url="${_base_url}/sanctum-${_target}"
    local _url_daemon="${_base_url}/sanctum-daemon-${_target}"
    local _tmpdir
    _tmpdir="$(mktemp -d)"

    curl --proto '=https' --tlsv1.2 -fsSL "${_url}" -o "${_tmpdir}/sanctum"
    curl --proto '=https' --tlsv1.2 -fsSL "${_url_daemon}" -o "${_tmpdir}/sanctum-daemon"
    chmod +x "${_tmpdir}/sanctum" "${_tmpdir}/sanctum-daemon"

    # Download SHA256SUMS and verify checksums (mandatory)
    echo "Downloading checksums..."
    curl --proto '=https' --tlsv1.2 -fsSL "${_base_url}/SHA256SUMS" -o "${_tmpdir}/SHA256SUMS"

    # Detect available sha256 tool
    if command -v sha256sum > /dev/null 2>&1; then
        _sha256cmd="sha256sum"
    elif command -v shasum > /dev/null 2>&1; then
        _sha256cmd="shasum -a 256"
    else
        err "need 'sha256sum' or 'shasum' for checksum verification (command not found)"
    fi

    echo "Verifying checksums..."
    # Extract expected checksums for our target binaries and verify
    local _sanctum_hash _daemon_hash _actual_sanctum _actual_daemon
    _sanctum_hash="$(grep "sanctum-${_target}\$" "${_tmpdir}/SHA256SUMS" | head -1 | awk '{print $1}')"
    _daemon_hash="$(grep "sanctum-daemon-${_target}\$" "${_tmpdir}/SHA256SUMS" | head -1 | awk '{print $1}')"

    if [ -z "$_sanctum_hash" ] || [ -z "$_daemon_hash" ]; then
        err "could not find checksums for ${_target} in SHA256SUMS"
    fi

    _actual_sanctum="$($_sha256cmd "${_tmpdir}/sanctum" | awk '{print $1}')"
    _actual_daemon="$($_sha256cmd "${_tmpdir}/sanctum-daemon" | awk '{print $1}')"

    if [ "$_sanctum_hash" != "$_actual_sanctum" ]; then
        err "checksum mismatch for sanctum: expected ${_sanctum_hash}, got ${_actual_sanctum}"
    fi
    if [ "$_daemon_hash" != "$_actual_daemon" ]; then
        err "checksum mismatch for sanctum-daemon: expected ${_daemon_hash}, got ${_actual_daemon}"
    fi
    echo "Checksums verified."

    # Download signature and certificate for Sigstore verification (both binaries)
    local _sig_url="${_base_url}/sanctum-${_target}.sig"
    local _cert_url="${_base_url}/sanctum-${_target}.cert"
    local _sig_daemon_url="${_base_url}/sanctum-daemon-${_target}.sig"
    local _cert_daemon_url="${_base_url}/sanctum-daemon-${_target}.cert"

    curl --proto '=https' --tlsv1.2 -fsSL "$_sig_url" -o "${_tmpdir}/sanctum.sig" 2>/dev/null || true
    curl --proto '=https' --tlsv1.2 -fsSL "$_cert_url" -o "${_tmpdir}/sanctum.cert" 2>/dev/null || true
    curl --proto '=https' --tlsv1.2 -fsSL "$_sig_daemon_url" -o "${_tmpdir}/sanctum-daemon.sig" 2>/dev/null || true
    curl --proto '=https' --tlsv1.2 -fsSL "$_cert_daemon_url" -o "${_tmpdir}/sanctum-daemon.cert" 2>/dev/null || true

    # Verify Sigstore signatures if cosign is available (optional)
    if command -v cosign > /dev/null 2>&1; then
        # Verify sanctum binary
        if [ -f "${_tmpdir}/sanctum.sig" ] && [ -f "${_tmpdir}/sanctum.cert" ]; then
            echo "Verifying Sigstore signature for sanctum..."
            if cosign verify-blob \
                --signature "${_tmpdir}/sanctum.sig" \
                --certificate "${_tmpdir}/sanctum.cert" \
                --certificate-identity-regexp "^https://github\\.com/postrv/sanctum-oss/" \
                --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
                "${_tmpdir}/sanctum"; then
                echo "Signature verified for sanctum."
            else
                err "signature verification failed for sanctum -- binary may be tampered with"
            fi
        else
            echo "warning: signature files not found for sanctum, skipping cosign verification" >&2
        fi
        # Verify sanctum-daemon binary
        if [ -f "${_tmpdir}/sanctum-daemon.sig" ] && [ -f "${_tmpdir}/sanctum-daemon.cert" ]; then
            echo "Verifying Sigstore signature for sanctum-daemon..."
            if cosign verify-blob \
                --signature "${_tmpdir}/sanctum-daemon.sig" \
                --certificate "${_tmpdir}/sanctum-daemon.cert" \
                --certificate-identity-regexp "^https://github\\.com/postrv/sanctum-oss/" \
                --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
                "${_tmpdir}/sanctum-daemon"; then
                echo "Signature verified for sanctum-daemon."
            else
                err "signature verification failed for sanctum-daemon -- binary may be tampered with"
            fi
        else
            echo "warning: signature files not found for sanctum-daemon, skipping cosign verification" >&2
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

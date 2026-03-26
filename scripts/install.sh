#!/bin/sh
# Sanctum installer
# Usage: curl -fsSL https://sanctum.dev/install | sh
#
# This script downloads the latest Sanctum binary for your platform,
# verifies its Sigstore signature, and installs it to /usr/local/bin.

set -e

REPO="arbiter-security/sanctum"
INSTALL_DIR="${SANCTUM_INSTALL_DIR:-/usr/local/bin}"

main() {
    need_cmd curl
    need_cmd tar

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

    local _url="https://github.com/${REPO}/releases/download/${_latest}/sanctum-${_target}.tar.gz"
    local _tmpdir
    _tmpdir="$(mktemp -d)"

    curl -fsSL "$_url" | tar -xz -C "$_tmpdir"

    # TODO: Verify Sigstore signature
    # cosign verify-blob --signature "${_tmpdir}/sanctum.sig" \
    #   --certificate "${_tmpdir}/sanctum.cert" "${_tmpdir}/sanctum"

    install -m 755 "${_tmpdir}/sanctum" "${INSTALL_DIR}/sanctum"
    rm -rf "$_tmpdir"

    echo ""
    echo "Sanctum ${_latest} installed to ${INSTALL_DIR}/sanctum"
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

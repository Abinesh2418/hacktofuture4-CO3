#!/usr/bin/env bash
#
# Install the Red Arsenal MCP server + all tool binaries on a fresh Kali VM.
#
# Downloads *prebuilt* binaries from GitHub releases — no `go install` or
# `cargo install`, so this runs in <1 minute and needs essentially no RAM.
#
# Flags:
#   --skip-binaries   skip the github-release downloads (iterate on server only)
#   --skip-apt        skip apt update/install
#
# Safe to re-run.

set -euo pipefail

SKIP_BINARIES=0
SKIP_APT=0
for arg in "$@"; do
    case "$arg" in
        --skip-binaries) SKIP_BINARIES=1 ;;
        --skip-apt)      SKIP_APT=1 ;;
        -h|--help)
            sed -n '2,13p' "$0"; exit 0 ;;
        *) echo "unknown flag: $arg" >&2; exit 2 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC_DIR="$REPO_ROOT/red_agent/red_arsenal"
INSTALL_DIR="/opt/red-arsenal"
BIN_DIR="/usr/local/bin"
ARCH="linux_amd64"

# ---------------------------------------------------------------- helpers

fetch_github_release() {
    # fetch_github_release OWNER REPO ASSET_PATTERN BIN_NAME [force]
    #
    # Finds the latest release, grabs the asset whose filename matches
    # ASSET_PATTERN (regex, egrep-style), extracts BIN_NAME, and installs
    # it to /usr/local/bin. Handles .zip and .tar.gz archives.
    #
    # If `force` is "force", re-installs even if the binary is already on
    # PATH (needed when a distro ships a wrong-upstream binary with the
    # same name, e.g. Kali's python3-httpx vs ProjectDiscovery httpx).
    local owner=$1 repo=$2 pattern=$3 binname=$4 force=${5:-}

    if [[ "$force" != "force" ]] && command -v "$binname" >/dev/null 2>&1; then
        echo "    [skip] $binname already installed at $(command -v "$binname")"
        return 0
    fi

    echo "    [+] $owner/$repo ($pattern)"
    local api="https://api.github.com/repos/$owner/$repo/releases/latest"
    local url
    url=$(curl -fsSL "$api" \
        | grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+"' \
        | cut -d'"' -f4 \
        | grep -iE "$pattern" \
        | head -1 || true)
    if [[ -z "$url" ]]; then
        echo "    [!] no asset matching '$pattern' for $owner/$repo — skipping" >&2
        return 0
    fi

    local tmp
    tmp=$(mktemp -d)
    local pkg="$tmp/pkg"
    curl -fsSL -o "$pkg" "$url"

    case "$url" in
        *.zip)
            unzip -q -o "$pkg" -d "$tmp"
            ;;
        *.tar.gz|*.tgz)
            tar -xzf "$pkg" -C "$tmp"
            ;;
        *)
            # Single binary, no archive
            cp "$pkg" "$tmp/$binname"
            ;;
    esac

    local found
    found=$(find "$tmp" -type f -name "$binname" ! -name "*.zip" ! -name "*.tar.gz" | head -1 || true)
    if [[ -z "$found" ]]; then
        # Fallback: some archives put the binary under a weird subdir name
        found=$(find "$tmp" -type f -executable ! -name "pkg" | head -1 || true)
    fi
    if [[ -z "$found" ]]; then
        echo "    [!] could not find binary '$binname' in $url" >&2
        rm -rf "$tmp"
        return 0
    fi

    sudo install -m 0755 "$found" "$BIN_DIR/$binname"
    rm -rf "$tmp"
    echo "    [+] installed $BIN_DIR/$binname"
}

# ---------------------------------------------------------------- apt

if [[ $SKIP_APT -eq 0 ]]; then
    echo "[*] apt packages"
    sudo apt update
    sudo apt install -y \
        python3 python3-venv python3-pip pipx \
        curl unzip tar git \
        nmap masscan arp-scan \
        gobuster ffuf nikto \
        enum4linux-ng nbtscan smbmap \
        samba-common-bin \
        wordlists
else
    echo "[*] apt: skipped"
fi

# ---------------------------------------------------------------- prebuilt binaries

if [[ $SKIP_BINARIES -eq 0 ]]; then
    echo "[*] Prebuilt binaries from GitHub releases"

    # ProjectDiscovery. httpx is FORCE-installed because Kali's base
    # `httpx` package is python3-httpx (different tool, different flags).
    # We install ProjectDiscovery httpx to /usr/local/bin which takes
    # PATH precedence over /usr/bin in our systemd unit.
    fetch_github_release projectdiscovery httpx   "${ARCH}\\.zip$"   httpx  force
    fetch_github_release projectdiscovery katana  "${ARCH}\\.zip$"   katana
    fetch_github_release projectdiscovery nuclei  "${ARCH}\\.zip$"   nuclei

    # tomnomnom / lc
    fetch_github_release lc              gau          "${ARCH}\\.tar\\.gz$" gau
    fetch_github_release tomnomnom       waybackurls  "linux-amd64.*\\.tgz$" waybackurls

    # rustscan: optional — Kali does NOT package it and upstream asset
    # naming varies. Try the GitHub .deb; silently skip on failure since
    # nmap+masscan already cover port scanning.
    if ! command -v rustscan >/dev/null 2>&1; then
        echo "    [+] RustScan (optional, via .deb)"
        rustscan_url=$(curl -fsSL https://api.github.com/repos/RustScan/RustScan/releases/latest 2>/dev/null \
            | grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+"' \
            | cut -d'"' -f4 \
            | grep -iE 'amd64\.deb$' \
            | head -1 || true)
        if [[ -n "$rustscan_url" ]]; then
            tmp=$(mktemp -d)
            if curl -fsSL -o "$tmp/pkg.deb" "$rustscan_url" \
               && sudo dpkg -i "$tmp/pkg.deb" >/dev/null 2>&1; then
                echo "    [+] installed rustscan from $rustscan_url"
            else
                echo "    [!] rustscan .deb install failed — skipping (optional)"
            fi
            rm -rf "$tmp"
        else
            echo "    [!] rustscan: no .deb asset found — skipping (optional)"
        fi
    else
        echo "    [skip] rustscan already installed at $(command -v rustscan)"
    fi

    # x8: Sh1Yo publishes `x8-<target>.tar.gz` where target is e.g.
    # `x86_64-unknown-linux-gnu`. Match on `linux-gnu.*\.tar\.gz$`.
    fetch_github_release Sh1Yo x8 "linux-gnu\\.tar\\.gz$|linux-musl\\.tar\\.gz$" x8

    # Update nuclei templates (small, fast)
    if command -v nuclei >/dev/null 2>&1; then
        HOME="${HOME:-/root}" nuclei -update-templates -silent || true
    fi
else
    echo "[*] Prebuilt binaries: skipped"
fi

# ---------------------------------------------------------------- python tools via pipx

echo "[*] Python tooling via pipx (installed --global so systemd finds them)"
# --global puts shims in /usr/local/bin instead of per-user ~/.local/bin,
# which is critical because the systemd unit runs as root with a PATH
# that doesn't include /home/<user>/.local/bin.
PIPX_ENV=(PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin)

# arjun and dirsearch are on PyPI, plain pipx install works.
sudo "${PIPX_ENV[@]}" pipx install arjun     2>/dev/null \
    || sudo "${PIPX_ENV[@]}" pipx upgrade arjun     || true
sudo "${PIPX_ENV[@]}" pipx install dirsearch 2>/dev/null \
    || sudo "${PIPX_ENV[@]}" pipx upgrade dirsearch || true

# dirsearch imports pkg_resources which comes from setuptools. Python
# 3.12+ stopped bundling setuptools in new venvs, so dirsearch crashes
# at import time unless we drop setuptools into its venv. Use pipx
# inject *and* a direct pip fallback — one of them will work.
sudo "${PIPX_ENV[@]}" pipx inject dirsearch setuptools || \
    sudo /opt/pipx/venvs/dirsearch/bin/pip install setuptools || true

# paramspider is git-only (not on PyPI) — use the repo URL.
sudo "${PIPX_ENV[@]}" pipx install git+https://github.com/devanshbatham/paramspider.git 2>/dev/null \
    || sudo "${PIPX_ENV[@]}" pipx upgrade paramspider || true

# ---------------------------------------------------------------- deploy server

echo "[*] Deploy Red Arsenal to ${INSTALL_DIR}"
# Deployed as top-level `red_arsenal` so `python -m red_arsenal.server`
# resolves on Kali, independent of the repo's red_agent/ nesting.
sudo mkdir -p "$INSTALL_DIR"
sudo rsync -a --delete "$SRC_DIR/" "$INSTALL_DIR/red_arsenal/"
sudo cp "$SRC_DIR/requirements.txt" "$INSTALL_DIR/requirements.txt"

if [[ ! -x "$INSTALL_DIR/.venv/bin/python" ]]; then
    sudo python3 -m venv "$INSTALL_DIR/.venv"
fi
sudo "$INSTALL_DIR/.venv/bin/pip" install --upgrade pip >/dev/null
sudo "$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

echo "[*] systemd unit"
sudo cp "$SRC_DIR/systemd/red-arsenal.service" /etc/systemd/system/red-arsenal.service
sudo mkdir -p /var/log/red-arsenal
sudo systemctl daemon-reload
sudo systemctl enable red-arsenal
sudo systemctl restart red-arsenal

echo "[+] Done. Tail the log with:  sudo journalctl -u red-arsenal -f"

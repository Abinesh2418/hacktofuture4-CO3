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
    # fetch_github_release OWNER REPO ASSET_PATTERN BIN_NAME
    #
    # Finds the latest release, grabs the asset whose filename contains
    # ASSET_PATTERN, extracts the binary BIN_NAME, and installs it to
    # /usr/local/bin. Handles .zip and .tar.gz archives.
    local owner=$1 repo=$2 pattern=$3 binname=$4

    if command -v "$binname" >/dev/null 2>&1; then
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
        curl unzip tar \
        nmap masscan arp-scan \
        gobuster ffuf nikto \
        enum4linux-ng nbtscan smbmap \
        samba-common-bin
else
    echo "[*] apt: skipped"
fi

# ---------------------------------------------------------------- prebuilt binaries

if [[ $SKIP_BINARIES -eq 0 ]]; then
    echo "[*] Prebuilt binaries from GitHub releases"

    # ProjectDiscovery — all publish ${tool}_${version}_${ARCH}.zip
    fetch_github_release projectdiscovery httpx   "${ARCH}\\.zip$"   httpx
    fetch_github_release projectdiscovery katana  "${ARCH}\\.zip$"   katana
    fetch_github_release projectdiscovery nuclei  "${ARCH}\\.zip$"   nuclei

    # tomnomnom / lc
    fetch_github_release lc              gau          "${ARCH}\\.tar\\.gz$" gau
    fetch_github_release tomnomnom       waybackurls  "linux-amd64.*\\.tgz$" waybackurls

    # Rust tools that publish prebuilt releases
    fetch_github_release RustScan        RustScan     "amd64\\.deb$"        rustscan_pkg || true
    if [[ -f "$BIN_DIR/rustscan_pkg" ]]; then
        sudo dpkg -i "$BIN_DIR/rustscan_pkg" || true
        sudo rm -f "$BIN_DIR/rustscan_pkg"
    fi
    fetch_github_release Sh1Yo           x8           "x86_64.*linux.*\\.tar\\.gz$|linux.*\\.zip$" x8

    # Update nuclei templates (small, fast)
    if command -v nuclei >/dev/null 2>&1; then
        nuclei -update-templates -silent || true
    fi
else
    echo "[*] Prebuilt binaries: skipped"
fi

# ---------------------------------------------------------------- python tools via pipx

echo "[*] Python tooling via pipx"
pipx install arjun       2>/dev/null || pipx upgrade arjun       || true
pipx install paramspider 2>/dev/null || pipx upgrade paramspider || true
pipx install dirsearch   2>/dev/null || pipx upgrade dirsearch   || true
pipx ensurepath >/dev/null 2>&1 || true

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

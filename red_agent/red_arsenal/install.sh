#!/usr/bin/env bash
#
# Install the Red Arsenal MCP server + all tool binaries on a fresh Kali VM.
# Run as a normal user with sudo rights. Idempotent — safe to re-run.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC_DIR="$REPO_ROOT/red_agent/red_arsenal"
INSTALL_DIR="/opt/red-arsenal"

echo "[*] apt packages"
sudo apt update
sudo apt install -y \
    python3 python3-venv python3-pip pipx \
    golang-go cargo \
    nmap masscan arp-scan \
    gobuster ffuf nikto \
    enum4linux-ng nbtscan smbmap \
    samba-common-bin

echo "[*] ProjectDiscovery Go tools"
export PATH="$PATH:$HOME/go/bin"
for tool in \
    github.com/projectdiscovery/httpx/cmd/httpx@latest \
    github.com/projectdiscovery/katana/cmd/katana@latest \
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    github.com/lc/gau/v2/cmd/gau@latest \
    github.com/tomnomnom/waybackurls@latest ; do
    go install "$tool"
done
nuclei -update-templates || true

echo "[*] Python tooling via pipx"
pipx install arjun || pipx upgrade arjun
pipx install paramspider || pipx upgrade paramspider
pipx install dirsearch || pipx upgrade dirsearch

echo "[*] Rust tooling via cargo"
cargo install rustscan || true
cargo install x8 || true

echo "[*] Deploy Red Arsenal to ${INSTALL_DIR}"
# The package is deployed as a top-level `red_arsenal` so the server module
# resolves as `python -m red_arsenal.server` on Kali, independent of the
# repo's red_agent/ nesting.
sudo mkdir -p "$INSTALL_DIR"
sudo rsync -a --delete "$SRC_DIR/" "$INSTALL_DIR/red_arsenal/"
sudo cp "$SRC_DIR/requirements.txt" "$INSTALL_DIR/requirements.txt"

sudo python3 -m venv "$INSTALL_DIR/.venv"
sudo "$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
sudo "$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

echo "[*] systemd unit"
sudo cp "$SRC_DIR/systemd/red-arsenal.service" /etc/systemd/system/red-arsenal.service
sudo mkdir -p /var/log/red-arsenal
sudo systemctl daemon-reload
sudo systemctl enable red-arsenal
sudo systemctl restart red-arsenal

echo "[+] Done. Tail the log with:  sudo journalctl -u red-arsenal -f"

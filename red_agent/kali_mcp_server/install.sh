#!/usr/bin/env bash
#
# Install the Kali MCP server + all tool binaries on a fresh Kali VM.
# Run as a normal user with sudo rights. Idempotent — safe to re-run.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC_DIR="$REPO_ROOT/red_agent/kali_mcp_server"
INSTALL_DIR="/opt/kali-mcp"

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

echo "[*] Deploy MCP server to ${INSTALL_DIR}"
# The package is deployed as a top-level `kali_mcp_server` so the server
# module resolves as `python -m kali_mcp_server.server` on Kali, independent
# of the repo's red_agent/ nesting.
sudo mkdir -p "$INSTALL_DIR"
sudo rsync -a --delete "$SRC_DIR/" "$INSTALL_DIR/kali_mcp_server/"
sudo cp "$SRC_DIR/requirements.txt" "$INSTALL_DIR/requirements.txt"

sudo python3 -m venv "$INSTALL_DIR/.venv"
sudo "$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
sudo "$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

echo "[*] systemd unit"
sudo cp "$SRC_DIR/systemd/kali-mcp.service" /etc/systemd/system/kali-mcp.service
sudo mkdir -p /var/log/kali-mcp
sudo systemctl daemon-reload
sudo systemctl enable kali-mcp
sudo systemctl restart kali-mcp

echo "[+] Done. Tail the log with:  sudo journalctl -u kali-mcp -f"

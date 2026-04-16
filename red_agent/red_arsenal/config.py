"""Static configuration: binary paths, default flags, workflow registry."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field

HOST = os.environ.get("RED_ARSENAL_HOST", "0.0.0.0")
PORT = int(os.environ.get("RED_ARSENAL_PORT", "8765"))
LOG_DIR = os.environ.get("RED_ARSENAL_LOG_DIR", "/var/log/red-arsenal")

DEFAULT_TIMEOUT = 600
LONG_TIMEOUT = 1800
JOB_RETENTION_S = 3600


@dataclass
class ToolSpec:
    name: str
    binary: str
    default_timeout: int = DEFAULT_TIMEOUT
    extra_paths: list[str] = field(default_factory=list)

    def resolve(self) -> str | None:
        # Explicit candidates are checked FIRST so a tool with a distro
        # namespace collision (e.g. ProjectDiscovery httpx vs the Python
        # httpx CLI that ships in our venv) can be pinned to the right
        # binary. Falls back to shutil.which when no explicit match.
        for candidate in self.extra_paths:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return shutil.which(self.binary)

    @property
    def installed(self) -> bool:
        return self.resolve() is not None


GO_BIN = os.path.expanduser("~/go/bin")
CARGO_BIN = os.path.expanduser("~/.cargo/bin")

TOOLS: dict[str, ToolSpec] = {
    "nmap":         ToolSpec("nmap", "nmap", LONG_TIMEOUT),
    # httpx: pin explicit paths so we skip the Python httpx CLI that pip
    # installs into our venv as a transitive dep of fastmcp/mcp.
    "httpx":        ToolSpec("httpx", "httpx", DEFAULT_TIMEOUT,
                             ["/usr/local/bin/httpx", f"{GO_BIN}/httpx"]),
    "katana":       ToolSpec("katana", "katana", LONG_TIMEOUT,
                             ["/usr/local/bin/katana", f"{GO_BIN}/katana"]),
    "gau":          ToolSpec("gau", "gau", DEFAULT_TIMEOUT,
                             ["/usr/local/bin/gau", f"{GO_BIN}/gau"]),
    "waybackurls":  ToolSpec("waybackurls", "waybackurls", DEFAULT_TIMEOUT,
                             ["/usr/local/bin/waybackurls", f"{GO_BIN}/waybackurls"]),
    "nuclei":       ToolSpec("nuclei", "nuclei", LONG_TIMEOUT,
                             ["/usr/local/bin/nuclei", f"{GO_BIN}/nuclei"]),
    "dirsearch":    ToolSpec("dirsearch", "dirsearch", LONG_TIMEOUT),
    "gobuster":     ToolSpec("gobuster", "gobuster", LONG_TIMEOUT),
    "arjun":        ToolSpec("arjun", "arjun", DEFAULT_TIMEOUT),
    "x8":           ToolSpec("x8", "x8", DEFAULT_TIMEOUT,
                             ["/usr/local/bin/x8", f"{CARGO_BIN}/x8"]),
    "paramspider":  ToolSpec("paramspider", "paramspider", DEFAULT_TIMEOUT),
    "ffuf":         ToolSpec("ffuf", "ffuf", LONG_TIMEOUT),
    "arp-scan":     ToolSpec("arp-scan", "arp-scan", DEFAULT_TIMEOUT),
    "rustscan":     ToolSpec("rustscan", "rustscan", LONG_TIMEOUT,
                             ["/usr/local/bin/rustscan", f"{CARGO_BIN}/rustscan"]),
    "masscan":      ToolSpec("masscan", "masscan", LONG_TIMEOUT),
    "enum4linux-ng": ToolSpec("enum4linux-ng", "enum4linux-ng", LONG_TIMEOUT),
    "nbtscan":      ToolSpec("nbtscan", "nbtscan", DEFAULT_TIMEOUT),
    "smbmap":       ToolSpec("smbmap", "smbmap", DEFAULT_TIMEOUT),
    "rpcclient":    ToolSpec("rpcclient", "rpcclient", DEFAULT_TIMEOUT),
    "sqlmap":       ToolSpec("sqlmap", "sqlmap", LONG_TIMEOUT),
}

DEFAULT_WORDLISTS = {
    # dirb/common.txt is ~4.6K entries — sane default for both dirsearch
    # and gobuster. directory-list-2.3-medium.txt (220K entries) is
    # unusable for interactive / smoke-test scans.
    "dirsearch": "/usr/share/wordlists/dirb/common.txt",
    "gobuster":  "/usr/share/wordlists/dirb/common.txt",
    "ffuf":      "/usr/share/wordlists/dirb/common.txt",
    "x8":        "/usr/share/wordlists/x8/params.txt",
}

WORKFLOWS = {
    "web_reconnaissance": [
        "nmap", "httpx", "katana", "gau", "waybackurls",
        "nuclei", "dirsearch", "gobuster",
    ],
    "api_testing": [
        "httpx", "arjun", "x8", "paramspider", "nuclei", "ffuf",
    ],
    "network_discovery": [
        "arp-scan", "rustscan", "nmap", "masscan",
        "enum4linux-ng", "nbtscan", "smbmap", "rpcclient",
    ],
}

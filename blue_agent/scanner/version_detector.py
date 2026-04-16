from __future__ import annotations

"""Version detection for discovered services.

Simulates multiple detection techniques:
  - HTTP response header parsing (Server, X-Powered-By)
  - Banner grabbing (SSH, FTP, SMTP, Telnet)
  - Default page fingerprinting
  - Package manager / config file inspection

All detection is in-memory simulation — no real network calls.
"""

import logging
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Simulated version fingerprints per service type
# ---------------------------------------------------------------------------

_VERSION_DB: Dict[str, List[Dict[str, str]]] = {
    # Web servers
    "apache": [
        {"version": "2.4.49", "banner": "Apache/2.4.49 (Ubuntu)"},
        {"version": "2.4.51", "banner": "Apache/2.4.51 (Debian)"},
        {"version": "2.4.54", "banner": "Apache/2.4.54 (Unix)"},
        {"version": "2.4.41", "banner": "Apache/2.4.41 (Ubuntu)"},
    ],
    "nginx": [
        {"version": "1.18.0", "banner": "nginx/1.18.0 (Ubuntu)"},
        {"version": "1.20.0", "banner": "nginx/1.20.0"},
        {"version": "1.21.6", "banner": "nginx/1.21.6"},
        {"version": "1.24.0", "banner": "nginx/1.24.0"},
    ],
    "iis": [
        {"version": "10.0", "banner": "Microsoft-IIS/10.0"},
        {"version": "8.5", "banner": "Microsoft-IIS/8.5"},
    ],
    # Databases
    "mysql": [
        {"version": "5.7.30", "banner": "5.7.30-0ubuntu0.18.04.1"},
        {"version": "8.0.25", "banner": "8.0.25-0ubuntu0.20.04.1"},
        {"version": "8.0.32", "banner": "8.0.32"},
    ],
    "postgresql": [
        {"version": "13.2", "banner": "PostgreSQL 13.2 on x86_64-pc-linux-gnu"},
        {"version": "14.5", "banner": "PostgreSQL 14.5 (Ubuntu 14.5-1)"},
        {"version": "15.1", "banner": "PostgreSQL 15.1"},
    ],
    "mongodb": [
        {"version": "4.4.6", "banner": "MongoDB 4.4.6"},
        {"version": "5.0.9", "banner": "MongoDB 5.0.9"},
        {"version": "6.0.3", "banner": "MongoDB 6.0.3"},
    ],
    "redis": [
        {"version": "6.0.9", "banner": "Redis server v=6.0.9 sha=00000000:0"},
        {"version": "6.2.7", "banner": "Redis server v=6.2.7"},
        {"version": "7.0.5", "banner": "Redis server v=7.0.5"},
    ],
    # System services
    "openssh": [
        {"version": "8.2", "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"},
        {"version": "8.9", "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
        {"version": "9.0", "banner": "SSH-2.0-OpenSSH_9.0"},
    ],
    "vsftpd": [
        {"version": "3.0.3", "banner": "220 (vsFTPd 3.0.3)"},
        {"version": "3.0.5", "banner": "220 (vsFTPd 3.0.5)"},
    ],
    "proftpd": [
        {"version": "1.3.6", "banner": "220 ProFTPD 1.3.6 Server"},
        {"version": "1.3.7", "banner": "220 ProFTPD 1.3.7a Server"},
    ],
    # Application frameworks / runtimes
    "php": [
        {"version": "7.4.16", "banner": "X-Powered-By: PHP/7.4.16"},
        {"version": "8.0.12", "banner": "X-Powered-By: PHP/8.0.12"},
        {"version": "8.1.10", "banner": "X-Powered-By: PHP/8.1.10"},
    ],
    "nodejs": [
        {"version": "14.17.0", "banner": "X-Powered-By: Express"},
        {"version": "16.13.0", "banner": "X-Powered-By: Express"},
        {"version": "18.12.0", "banner": "X-Powered-By: Express"},
    ],
    "django": [
        {"version": "3.2.9", "banner": ""},
        {"version": "4.1.0", "banner": ""},
    ],
    "tomcat": [
        {"version": "9.0.50", "banner": "Apache-Coyote/1.1"},
        {"version": "10.0.12", "banner": "Apache-Coyote/1.1"},
    ],
    # CMS / Applications
    "wordpress": [
        {"version": "5.7.0", "banner": ""},
        {"version": "5.9.3", "banner": ""},
        {"version": "6.1.1", "banner": ""},
    ],
    "phpmyadmin": [
        {"version": "5.1.0", "banner": "phpMyAdmin 5.1.0"},
        {"version": "5.2.0", "banner": "phpMyAdmin 5.2.0"},
    ],
    # Cloud / Container
    "docker": [
        {"version": "20.10.12", "banner": "Docker Engine 20.10.12"},
        {"version": "23.0.1", "banner": "Docker Engine 23.0.1"},
    ],
    "kubernetes": [
        {"version": "1.24.0", "banner": "Kubernetes v1.24.0"},
        {"version": "1.26.0", "banner": "Kubernetes v1.26.0"},
    ],
    "elasticsearch": [
        {"version": "7.17.0", "banner": "Elasticsearch 7.17.0"},
        {"version": "8.5.0", "banner": "Elasticsearch 8.5.0"},
    ],
    # Flask / Werkzeug (target: 172.25.8.172:5000)
    "flask": [
        {"version": "3.1.8", "banner": "Werkzeug/3.1.8 Python/3.11"},
        {"version": "2.3.0", "banner": "Werkzeug/2.3.0 Python/3.10"},
        {"version": "3.0.0", "banner": "Werkzeug/3.0.0 Python/3.12"},
    ],
    "werkzeug": [
        {"version": "3.1.8", "banner": "Werkzeug/3.1.8"},
        {"version": "2.2.2", "banner": "Werkzeug/2.2.2"},
        {"version": "3.0.3", "banner": "Werkzeug/3.0.3"},
    ],
}


@dataclass
class VersionInfo:
    """Result of a version detection scan."""
    software: str
    version: str
    banner: str
    detection_method: str
    confidence: float  # 0.0 - 1.0


class VersionDetector:
    """Detects software versions via simulated fingerprinting techniques."""

    def __init__(self) -> None:
        self.detection_count: int = 0
        self._cache: Dict[str, VersionInfo] = {}

    def detect(self, software: str, host: str, port: int) -> Optional[VersionInfo]:
        """Detect the version of a given software on host:port.

        Uses cached result if available, otherwise simulates detection.
        """
        cache_key = f"{host}:{port}:{software}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        sw = software.lower().strip()
        entries = _VERSION_DB.get(sw)
        if not entries:
            return None

        # Simulate picking a version — weighted toward older (more vulnerable) ones
        weights = list(range(len(entries), 0, -1))
        entry = random.choices(entries, weights=weights, k=1)[0]

        method = self._pick_method(sw)
        info = VersionInfo(
            software=sw,
            version=entry["version"],
            banner=entry["banner"],
            detection_method=method,
            confidence=round(random.uniform(0.85, 0.99), 2),
        )

        self._cache[cache_key] = info
        self.detection_count += 1
        return info

    def clear_cache(self) -> None:
        self._cache.clear()

    @staticmethod
    def _pick_method(software: str) -> str:
        """Select the most realistic detection method for the software type."""
        method_map = {
            "apache": "http_header",
            "nginx": "http_header",
            "iis": "http_header",
            "mysql": "banner_grab",
            "postgresql": "banner_grab",
            "mongodb": "banner_grab",
            "redis": "banner_grab",
            "openssh": "banner_grab",
            "vsftpd": "banner_grab",
            "proftpd": "banner_grab",
            "php": "http_header",
            "nodejs": "http_header",
            "wordpress": "page_fingerprint",
            "phpmyadmin": "page_fingerprint",
            "tomcat": "http_header",
            "django": "error_page_fingerprint",
            "flask": "http_header",
            "werkzeug": "http_header",
            "docker": "api_query",
            "kubernetes": "api_query",
            "elasticsearch": "api_query",
        }
        return method_map.get(software, "banner_grab")

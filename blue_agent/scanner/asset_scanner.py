from __future__ import annotations

"""Full-stack asset scanner — discovers services, detects versions, looks up CVEs.

Continuously scans across Cloud, On-Premise, and Hybrid environments to build
a live asset inventory. For each discovered asset:
  1. Detect the running software and version (version_detector)
  2. Look up known CVEs for that software+version (cve_lookup)
  3. Emit events so the response/patch chain can remediate

Covers: web servers, databases, application frameworks, CMS platforms,
system services (SSH/FTP), container runtimes, cloud services.

All scanning is simulated in-memory — no real network calls.
Continuous operation: the scan loop never stops; interval tightens under threat.
"""

import asyncio
import json
import logging
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from core.event_bus import event_bus
from blue_agent.scanner.version_detector import VersionDetector, VersionInfo
from blue_agent.scanner.cve_lookup import CVELookup, CVERecord

logger = logging.getLogger(__name__)


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


# ---------------------------------------------------------------------------
# Simulated target environment
# ---------------------------------------------------------------------------

@dataclass
class Asset:
    """A single discovered asset."""
    asset_id: str
    host: str
    port: int
    service: str
    environment: str         # "cloud" | "onprem" | "hybrid"
    layer: str               # "webserver" | "database" | "application" | "frontend" | "system" | "container"
    version_info: Optional[VersionInfo] = None
    cves: List[CVERecord] = field(default_factory=list)
    last_scanned: Optional[float] = None
    status: str = "discovered"  # discovered | scanned | vulnerable | patched

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "environment": self.environment,
            "layer": self.layer,
            "version": self.version_info.version if self.version_info else None,
            "banner": self.version_info.banner if self.version_info else None,
            "detection_method": self.version_info.detection_method if self.version_info else None,
            "cve_count": len(self.cves),
            "cves": [c.to_dict() for c in self.cves],
            "last_scanned": self.last_scanned,
            "status": self.status,
        }


# The simulated target infrastructure spanning all 3 environments
_TARGET_ASSETS: List[Dict[str, Any]] = [
    # ── Cloud Environment ──────────────────────────────────────────
    {"host": "10.0.1.10", "port": 443,  "service": "nginx",       "env": "cloud",  "layer": "webserver"},
    {"host": "10.0.1.10", "port": 80,   "service": "nginx",       "env": "cloud",  "layer": "webserver"},
    {"host": "10.0.1.11", "port": 8080, "service": "tomcat",      "env": "cloud",  "layer": "application"},
    {"host": "10.0.1.12", "port": 3306, "service": "mysql",       "env": "cloud",  "layer": "database"},
    {"host": "10.0.1.13", "port": 6379, "service": "redis",       "env": "cloud",  "layer": "database"},
    {"host": "10.0.1.14", "port": 9200, "service": "elasticsearch", "env": "cloud", "layer": "database"},
    {"host": "10.0.1.15", "port": 3000, "service": "nodejs",      "env": "cloud",  "layer": "frontend"},
    {"host": "10.0.1.16", "port": 443,  "service": "kubernetes",  "env": "cloud",  "layer": "container"},
    {"host": "10.0.1.17", "port": 2376, "service": "docker",      "env": "cloud",  "layer": "container"},
    {"host": "10.0.1.18", "port": 27017,"service": "mongodb",     "env": "cloud",  "layer": "database"},

    # ── On-Premise Environment ─────────────────────────────────────
    {"host": "192.168.1.10", "port": 80,   "service": "apache",     "env": "onprem", "layer": "webserver"},
    {"host": "192.168.1.10", "port": 443,  "service": "apache",     "env": "onprem", "layer": "webserver"},
    {"host": "192.168.1.11", "port": 22,   "service": "openssh",    "env": "onprem", "layer": "system"},
    {"host": "192.168.1.12", "port": 21,   "service": "vsftpd",     "env": "onprem", "layer": "system"},
    {"host": "192.168.1.13", "port": 3306, "service": "mysql",      "env": "onprem", "layer": "database"},
    {"host": "192.168.1.14", "port": 5432, "service": "postgresql",  "env": "onprem", "layer": "database"},
    {"host": "192.168.1.15", "port": 80,   "service": "wordpress",  "env": "onprem", "layer": "application"},
    {"host": "192.168.1.15", "port": 80,   "service": "php",        "env": "onprem", "layer": "application"},
    {"host": "192.168.1.16", "port": 8080, "service": "phpmyadmin", "env": "onprem", "layer": "application"},
    {"host": "192.168.1.17", "port": 23,   "service": "telnet",     "env": "onprem", "layer": "system"},

    # ── Target Flask/Werkzeug application (primary target) ─────────
    {"host": "172.25.8.172", "port": 5000, "service": "flask",      "env": "hybrid", "layer": "application"},
    {"host": "172.25.8.172", "port": 5000, "service": "werkzeug",   "env": "hybrid", "layer": "webserver"},

    # ── Hybrid / DMZ ───────────────────────────────────────────────
    {"host": "172.16.0.10", "port": 443,  "service": "nginx",       "env": "hybrid", "layer": "webserver"},
    {"host": "172.16.0.11", "port": 8443, "service": "apache",      "env": "hybrid", "layer": "webserver"},
    {"host": "172.16.0.12", "port": 22,   "service": "openssh",     "env": "hybrid", "layer": "system"},
    {"host": "172.16.0.13", "port": 5432, "service": "postgresql",  "env": "hybrid", "layer": "database"},
    {"host": "172.16.0.14", "port": 21,   "service": "proftpd",     "env": "hybrid", "layer": "system"},
    {"host": "172.16.0.15", "port": 6379, "service": "redis",       "env": "hybrid", "layer": "database"},
    {"host": "172.16.0.16", "port": 3000, "service": "nodejs",      "env": "hybrid", "layer": "frontend"},
    {"host": "172.16.0.17", "port": 8080, "service": "django",      "env": "hybrid", "layer": "application"},
    {"host": "172.16.0.18", "port": 443,  "service": "iis",         "env": "hybrid", "layer": "webserver"},
]


# ---------------------------------------------------------------------------
# Asset Scanner
# ---------------------------------------------------------------------------

class AssetScanner:
    """Continuously scans all environments, detects versions, looks up CVEs.

    Usage::

        scanner = AssetScanner()
        await scanner.start()   # blocks — runs continuous scan loops
    """

    def __init__(self) -> None:
        self.version_detector = VersionDetector()
        self.cve_lookup = CVELookup()

        self.inventory: Dict[str, Asset] = {}
        self.scan_count: int = 0
        self.total_vulnerabilities: int = 0
        self._running: bool = False

        # Dynamic scan interval — tightens under threat (default 8s)
        self.scan_interval: float = 8.0

    @property
    def asset_count(self) -> int:
        return len(self.inventory)

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for a in self.inventory.values() if a.cves)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Continuous scanning loop — never stops until stop() is called."""
        self._running = True
        ts = _ts()
        print(
            f"{ts} < asset_scanner: Starting continuous asset scan across "
            f"{len(_TARGET_ASSETS)} targets (cloud + onprem + hybrid)"
        )

        while self._running:
            await self._full_scan_cycle()
            await asyncio.sleep(self.scan_interval)

    async def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------
    # Core scan logic
    # ------------------------------------------------------------------

    async def _full_scan_cycle(self) -> None:
        """Run a complete scan cycle across all target assets."""
        self.scan_count += 1
        cycle_start = time.monotonic()
        ts = _ts()
        print(
            f"{ts} > asset_scan(cycle={self.scan_count}, "
            f"targets={len(_TARGET_ASSETS)}, interval={self.scan_interval:.1f}s)"
        )

        new_vulns_this_cycle = 0

        for target in _TARGET_ASSETS:
            if not self._running:
                break

            asset_id = f"{target['host']}:{target['port']}:{target['service']}"

            # 1. Discover / refresh asset
            asset = self.inventory.get(asset_id)
            if asset is None:
                asset = Asset(
                    asset_id=asset_id,
                    host=target["host"],
                    port=target["port"],
                    service=target["service"],
                    environment=target["env"],
                    layer=target["layer"],
                )
                self.inventory[asset_id] = asset

                await event_bus.emit("asset_discovered", {
                    "asset_id": asset_id,
                    "host": target["host"],
                    "port": target["port"],
                    "service": target["service"],
                    "environment": target["env"],
                    "layer": target["layer"],
                })

            # 2. Version detection
            version_info = self.version_detector.detect(
                target["service"], target["host"], target["port"]
            )
            if version_info:
                asset.version_info = version_info
                asset.status = "scanned"

                # 3. CVE lookup
                cves = await self.cve_lookup.lookup(
                    version_info.software, version_info.version
                )

                if cves:
                    # Only report new CVEs not already tracked for this asset
                    existing_ids = {c.cve_id for c in asset.cves}
                    new_cves = [c for c in cves if c.cve_id not in existing_ids]

                    if new_cves:
                        asset.cves.extend(new_cves)
                        asset.status = "vulnerable"
                        new_vulns_this_cycle += len(new_cves)

                        for cve in new_cves:
                            self.total_vulnerabilities += 1

                            ts = _ts()
                            print(
                                f"{ts} < asset_scanner: [{target['env'].upper()}] "
                                f"{target['service']} {version_info.version} @ "
                                f"{target['host']}:{target['port']} -> "
                                f"{cve.cve_id} (CVSS {cve.cvss_score}, {cve.severity})"
                            )

                            # Emit to event bus for response chain
                            await event_bus.emit("vulnerability_found", {
                                "asset_id": asset_id,
                                "host": target["host"],
                                "port": target["port"],
                                "service": target["service"],
                                "software": version_info.software,
                                "version": version_info.version,
                                "environment": target["env"],
                                "layer": target["layer"],
                                "cve_id": cve.cve_id,
                                "cvss_score": cve.cvss_score,
                                "severity": cve.severity,
                                "description": cve.description,
                                "fix": cve.fix,
                            })

                            # Also emit cve_detected for existing response chain
                            await event_bus.emit("cve_detected", {
                                "cve_id": cve.cve_id,
                                "service": target["service"],
                                "port": target["port"],
                                "source_ip": target["host"],
                                "severity": cve.severity,
                                "fix": cve.fix,
                            })

            asset.last_scanned = time.monotonic()
            await asyncio.sleep(0.05)  # simulate network latency

        elapsed = time.monotonic() - cycle_start
        ts = _ts()
        print(
            f"{ts} < asset_scan: cycle {self.scan_count} complete in {elapsed:.1f}s — "
            f"{self.asset_count} assets, {self.vulnerable_count} vulnerable, "
            f"{new_vulns_this_cycle} new CVEs this cycle"
        )

        await event_bus.emit("scan_complete", {
            "cycle": self.scan_count,
            "assets_scanned": self.asset_count,
            "vulnerable_assets": self.vulnerable_count,
            "new_vulnerabilities": new_vulns_this_cycle,
            "elapsed_seconds": round(elapsed, 2),
        })

    # ------------------------------------------------------------------
    # Query API (for service layer / dashboard)
    # ------------------------------------------------------------------

    def get_inventory(self) -> List[Dict[str, Any]]:
        """Return the full asset inventory as a list of dicts."""
        return [a.to_dict() for a in self.inventory.values()]

    def get_inventory_by_environment(self) -> Dict[str, List[Dict[str, Any]]]:
        """Group inventory by environment."""
        result: Dict[str, List[Dict[str, Any]]] = {
            "cloud": [], "onprem": [], "hybrid": [],
        }
        for asset in self.inventory.values():
            result.setdefault(asset.environment, []).append(asset.to_dict())
        return result

    def get_vulnerable_assets(self) -> List[Dict[str, Any]]:
        """Return only assets with known CVEs."""
        return [a.to_dict() for a in self.inventory.values() if a.cves]

    def get_stats(self) -> Dict[str, Any]:
        """Return scan statistics."""
        env_counts = {"cloud": 0, "onprem": 0, "hybrid": 0}
        layer_counts: Dict[str, int] = {}
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for asset in self.inventory.values():
            env_counts[asset.environment] = env_counts.get(asset.environment, 0) + 1
            layer_counts[asset.layer] = layer_counts.get(asset.layer, 0) + 1
            for cve in asset.cves:
                severity_counts[cve.severity] = severity_counts.get(cve.severity, 0) + 1

        return {
            "scan_count": self.scan_count,
            "total_assets": self.asset_count,
            "vulnerable_assets": self.vulnerable_count,
            "total_vulnerabilities": self.total_vulnerabilities,
            "by_environment": env_counts,
            "by_layer": layer_counts,
            "by_severity": severity_counts,
            "scan_interval": self.scan_interval,
            "cve_lookups": self.cve_lookup.lookup_count,
            "unique_cves_found": self.cve_lookup.total_cves_found,
        }
